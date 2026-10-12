// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

// testServentID returns a deterministic 16-byte servent identifier.
func testServentID(seed byte) [idSize]byte {
	var sid [idSize]byte
	for i := range sid {
		sid[i] = seed + byte(i)
	}
	return sid
}

func TestEncodePushWireLayout(t *testing.T) {
	// Field table (0.6 draft 2.2.8): 0-15 servent identifier,
	// 16-19 file index (LE), 20-23 IPv4 (big-endian), 24-25 port (LE).
	sid := testServentID(0x10)
	p := Push{
		ServentID: sid,
		FileIndex: 0x04030201,
		IP:        [4]byte{1, 2, 3, 4},
		Port:      6346, // 0x18CA
	}
	enc := EncodePush(p)
	if len(enc) != pushPayloadSize {
		t.Fatalf("length: got %d want %d", len(enc), pushPayloadSize)
	}
	if enc[0] != sid[0] || enc[15] != sid[15] {
		t.Errorf("servent id not at 0-15: %x", enc[:16])
	}
	// file index, LE
	if enc[16] != 0x01 || enc[17] != 0x02 || enc[18] != 0x03 || enc[19] != 0x04 {
		t.Errorf("file index not LE at 16-19: %x", enc[16:20])
	}
	// ip, big-endian
	if enc[20] != 1 || enc[21] != 2 || enc[22] != 3 || enc[23] != 4 {
		t.Errorf("ip not BE at 20-23: %x", enc[20:24])
	}
	// port, LE
	if enc[24] != 0xCA || enc[25] != 0x18 {
		t.Errorf("port not LE at 24-25: %x", enc[24:26])
	}
}

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		ServentID: testServentID(0x77),
		FileIndex: 424242,
		IP:        [4]byte{127, 0, 0, 1},
		Port:      4665,
	}
	dec, err := DecodePush(EncodePush(p))
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec != p {
		t.Errorf("round trip mismatch:\n got %+v\nwant %+v", dec, p)
	}
}

func TestDecodePushMalformed(t *testing.T) {
	// Below the fixed 26 bytes the payload is malformed.
	short := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 0, 0, 0, 0, 1, 2, 3, 4, 5}
	if _, err := DecodePush(short); err == nil {
		t.Fatalf("expected error for %d-byte payload", len(short))
	}
}

func TestDecodePushIgnoresGGEPTrailer(t *testing.T) {
	// A 0.6 servent may append an optional GGEP extension block after
	// the fixed 26 bytes; the codec must ignore it.
	p := Push{
		ServentID: testServentID(0x01),
		FileIndex: 1,
		IP:        [4]byte{10, 0, 0, 1},
		Port:      7000,
	}
	withGGEP := append(EncodePush(p), 0x80, 0x00) // GGEP "machine readable" flag block
	dec, err := DecodePush(withGGEP)
	if err != nil {
		t.Fatalf("decode failed with trailer: %v", err)
	}
	if dec != p {
		t.Errorf("decode with trailer mismatch:\n got %+v\nwant %+v", dec, p)
	}
}
// waitForPushRoute blocks until the engine has recorded a route for the
// servent identifier, i.e. until it has processed the QUERYHIT that
// carries it. Engine.Push refuses a servent with no route, so a test
// must not call it before the route exists.
func waitForPushRoute(t *testing.T, eng *Engine, sid [idSize]byte) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for {
		if _, ok := eng.pushRoutes.lookup(sid); ok {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("engine never recorded a push route for servent %x", sid)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// firewalledHit builds a 0.6-form QUERYHIT whose source cannot be dialed
// (unspecified address, zero port) and whose trailing servent id is sid.
func firewalledHit(sid [idSize]byte, hit FileHit) QueryHit {
	return QueryHit{
		HitCount:  1,
		Port:      0,
		IP:        [4]byte{},
		Speed:     1234,
		Hits:      []FileHit{hit},
		ServentID: sid,
	}
}

// scriptPush runs the firewalled servent's half of one push transfer:
// it reads the engine's PUSH from r, validates it, dials back the
// advertised address, greets with the GIV line, and hands the
// requester's GET to serve. The returned channel receives the decoded
// PUSH before the dial-back, so the caller can inspect what the engine
// advertised. Assertions use t.Errorf, never Fatalf: this runs on its
// own goroutine.
func scriptPush(t *testing.T, r *bufio.Reader, sid [idSize]byte, queryID [idSize]byte, index uint32, name string, serve func(back net.Conn, req *http.Request) error) <-chan Push {
	t.Helper()
	seen := make(chan Push, 1)
	go func() {
		hdr, payload, err := readMsgErr(r)
		if err != nil {
			t.Errorf("script: read push: %v", err)
			return
		}
		if hdr.Type != MsgPush {
			t.Errorf("script: engine sent %s, want push", typeName(hdr.Type))
			return
		}
		if hdr.TTL != keepAliveTTL || hdr.Hops != 0 {
			t.Errorf("script: push ttl/hops = %d/%d, want %d/0", hdr.TTL, hdr.Hops, keepAliveTTL)
		}
		if hdr.ID == queryID {
			t.Errorf("script: push reused the QUERYHIT descriptor id %x", queryID)
		}
		if len(payload) != pushPayloadSize {
			t.Errorf("script: push payload = %d bytes, want %d", len(payload), pushPayloadSize)
		}
		p, err := DecodePush(payload)
		if err != nil {
			t.Errorf("script: decode push: %v", err)
			return
		}
		if p.ServentID != sid {
			t.Errorf("script: push servent id = %x, want %x", p.ServentID, sid)
		}
		if p.FileIndex != index {
			t.Errorf("script: push file index = %d, want %d", p.FileIndex, index)
		}
		seen <- p

		back, err := net.DialTimeout("tcp",
			net.JoinHostPort(net.IP(p.IP[:]).String(), strconv.Itoa(int(p.Port))), 5*time.Second)
		if err != nil {
			t.Errorf("script: dial back %s:%d: %v", net.IP(p.IP[:]), p.Port, err)
			return
		}
		defer back.Close()
		if _, err := fmt.Fprintf(back, "GIV %x:%x/%s\r\n", index, sid, name); err != nil {
			t.Errorf("script: write GIV: %v", err)
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(back))
		if err != nil {
			t.Errorf("script: read GET: %v", err)
			return
		}
		if err := serve(back, req); err != nil {
			t.Errorf("script: serve: %v", err)
		}
	}()
	return seen
}

func TestPushDownloadsFromFirewalledServent(t *testing.T) {
	const (
		index = 4
		size  = 913
	)
	content := testContent(size)
	sid := testServentID(0x60)
	queryID := testID(0xE1)

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())

	hit := FileHit{FileIndex: index, FileSize: size, FileName: "pushed-song.mp3"}
	qh := firewalledHit(sid, hit)
	hitPayload := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: queryID, Type: MsgQueryHit, TTL: 5, Hops: 0, Length: uint32(len(hitPayload))}, hitPayload)

	// The engine must learn the route from the QUERYHIT before a PUSH
	// can be sent back over the same connection.
	waitForPushRoute(t, eng, sid)

	seen := scriptPush(t, r, sid, queryID, index, hit.FileName, func(back net.Conn, req *http.Request) error {
		if req.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			return fmt.Errorf("GET path = %q, want /gnutella/%d", req.URL.Path, index)
		}
		if got := req.Header.Get("X-Gnutella-Content-Length"); got != strconv.Itoa(size) {
			return fmt.Errorf("X-Gnutella-Content-Length = %q, want %d", got, size)
		}
		if got := req.Header.Get("Range"); got != "" {
			return fmt.Errorf("fresh push transfer sent Range %q", got)
		}
		if _, err := fmt.Fprintf(back, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nConnection: close\r\n\r\n", size); err != nil {
			return err
		}
		_, err := back.Write(content)
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	dir := t.TempDir()
	res, err := eng.Push(ctx, qh, hit, dir)
	if err != nil {
		t.Fatalf("Push: %v", err)
	}
	if res.Bytes != size || res.Offset != 0 {
		t.Errorf("result = %+v, want %d bytes at offset 0", res, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("pushed file (%d bytes) does not match served content (%d bytes)", len(onDisk), len(content))
	}

	select {
	case p := <-seen:
		if got := net.IP(p.IP[:]).String(); got != "127.0.0.1" {
			t.Errorf("push advertised ip = %s, want the link's own 127.0.0.1", got)
		}
		if p.Port != eng.pushPort() {
			t.Errorf("push advertised port = %d, want the engine's push port %d", p.Port, eng.pushPort())
		}
		if p.Port == 0 {
			t.Error("push advertised port 0: nothing could dial back")
		}
	case <-time.After(testDeadline):
		t.Fatal("scripted servent never saw the push")
	}
}

func TestPushRefusesSizeMismatchOverPushedConn(t *testing.T) {
	const (
		index = 5
		size  = 640
	)
	content := testContent(size)
	sid := testServentID(0x61)
	queryID := testID(0xE2)

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())

	hit := FileHit{FileIndex: index, FileSize: size, FileName: "short.bin"}
	qh := firewalledHit(sid, hit)
	hitPayload := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: queryID, Type: MsgQueryHit, TTL: 5, Hops: 0, Length: uint32(len(hitPayload))}, hitPayload)
	waitForPushRoute(t, eng, sid)

	scriptPush(t, r, sid, queryID, index, hit.FileName, func(back net.Conn, req *http.Request) error {
		// Close-delimited body one byte short of the declared size: no
		// Content-Length, so only the body count exposes the lie.
		if _, err := fmt.Fprint(back, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n"); err != nil {
			return err
		}
		_, err := back.Write(content[:size-1])
		return err
	})

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	_, err := eng.Push(ctx, qh, hit, t.TempDir())
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("Push error = %v, want ErrSizeMismatch over the pushed conn", err)
	}
}

// TestPushRefusals covers the three ways Push must refuse before any
// PUSH goes out: a dialable hit, a hit with no servent identifier, and a
// servent the engine has no route to.
func TestPushRefusals(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	hit := FileHit{FileIndex: 1, FileSize: 4, FileName: "x.bin"}

	dialable := QueryHit{Port: 6346, IP: [4]byte{192, 168, 0, 1}, ServentID: testServentID(0x10), Hits: []FileHit{hit}}
	if _, err := eng.Push(context.Background(), dialable, hit, t.TempDir()); err == nil {
		t.Error("Push accepted a hit whose source is dialable")
	}

	noServentID := firewalledHit([idSize]byte{}, hit)
	if _, err := eng.Push(context.Background(), noServentID, hit, t.TempDir()); err == nil {
		t.Error("Push accepted a firewalled hit with no servent identifier")
	}

	unrouted := firewalledHit(testServentID(0x99), hit)
	if _, err := eng.Push(context.Background(), unrouted, hit, t.TempDir()); err == nil {
		t.Error("Push accepted a servent the engine has no route to")
	}
}