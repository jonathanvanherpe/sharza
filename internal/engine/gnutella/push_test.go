// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Tests for the downloader half of Gnutella PUSH. The big one drives the
// whole flow over real TCP: a scripted 0.6 peer answers the engine's
// QUERY with a QUERYHIT whose source is firewalled, the engine writes a
// PUSH back naming its own address, the peer dials that address, and the
// file completes over the dial-back connection. Nothing here reaches the
// network beyond loopback.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		ServentID: testID(0x7E),
		FileIndex: 12345,
		IP:        [4]byte{192, 168, 1, 9},
		Port:      6346,
	}
	enc := EncodePush(p)
	if len(enc) != pushPayloadSize {
		t.Fatalf("EncodePush = %d bytes, want the fixed %d", len(enc), pushPayloadSize)
	}
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("DecodePush: %v", err)
	}
	if dec != p {
		t.Errorf("round trip = %+v, want %+v", dec, p)
	}
}

// TestPushFieldByteOrder pins the wire layout: the file index and port
// are little-endian, the IPv4 address is big-endian. A consistent
// swap of two fields survives a round trip, so only the raw bytes can
// catch it.
func TestPushFieldByteOrder(t *testing.T) {
	p := Push{
		ServentID: testID(0x11),
		FileIndex: 0x04030201,
		IP:        [4]byte{10, 0, 0, 1},
		Port:      0x1234,
	}
	enc := EncodePush(p)
	wantID := testID(0x11)
	if !bytes.Equal(enc[0:16], wantID[:]) {
		t.Errorf("servent id bytes = %x, want 16 bytes of 0x11", enc[0:16])
	}
	if got := binary.LittleEndian.Uint32(enc[16:20]); got != p.FileIndex {
		t.Errorf("file index LE = 0x%08x, want 0x%08x", got, p.FileIndex)
	}
	if !bytes.Equal(enc[20:24], []byte{10, 0, 0, 1}) {
		t.Errorf("ip bytes = %v, want [10 0 0 1] big-endian", enc[20:24])
	}
	if got := binary.LittleEndian.Uint16(enc[24:26]); got != p.Port {
		t.Errorf("port LE = 0x%04x, want 0x%04x", got, p.Port)
	}
}

func TestDecodePushMalformed(t *testing.T) {
	for n := 0; n < pushPayloadSize; n++ {
		if _, err := DecodePush(make([]byte, n)); !errors.Is(err, ErrPushBadFormat) {
			t.Errorf("DecodePush(%d bytes) error = %v, want ErrPushBadFormat", n, err)
		}
	}
	// Anything past the fixed part is a GGEP block and is ignored.
	if _, err := DecodePush(make([]byte, pushPayloadSize+3)); err != nil {
		t.Errorf("DecodePush with trailing GGEP bytes: %v", err)
	}
}

func TestQueryHitServentIDRoundTrip(t *testing.T) {
	want := testID(0xC3)
	qh := QueryHit{
		HitCount:     1,
		Port:         6346,
		IP:           [4]byte{127, 0, 0, 1},
		Hits:         []FileHit{{FileIndex: 3, FileSize: 9, FileName: "a.bin"}},
		ServentID:    want,
		HasServentID: true,
	}
	dec, err := DecodeQueryHit(EncodeQueryHit(qh))
	if err != nil {
		t.Fatalf("DecodeQueryHit: %v", err)
	}
	if !dec.HasServentID || dec.ServentID != want {
		t.Errorf("servent id = %x (present %v), want %x", dec.ServentID, dec.HasServentID, want)
	}
}

func TestQueryHitWithoutServentIDLeavesItUnset(t *testing.T) {
	qh := QueryHit{
		HitCount: 1,
		Port:     6346,
		Hits:     []FileHit{{FileIndex: 3, FileSize: 9, FileName: "a.bin"}},
	}
	dec, err := DecodeQueryHit(EncodeQueryHit(qh))
	if err != nil {
		t.Fatalf("DecodeQueryHit: %v", err)
	}
	if dec.HasServentID {
		t.Errorf("servent id present for a response that carried none")
	}
}

func TestRequestPushRejectsUnroutable(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
	})
	hit := FileHit{FileIndex: 1, FileSize: 1, FileName: "x"}
	if err := eng.RequestPush(QueryHit{}, hit); err == nil {
		t.Error("RequestPush accepted a QUERYHIT with no servent identifier")
	}
	qh := QueryHit{HasServentID: true, ServentID: testID(0x01)}
	if err := eng.RequestPush(qh, hit); !errors.Is(err, ErrNoPushRoute) {
		t.Errorf("RequestPush error = %v, want ErrNoPushRoute", err)
	}
}

// servePushedOnce is the holder's side of a pushed connection: it reads
// the GET the downloader sends over the connection it dialed, then serves
// the content. It returns the request path for assertion.
func servePushedOnce(conn net.Conn, content []byte) (string, error) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(testDeadline))
	req, err := http.ReadRequest(bufio.NewReader(conn))
	if err != nil {
		return "", err
	}
	path := req.URL.Path
	resp := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Gnutella-Content-Length: %d\r\n\r\n",
		len(content), len(content))
	if _, err := io.WriteString(conn, resp); err != nil {
		return path, err
	}
	if _, err := conn.Write(content); err != nil {
		return path, err
	}
	return path, nil
}

// searchWithFirewalledHit drives one Search against a scripted peer: it
// reads the QUERY the engine writes, answers with a QUERYHIT whose source
// is firewalled (no address, no port) and which carries serventID, and
// returns the hit the engine collected.
func searchWithFirewalledHit(t *testing.T, eng *Engine, r *bufio.Reader, conn net.Conn, serventID [idSize]byte, index, size uint32, name string) QueryHit {
	t.Helper()
	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("push")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	qh := QueryHit{
		HitCount:     1,
		Port:         0,          // firewalled: no usable source port
		IP:           [4]byte{},  // and no usable source address
		ServentID:    serventID,  // the routing key a PUSH uses
		HasServentID: true,
		Hits:         []FileHit{{FileIndex: index, FileSize: size, FileName: name}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) != 1 {
		t.Fatalf("Search returned %d hits, want 1", len(res.hits))
	}
	return res.hits[0]
}

func TestPushCompletesDownloadOverDialBack(t *testing.T) {
	const (
		index = 42
		size  = 2048
	)
	content := testContent(size)
	serventID := testID(0x9A)

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		PushClaimTimeout:  5 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	qh := searchWithFirewalledHit(t, eng, r, conn, serventID, index, size, "pushed.bin")
	if !qh.HasServentID || qh.ServentID != serventID {
		t.Fatalf("hit servent id = %x (present %v), want %x", qh.ServentID, qh.HasServentID, serventID)
	}
	hit := qh.Hits[0]

	if err := eng.RequestPush(qh, hit); err != nil {
		t.Fatalf("RequestPush: %v", err)
	}

	// The PUSH comes back over the same connection and names this engine
	// as the address to dial back to.
	ph, ppayload := readMsg(t, r)
	if ph.Type != MsgPush {
		t.Fatalf("message type = %s, want push", typeName(ph.Type))
	}
	push, err := DecodePush(ppayload)
	if err != nil {
		t.Fatalf("DecodePush: %v", err)
	}
	if push.ServentID != serventID {
		t.Errorf("push servent id = %x, want %x", push.ServentID, serventID)
	}
	if push.FileIndex != index {
		t.Errorf("push file index = %d, want %d", push.FileIndex, index)
	}
	wantPort := uint16(eng.Addr().(*net.TCPAddr).Port)
	if push.Port != wantPort {
		t.Errorf("push port = %d, want %d (our listen port)", push.Port, wantPort)
	}
	if got := net.IP(push.IP[:]).String(); got != "127.0.0.1" {
		t.Errorf("push ip = %s, want 127.0.0.1 (our local address on this link)", got)
	}

	// The holder dials back to the advertised address and serves the file
	// over the pushed connection.
	backAddr := net.JoinHostPort(net.IP(push.IP[:]).String(), strconv.Itoa(int(push.Port)))
	back, err := net.DialTimeout("tcp", backAddr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial back to %s: %v", backAddr, err)
	}
	pathCh := make(chan string, 1)
	errCh := make(chan error, 1)
	go func() {
		p, err := servePushedOnce(back, content)
		pathCh <- p
		errCh <- err
	}()

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	pconn, err := eng.AwaitPush(ctx, qh, hit)
	if err != nil {
		t.Fatalf("AwaitPush: %v", err)
	}
	dir := t.TempDir()
	res, err := eng.Downloader(qh, hit).FetchConn(ctx, pconn, dir)
	if err != nil {
		t.Fatalf("FetchConn: %v", err)
	}
	if res.Bytes != size || res.Offset != 0 || res.Resumed() {
		t.Errorf("result = %+v, want %d bytes at offset 0, not resumed", res, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)", len(onDisk), len(content))
	}
	if got := <-pathCh; got != fmt.Sprintf("/gnutella/%d", index) {
		t.Errorf("pushed request path = %q, want /gnutella/%d", got, index)
	}
	if err := <-errCh; err != nil {
		t.Errorf("pushed server: %v", err)
	}
}
