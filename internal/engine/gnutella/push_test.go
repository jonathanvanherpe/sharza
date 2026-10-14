// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Push tests, downloader half. The codec tests pin the wire layout
// (little-endian index and port, network-order address, trailing 16-byte
// identifier) so an endianness slip cannot hide behind a round trip that
// decodes whatever it encoded. The integration test drives the whole
// path over real TCP: a scripted holder advertises itself firewalled,
// receives the PUSH, dials back with a GIV, and answers the GET the
// downloader sends over that connection.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEncodePushLayout(t *testing.T) {
	p := Push{
		ServentID: testID(0xAB),
		FileIndex: 0x01020304,
		IP:        [4]byte{1, 2, 3, 4},
		Port:      6346, // 0x18CA
	}
	enc := EncodePush(p)
	if len(enc) != pushPayloadSize {
		t.Fatalf("encoded length = %d, want %d", len(enc), pushPayloadSize)
	}
	var want []byte
	for i := 0; i < idSize; i++ {
		want = append(want, 0xAB)
	}
	want = append(want, 0x04, 0x03, 0x02, 0x01) // file index, little-endian
	want = append(want, 0x01, 0x02, 0x03, 0x04) // address, network order
	want = append(want, 0xCA, 0x18)             // port, little-endian
	if !bytes.Equal(enc, want) {
		t.Errorf("encoded PUSH = % x\nwant            % x", enc, want)
	}

	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec != p {
		t.Errorf("round trip = %+v, want %+v", dec, p)
	}
}

func TestDecodePushShort(t *testing.T) {
	if _, err := DecodePush(make([]byte, pushPayloadSize-1)); !errors.Is(err, ErrPushBadFormat) {
		t.Errorf("error = %v, want ErrPushBadFormat", err)
	}
}

// TestDecodePushIgnoresTrailer pins the GGEP tolerance: Shareaza reads
// only the first 26 bytes and then tries a GGEP block, so an extra tail
// must not change the fields.
func TestDecodePushIgnoresTrailer(t *testing.T) {
	base := EncodePush(Push{ServentID: testID(0x11), FileIndex: 3, IP: [4]byte{9, 8, 7, 6}, Port: 1})
	withTrailer := append(append([]byte{}, base...), []byte{0xC3, 0x47, 0x47, 0x45, 0x50}...)
	a, err := DecodePush(base)
	if err != nil {
		t.Fatal(err)
	}
	b, err := DecodePush(withTrailer)
	if err != nil {
		t.Fatal(err)
	}
	if a != b {
		t.Errorf("trailer changed the fields: %+v vs %+v", b, a)
	}
}

func TestParseGIV(t *testing.T) {
	lower := strings.Repeat("ab", idSize) // 32 hex digits = 16 bytes of 0xAB
	upper := strings.ToUpper(lower)

	cases := []struct {
		name  string
		line  string
		index uint32
		id    [idSize]byte
		fname string
		ok    bool
	}{
		{"plain", "GIV 5:" + lower + "/song.mp3", 5, testID(0xAB), "song.mp3", true},
		{"url encoded", "GIV 124:d51dff817f895598ff0065537c09d503/my%20song.mp3", 124,
			givID(t, "d51dff817f895598ff0065537c09d503"), "my song.mp3", true},
		{"empty name", "GIV 0:" + lower + "/", 0, testID(0xAB), "", true},
		{"uppercase hex", "GIV 7:" + upper + "/x", 7, testID(0xAB), "x", true},
		{"no prefix", "PUSH 5:" + lower + "/x", 0, [idSize]byte{}, "", false},
		{"no slash", "GIV 5:" + lower, 0, [idSize]byte{}, "", false},
		{"no colon", "GIV 5/" + lower, 0, [idSize]byte{}, "", false},
		{"empty index", "GIV :" + lower + "/x", 0, [idSize]byte{}, "", false},
		{"short id", "GIV 5:" + lower[:30] + "/x", 0, [idSize]byte{}, "", false},
		{"non-hex id", "GIV 5:" + strings.Repeat("zz", idSize) + "/x", 0, [idSize]byte{}, "", false},
		{"bad index", "GIV 5x:" + lower + "/x", 0, [idSize]byte{}, "", false},
	}
	for _, tc := range cases {
		g, err := ParseGIV(tc.line)
		if !tc.ok {
			if err == nil {
				t.Errorf("%s: ParseGIV(%q) succeeded, want error", tc.name, tc.line)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: ParseGIV(%q): %v", tc.name, tc.line, err)
			continue
		}
		if g.FileIndex != tc.index || g.ServentID != tc.id || g.Name != tc.fname {
			t.Errorf("%s: got index=%d id=%x name=%q, want index=%d id=%x name=%q",
				tc.name, g.FileIndex, g.ServentID, g.Name, tc.index, tc.id, tc.fname)
		}
	}
}

func givID(t *testing.T, hexID string) [idSize]byte {
	t.Helper()
	raw, err := hex.DecodeString(hexID)
	if err != nil {
		t.Fatalf("bad fixture id %q: %v", hexID, err)
	}
	var id [idSize]byte
	copy(id[:], raw)
	return id
}

func TestFormatGIVRoundTrip(t *testing.T) {
	in := GIV{FileIndex: 124, ServentID: givID(t, "d51dff817f895598ff0065537c09d503"), Name: "my song.mp3"}
	out, err := ParseGIV(FormatGIV(in))
	if err != nil {
		t.Fatalf("parse of formatted GIV: %v", err)
	}
	if out != in {
		t.Errorf("round trip = %+v, want %+v", out, in)
	}
}

// acceptHolderHandshake performs the server half of the 0.6 handshake on
// a connection the engine dialed, and returns the reader positioned at
// the first binary message.
func acceptHolderHandshake(c net.Conn) (*bufio.Reader, error) {
	if err := c.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		return nil, err
	}
	r := bufio.NewReader(c)
	hs, err := ReadHandshake(r)
	if err != nil {
		return nil, fmt.Errorf("read connect: %w", err)
	}
	if !hs.Request {
		return nil, fmt.Errorf("first line is %q, want a CONNECT request", hs.Status())
	}
	if _, err := c.Write(OKReply(
		Field{"Listen-IP", "127.0.0.1:1"},
		Field{"User-Agent", "scripted-holder/0.1"},
	)); err != nil {
		return nil, err
	}
	confirm, err := ReadHandshake(r)
	if err != nil {
		return nil, fmt.Errorf("read confirmation: %w", err)
	}
	if !confirm.IsOK() {
		return nil, fmt.Errorf("client confirmation is %q, want 200 OK", confirm.Status())
	}
	return r, nil
}

// TestDownloadFirewalledSourceViaPush is the end-to-end downloader-half
// test: the QUERYHIT names no reachable address, the engine PUSHes the
// scripted holder, the holder dials back with a GIV, and the file arrives
// over the GET sent on that dial-back. The holder's observations are
// asserted too, because the bytes the downloader puts on the wire are as
// much the contract as the file it gets back.
func TestDownloadFirewalledSourceViaPush(t *testing.T) {
	const (
		index = 42
		size  = 900
	)
	content := testContent(size)
	holderID := testID(0x7B)
	hitName := "push song.mp3" // a space, to prove the GET path is URL-encoded

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	eng, _ := startEngine(t, Options{
		Peers:             []string{ln.Addr().String()},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		PushTimeout:       5 * time.Second,
	})
	waitForPeers(t, eng, 1)

	handshakeDone := make(chan struct{})
	type observed struct {
		pushID, wantID [idSize]byte
		pushIndex      uint32
		pushIP         string
		pushPort       int
		gotPath        string
		gotGXCL        string
		err            error
	}
	resCh := make(chan observed, 1)
	go func() {
		var o observed
		o.wantID = holderID
		defer func() { resCh <- o }()

		sconn, err := ln.Accept()
		if err != nil {
			o.err = fmt.Errorf("accept peer: %w", err)
			return
		}
		defer sconn.Close()
		r, err := acceptHolderHandshake(sconn)
		if err != nil {
			o.err = err
			return
		}
		close(handshakeDone)

		hdr, payload, err := readMsgErr(r)
		if err != nil {
			o.err = fmt.Errorf("read push: %w", err)
			return
		}
		if hdr.Type != MsgPush {
			o.err = fmt.Errorf("message type = %s, want push", typeName(hdr.Type))
			return
		}
		push, err := DecodePush(payload)
		if err != nil {
			o.err = err
			return
		}
		o.pushID = push.ServentID
		o.pushIndex = push.FileIndex
		o.pushIP = net.IP(push.IP[:]).String()
		o.pushPort = int(push.Port)

		back, err := net.DialTimeout("tcp", net.JoinHostPort(o.pushIP, strconv.Itoa(o.pushPort)), testDeadline)
		if err != nil {
			o.err = fmt.Errorf("dial back: %w", err)
			return
		}
		defer back.Close()
		if err := back.SetDeadline(time.Now().Add(testDeadline)); err != nil {
			o.err = err
			return
		}
		if _, err := fmt.Fprintf(back, "GIV %d:%s/%s\n\n",
			push.FileIndex, hex.EncodeToString(holderID[:]), url.PathEscape(hitName)); err != nil {
			o.err = fmt.Errorf("write giv: %w", err)
			return
		}
		req, err := http.ReadRequest(bufio.NewReader(back))
		if err != nil {
			o.err = fmt.Errorf("read get: %w", err)
			return
		}
		o.gotPath = req.URL.RequestURI()
		o.gotGXCL = req.Header.Get("X-Gnutella-Content-Length")
		if _, err := fmt.Fprintf(back,
			"HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Gnutella-Content-Length: %d\r\n\r\n",
			size, size); err != nil {
			o.err = fmt.Errorf("write response: %w", err)
			return
		}
		if _, err := back.Write(content); err != nil {
			o.err = fmt.Errorf("write body: %w", err)
			return
		}
	}()

	select {
	case <-handshakeDone:
	case <-time.After(testDeadline):
		t.Fatal("holder never completed the handshake with the engine")
	}

	qh := QueryHit{
		HitCount:  1,
		Port:      0, // no advertised port: firewalled
		IP:        [4]byte{0, 0, 0, 0},
		ServentID: holderID,
		Hits:      []FileHit{{FileIndex: index, FileSize: size, FileName: hitName}},
	}
	dir := t.TempDir()
	res, err := eng.Downloader(qh, qh.Hits[0]).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	o := <-resCh
	if o.err != nil {
		t.Fatalf("holder: %v", o.err)
	}
	if o.pushID != holderID {
		t.Errorf("PUSH named servent %x, want the QUERYHIT's %x", o.pushID, holderID)
	}
	if o.pushIndex != index {
		t.Errorf("PUSH file index = %d, want %d", o.pushIndex, index)
	}
	if o.pushIP != "127.0.0.1" {
		t.Errorf("PUSH dial-back address = %s, want the engine's 127.0.0.1", o.pushIP)
	}
	if want := eng.Addr().(*net.TCPAddr).Port; o.pushPort != want {
		t.Errorf("PUSH dial-back port = %d, want the engine's listen port %d", o.pushPort, want)
	}
	if want := fmt.Sprintf("/get/%d/%s", index, url.PathEscape(hitName)); o.gotPath != want {
		t.Errorf("GET path = %q, want %q", o.gotPath, want)
	}
	if o.gotGXCL != strconv.Itoa(size) {
		t.Errorf("GET X-Gnutella-Content-Length = %q, want %d", o.gotGXCL, size)
	}
	if res.Bytes != size || res.Offset != 0 {
		t.Errorf("result = %+v, want %d bytes at offset 0", res, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)", len(onDisk), len(content))
	}
}

// TestDownloadPushTimeout pins the no-dial-back path: the holder takes the
// PUSH and never answers it, so Fetch must give up with ErrPushTimeout
// rather than hang.
func TestDownloadPushTimeout(t *testing.T) {
	holderID := testID(0x5E)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	eng, _ := startEngine(t, Options{
		Peers:             []string{ln.Addr().String()},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		PushTimeout:       250 * time.Millisecond,
	})
	waitForPeers(t, eng, 1)

	handshakeDone := make(chan struct{})
	go func() {
		sconn, err := ln.Accept()
		if err != nil {
			return
		}
		defer sconn.Close()
		r, err := acceptHolderHandshake(sconn)
		if err != nil {
			return
		}
		close(handshakeDone)
		// Take the PUSH and deliberately never dial back.
		_, _, _ = readMsgErr(r)
	}()

	select {
	case <-handshakeDone:
	case <-time.After(testDeadline):
		t.Fatal("holder never completed the handshake with the engine")
	}

	qh := QueryHit{
		HitCount:  1,
		Port:      0,
		IP:        [4]byte{0, 0, 0, 0},
		ServentID: holderID,
		Hits:      []FileHit{{FileIndex: 1, FileSize: 10, FileName: "x"}},
	}
	_, err = eng.Downloader(qh, qh.Hits[0]).Fetch(context.Background(), t.TempDir())
	if !errors.Is(err, ErrPushTimeout) {
		t.Fatalf("Fetch error = %v, want ErrPushTimeout", err)
	}
}

// TestPushDialbackUnknownServentRefused pins the accept path's rejection
// of a dial-back nobody asked for: the GIV names an identifier no PUSH is
// waiting on, so the engine answers 503 and closes, exactly as Shareaza
// does.
func TestPushDialbackUnknownServentRefused(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	conn, err := net.DialTimeout("tcp", eng.Addr().String(), testDeadline)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}
	stranger := testID(0x44)
	if _, err := fmt.Fprintf(conn, "GIV 1:%s/x\n\n", hex.EncodeToString(stranger[:])); err != nil {
		t.Fatal(err)
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if !strings.Contains(line, "503 Unknown push") {
		t.Errorf("refusal line = %q, want a 503 Unknown push", line)
	}
}
