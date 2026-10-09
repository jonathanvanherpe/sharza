// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Compression tests. The scripted peers reproduce what the live 2026
// gtk-gnutella 1.3.1 ultrapeers do on a leaf link: accept only after
// Accept-Encoding: deflate, then send their messages on a
// zlib-compressed stream.

import (
	"bufio"
	"bytes"
	"compress/flate"
	"compress/zlib"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

func TestWantsInflate(t *testing.T) {
	cases := []struct {
		name string
		hs   Handshake
		want bool
	}{
		{"absent", Handshake{Code: 200}, false},
		{"deflate", Handshake{Code: 200, Fields: []Field{{"Content-Encoding", "deflate"}}}, true},
		{"uppercase", Handshake{Code: 200, Fields: []Field{{"Content-Encoding", "DEFLATE"}}}, true},
		{"token list", Handshake{Code: 200, Fields: []Field{{"Content-Encoding", "gzip, deflate"}}}, true},
		{"gzip only", Handshake{Code: 200, Fields: []Field{{"Content-Encoding", "gzip"}}}, false},
		{"empty value", Handshake{Code: 200, Fields: []Field{{"Content-Encoding", ""}}}, false},
	}
	for _, c := range cases {
		if got := wantsInflate(c.hs); got != c.want {
			t.Errorf("%s: wantsInflate = %v, want %v", c.name, got, c.want)
		}
	}
}

func TestIsZlibHeader(t *testing.T) {
	cases := []struct {
		name string
		b    [2]byte
		want bool
	}{
		{"gtk-gnutella", [2]byte{0x68, 0x81}, true},
		{"zlib default", [2]byte{0x78, 0x9c}, true},
		{"bad checksum", [2]byte{0x78, 0x9d}, false}, // CMF/FLG not a multiple of 31
		{"gzip magic", [2]byte{0x1f, 0x8b}, false},   // method nibble is not 8
		{"raw stored block", [2]byte{0x00, 0x00}, false},
	}
	for _, c := range cases {
		if got := isZlibHeader(c.b); got != c.want {
			t.Errorf("%s (%x): isZlibHeader = %v, want %v", c.name, c.b, got, c.want)
		}
	}
}

// zlibCompress returns b as a complete zlib-wrapped stream, which is
// what a peer that negotiated deflate builds per message (or, for one
// stream per connection, as the prefix of it).
func zlibCompress(t *testing.T, b []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := zlib.NewWriter(&buf)
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestInflateReaderDecodesZlibStream(t *testing.T) {
	want := []byte("message bytes, plain once decoded: " + strings.Repeat("x", 4096))
	got, err := io.ReadAll(newInflateReader(bytes.NewReader(zlibCompress(t, want))))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decoded %q, want %q", got, want)
	}
}

func TestInflateReaderDecodesRawDeflate(t *testing.T) {
	want := []byte("bare RFC 1951 stream, no zlib wrapper")
	var buf bytes.Buffer
	fw, err := flate.NewWriter(&buf, flate.DefaultCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fw.Write(want); err != nil {
		t.Fatal(err)
	}
	if err := fw.Close(); err != nil {
		t.Fatal(err)
	}
	var head [2]byte
	copy(head[:], buf.Bytes())
	if isZlibHeader(head) {
		t.Fatalf("test stream starts %x, which sniffs as zlib; the payload needs to change", head)
	}

	got, err := io.ReadAll(newInflateReader(bytes.NewReader(buf.Bytes())))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("decoded %q, want %q", got, want)
	}
}

// TestInflateReaderDecodesConcatenatedStreams covers a peer that frames
// every message as its own zlib stream: after one stream ends the next
// header must be sniffed, not mistaken for the end of the connection.
func TestInflateReaderDecodesConcatenatedStreams(t *testing.T) {
	joined := append(zlibCompress(t, []byte("first")), zlibCompress(t, []byte("second"))...)
	got, err := io.ReadAll(newInflateReader(bytes.NewReader(joined)))
	if err != nil {
		t.Fatalf("ReadAll: %v", err)
	}
	if string(got) != "firstsecond" {
		t.Errorf("decoded %q, want %q", got, "firstsecond")
	}
}

func TestInflateReaderRejectsUndecodableStream(t *testing.T) {
	// BTYPE 11 is reserved: flate must reject this rather than return
	// bytes, so a garbage stream fails visibly instead of corrupting
	// the message loop's framing.
	_, err := io.ReadAll(newInflateReader(bytes.NewReader([]byte{0xff, 0xff, 0xff, 0xff})))
	if err == nil {
		t.Fatal("decoding a non-deflate stream returned no error")
	}
}

// TestOutboundDialInflatedStream is the live 2026 link end to end: the
// server only completes the handshake after the client's
// Accept-Encoding: deflate, declares a compressed stream in its 200,
// and then sends its PING compressed. The engine can only answer the
// PING by decoding the stream.
func TestOutboundDialInflatedStream(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	_, _ = startEngine(t, Options{
		Listen:            "127.0.0.1:0",
		Peers:             []string{ln.Addr().String()},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	var sconn net.Conn
	select {
	case sconn = <-accepted:
	case <-time.After(testDeadline):
		t.Fatal("engine never dialed the configured peer")
	}
	defer sconn.Close()
	if err := sconn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(sconn)

	hs, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("read connect request: %v", err)
	}
	if !hs.Request {
		t.Fatalf("first line is a response (%s), want a CONNECT request", hs.Status())
	}
	if ae, ok := hs.Get("Accept-Encoding"); !ok || !strings.Contains(strings.ToLower(ae), "deflate") {
		t.Fatalf("Accept-Encoding = %q (present=%v), want a deflate offer", ae, ok)
	}

	if _, err := sconn.Write(OKReply(
		Field{"Content-Encoding", "deflate"},
		Field{"User-Agent", "scripted-server/0.1"},
	)); err != nil {
		t.Fatal(err)
	}
	confirm, err := ReadHandshake(r) // the confirmation itself is plain
	if err != nil {
		t.Fatalf("read client confirmation: %v", err)
	}
	if !confirm.IsOK() {
		t.Fatalf("client confirmation = %s, want 200 OK", confirm.Status())
	}

	ping := Header{ID: testID(0x77), Type: MsgPing, TTL: 4}
	frame := ping.Marshal()
	if _, err := sconn.Write(zlibCompress(t, frame[:])); err != nil {
		t.Fatal(err)
	}
	hdr, payload := readMsg(t, r) // our TX is never compressed
	if hdr.Type != MsgPong || hdr.ID != ping.ID || hdr.TTL != 3 {
		t.Fatalf("replied %s id %x ttl %d, want pong id 0x77... ttl 3",
			typeName(hdr.Type), hdr.ID, hdr.TTL)
	}
	if len(payload) != pongPayloadSize {
		t.Errorf("pong payload = %d bytes, want %d", len(payload), pongPayloadSize)
	}
}

// TestInboundCompressedClient covers the server side: a client that
// declares Content-Encoding: deflate -- in its CONNECT, its
// confirmation, or both, all of which gtk-gnutella honours -- sends
// its messages compressed, and the engine must decode them to answer.
func TestInboundCompressedClient(t *testing.T) {
	for _, decl := range []string{"connect", "confirm", "both"} {
		t.Run(decl, func(t *testing.T) {
			eng, _ := startEngine(t, Options{
				KeepAliveInterval: time.Hour,
				IdleTimeout:       5 * time.Second,
			})
			conn, err := net.DialTimeout("tcp", eng.Addr().String(), 5*time.Second)
			if err != nil {
				t.Fatalf("dial engine: %v", err)
			}
			t.Cleanup(func() { _ = conn.Close() })
			if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
				t.Fatal(err)
			}

			req := "GNUTELLA CONNECT/0.6\r\nUser-Agent: scripted-test/0.1\r\n"
			if decl == "connect" || decl == "both" {
				req += "Content-Encoding: deflate\r\n"
			}
			req += "\r\n"
			if _, err := conn.Write([]byte(req)); err != nil {
				t.Fatal(err)
			}
			r := bufio.NewReader(conn)
			hs, err := ReadHandshake(r)
			if err != nil {
				t.Fatalf("read server reply: %v", err)
			}
			if !hs.IsOK() {
				t.Fatalf("server replied %s, want 200 OK", hs.Status())
			}

			confirm := "GNUTELLA/0.6 200 OK\r\n"
			if decl == "confirm" || decl == "both" {
				confirm += "Content-Encoding: deflate\r\n"
			}
			confirm += "\r\n"
			if _, err := conn.Write([]byte(confirm)); err != nil {
				t.Fatal(err)
			}

			ping := Header{ID: testID(0x5A), Type: MsgPing, TTL: 5}
			frame := ping.Marshal()
			if _, err := conn.Write(zlibCompress(t, frame[:])); err != nil {
				t.Fatal(err)
			}
			hdr, payload := readMsg(t, r) // server TX stays plain
			if hdr.Type != MsgPong || hdr.ID != ping.ID || hdr.TTL != 4 {
				t.Fatalf("reply = %s id %x ttl %d, want pong id 0x5A... ttl 4",
					typeName(hdr.Type), hdr.ID, hdr.TTL)
			}
			if len(payload) != pongPayloadSize {
				t.Errorf("pong payload = %d bytes, want %d", len(payload), pongPayloadSize)
			}
		})
	}
}
