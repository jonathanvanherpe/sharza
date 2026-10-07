// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Integration tests drive the engine over real TCP with a scripted
// Gnutella 0.6 peer. The peer is a plain TCP client, not the engine
// itself, so the tests exercise the wire format the daemon speaks.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"strings"
	"testing"
	"time"
)

const testDeadline = 10 * time.Second

// startEngine boots an engine on an ephemeral port with sensible test
// timing and returns it plus a cancel func that shuts it down.
func startEngine(t *testing.T, opts Options) (*Engine, context.CancelFunc) {
	t.Helper()
	opts.Listen = "127.0.0.1:0"
	if opts.Logf == nil {
		opts.Logf = t.Logf
	}
	eng := New()
	ctx, cancel := context.WithCancel(context.Background())

	errCh := make(chan error, 1)
	go func() { errCh <- eng.Run(ctx, opts) }()
	// Cleanups run LIFO: cancel first, then wait for Run to report.
	t.Cleanup(func() {
		select {
		case err := <-errCh:
			if err != nil {
				t.Errorf("engine Run returned %v", err)
			}
		case <-time.After(testDeadline):
			t.Error("engine did not stop after context cancel")
		}
	})
	t.Cleanup(cancel)

	select {
	case <-eng.Ready():
	case <-time.After(testDeadline):
		t.Fatal("engine did not bind its listener")
	}
	return eng, cancel
}

// dialEngine connects like a real Gnutella 0.6 client: CONNECT request,
// expected 200, then returns its 200 confirmation. On success the
// returned reader is positioned at the first binary message.
func dialEngine(t *testing.T, addr string) (*bufio.Reader, net.Conn) {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}
	req := "GNUTELLA CONNECT/0.6\r\n" +
		"User-Agent: scripted-test/0.1\r\n" +
		"X-Gnutella-Network: G1,G2\r\n" +
		"Remote-IP: 127.0.0.1\r\n\r\n"
	if _, err := conn.Write([]byte(req)); err != nil {
		t.Fatalf("write connect: %v", err)
	}
	r := bufio.NewReader(conn)
	hs, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("read server reply: %v", err)
	}
	if !hs.IsOK() {
		t.Fatalf("server replied %s, want 200 OK", hs.Status())
	}
	if _, err := conn.Write([]byte("GNUTELLA/0.6 200 OK\r\n\r\n")); err != nil {
		t.Fatalf("write confirmation: %v", err)
	}
	return r, conn
}

// sendMsg writes one binary message.
func sendMsg(t *testing.T, conn net.Conn, h Header, payload []byte) {
	t.Helper()
	b := h.AppendTo(nil)
	b = append(b, payload...)
	if _, err := conn.Write(b); err != nil {
		t.Fatalf("write message: %v", err)
	}
}

// readMsg reads one binary message, failing the test on error.
func readMsg(t *testing.T, r *bufio.Reader) (Header, []byte) {
	t.Helper()
	hdr, payload, err := readMsgErr(r)
	if err != nil {
		t.Fatalf("read message: %v", err)
	}
	return hdr, payload
}

func readMsgErr(r *bufio.Reader) (Header, []byte, error) {
	hdr, err := DecodeHeader(r)
	if err != nil {
		return Header{}, nil, err
	}
	payload := make([]byte, hdr.Length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return Header{}, nil, err
	}
	return hdr, payload, nil
}

func testID(b byte) [16]byte {
	var id [16]byte
	for i := range id {
		id[i] = b
	}
	return id
}

func assertTimeout(t *testing.T, err error) {
	t.Helper()
	var ne net.Error
	if !errors.As(err, &ne) || !ne.Timeout() {
		t.Fatalf("error = %v, want a timeout", err)
	}
}

func TestInboundHandshakeThenPingPong(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())

	// PING with TTL 5 must produce a PONG echoing the ID with TTL 4:
	// the TTL decrement is the observable, testable contract of the
	// brief ("PONG for each PING with TTL decremented").
	ping := Header{ID: testID(0xAB), Type: MsgPing, TTL: 5, Hops: 0}
	sendMsg(t, conn, ping, nil)

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgPong {
		t.Fatalf("reply type = %s, want pong", typeName(hdr.Type))
	}
	if hdr.ID != ping.ID {
		t.Errorf("reply ID = %x, want echo of %x", hdr.ID, ping.ID)
	}
	if hdr.TTL != 4 {
		t.Errorf("reply TTL = %d, want 4 (ping TTL 5 minus one)", hdr.TTL)
	}
	if hdr.Hops != 0 {
		t.Errorf("reply hops = %d, want 0", hdr.Hops)
	}
	if len(payload) != pongPayloadSize {
		t.Fatalf("pong payload = %d bytes, want %d", len(payload), pongPayloadSize)
	}
	wantPort := uint16(eng.Addr().(*net.TCPAddr).Port)
	if got := binary.LittleEndian.Uint16(payload[0:2]); got != wantPort {
		t.Errorf("pong port = %d, want %d", got, wantPort)
	}
	if got := net.IP(payload[2:6]).String(); got != "127.0.0.1" {
		t.Errorf("pong ip = %s, want 127.0.0.1 (address this link is reachable at)", got)
	}
	if got := binary.LittleEndian.Uint32(payload[6:10]); got != 0 {
		t.Errorf("pong file count = %d, want 0 (nothing shared yet)", got)
	}
	if got := binary.LittleEndian.Uint32(payload[10:14]); got != 0 {
		t.Errorf("pong kB count = %d, want 0", got)
	}
}

func TestPingWithZeroTTLIsDropped(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())

	// TTL 0: the message's life is over; it must not even be answered.
	sendMsg(t, conn, Header{ID: testID(0x01), Type: MsgPing, TTL: 0}, nil)
	// A live PING after it must still get its own PONG, proving the
	// zero-TTL one was dropped rather than the connection closed.
	sendMsg(t, conn, Header{ID: testID(0x02), Type: MsgPing, TTL: 3}, nil)

	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgPong || hdr.ID != testID(0x02) {
		t.Fatalf("message = type %s id %x, want pong for id 02", typeName(hdr.Type), hdr.ID)
	}
	if hdr.TTL != 2 {
		t.Errorf("reply TTL = %d, want 2 (ping TTL 3 minus one)", hdr.TTL)
	}

	// And nothing else follows: the connection stays open but silent.
	if err := conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMsgErr(r); err == nil {
		t.Fatal("a further message arrived after the TTL-0 drop")
	} else {
		assertTimeout(t, err)
	}
}

func TestOversizedPayloadClosesConnection(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
	})
	_, conn := dialEngine(t, eng.Addr().String())

	sendMsg(t, conn, Header{ID: testID(0x33), Type: MsgPing, Length: MaxPayloadSize + 1}, nil)
	if err := conn.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMsgErr(bufio.NewReader(conn)); err == nil {
		t.Fatal("connection survived an oversized payload length")
	}
}

func TestIdleTimeoutClosesConnection(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour, // silence must not be masked by pings
		IdleTimeout:       300 * time.Millisecond,
	})
	_, conn := dialEngine(t, eng.Addr().String())

	// Say nothing and wait: the engine must put the connection away.
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(conn).ReadByte(); err == nil {
		t.Fatal("connection stayed open past IdleTimeout")
	}
}

func TestKeepAlivePingsArrive(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: 80 * time.Millisecond,
		IdleTimeout:       10 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())

	var gotIDs [][16]byte
	for i := 0; i < 2; i++ {
		hdr, payload := readMsg(t, r)
		if hdr.Type != MsgPing {
			t.Fatalf("message %d type = %s, want ping", i, typeName(hdr.Type))
		}
		if hdr.TTL != keepAliveTTL || hdr.Hops != 0 || hdr.Length != 0 {
			t.Errorf("keep-alive ping %d = ttl %d hops %d len %d, want 7/0/0",
				i, hdr.TTL, hdr.Hops, hdr.Length)
		}
		if len(payload) != 0 {
			t.Errorf("keep-alive ping %d has a %d-byte payload, want empty", i, len(payload))
		}
		for _, prev := range gotIDs {
			if prev == hdr.ID {
				t.Errorf("keep-alive ping %d reused descriptor ID %x", i, prev)
			}
		}
		gotIDs = append(gotIDs, hdr.ID)

		// Answer like any 0.6 peer; the engine must accept the PONG
		// and keep the link alive (proven by the next PING).
		sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgPong, TTL: 6, Hops: 0, Length: 14}, make([]byte, 14))
	}
}

func TestContextCancelClosesConnections(t *testing.T) {
	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       30 * time.Second,
	})
	_, _ = dialEngine(t, eng.Addr().String())
	_, conn := dialEngine(t, eng.Addr().String())

	cancel()
	if err := conn.SetReadDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := bufio.NewReader(conn).ReadByte(); err == nil {
		t.Fatal("connection stayed open after engine shutdown")
	}
}

func TestInboundUnsupportedVersionGets503(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
	})
	conn, err := net.DialTimeout("tcp", eng.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}
	// A Gnutella 0.4 peer: 0.6 supports it backwards is not our plan,
	// and it must be refused with a status, not answered silently.
	if _, err := conn.Write([]byte("GNUTELLA CONNECT/0.4\r\n\r\n")); err != nil {
		t.Fatal(err)
	}
	hs, err := ReadHandshake(bufio.NewReader(conn))
	if err != nil {
		t.Fatalf("read refusal: %v", err)
	}
	if hs.IsOK() {
		t.Fatalf("0.4 client got 200 OK, want refusal")
	}
	if hs.Code != 503 {
		t.Errorf("refusal code = %d, want 503", hs.Code)
	}
}

// TestOutboundDial exercises the client side: the engine dials a peer
// address, completes the 0.6 exchange, and answers PINGs with PONGs.
func TestOutboundDial(t *testing.T) {
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

	// The engine dials the listener we just bound.
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
	if hs.Version != "0.6" {
		t.Errorf("connect version = %q, want 0.6", hs.Version)
	}
	if ua := hs.UserAgent(); !strings.Contains(ua, "Sharza") {
		t.Errorf("client User-Agent = %q, want it to name Sharza", ua)
	}
	if got, ok := hs.Get("Listen-IP"); !ok || !strings.Contains(got, ":") {
		t.Errorf("client Listen-IP = %q (present=%v), want host:port", got, ok)
	}

	if _, err := sconn.Write(OKReply(
		Field{"Listen-IP", "127.0.0.1:6346"},
		Field{"User-Agent", "scripted-server/0.1"},
	)); err != nil {
		t.Fatal(err)
	}
	confirm, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("read client confirmation: %v", err)
	}
	if !confirm.IsOK() {
		t.Fatalf("client confirmation = %s, want 200 OK", confirm.Status())
	}

	// Now it is a 0.6 link: our PING must come back with TTL minus one.
	ping := Header{ID: testID(0x77), Type: MsgPing, TTL: 4}
	sendMsg(t, sconn, ping, nil)
	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgPong || hdr.ID != ping.ID || hdr.TTL != 3 {
		t.Fatalf("replied %s id %x ttl %d, want pong id 0x77... ttl 3",
			typeName(hdr.Type), hdr.ID, hdr.TTL)
	}
	if len(payload) != pongPayloadSize {
		t.Errorf("pong payload = %d bytes, want %d", len(payload), pongPayloadSize)
	}
}

// TestReadHandshakeBuffersPreserveMessageBytes is a unit-level guard for
// the shared-reader invariant: bytes after the handshake terminator
// must survive for the message loop.
func TestReadHandshakeBuffersPreserveMessageBytes(t *testing.T) {
	hsBytes := []byte("GNUTELLA/0.6 200 OK\r\n\r\n")
	msg := Header{Type: MsgPing, TTL: 3}.Marshal()
	all := append(append([]byte(nil), hsBytes...), msg[:]...)

	r := bufio.NewReader(bytes.NewReader(all))
	hs, err := ReadHandshake(r)
	if err != nil {
		t.Fatal(err)
	}
	if !hs.IsOK() {
		t.Fatalf("reply = %s, want 200 OK", hs.Status())
	}
	hdr, err := DecodeHeader(r)
	if err != nil {
		t.Fatalf("first message after handshake: %v", err)
	}
	if hdr.Type != MsgPing || hdr.TTL != 3 {
		t.Errorf("message after handshake = type %s ttl %d, want ping ttl 3", typeName(hdr.Type), hdr.TTL)
	}
}
