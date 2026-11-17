// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServerPeerConnHandshakeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantClientID := uint32(12345)
	wantPort := uint16(4661)

	serverHash := [16]byte{9, 9, 9}
	serverClientID := uint32(777)
	serverPort := uint16(4662)

	// Server side: accept, run helper, check returned peer identity.
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		e.mu.Lock()
		e.clientID = serverClientID
		e.laddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: int(serverPort)}
		e.mu.Unlock()
		e.kadMu.Lock()
		e.kadSelf = serverHash
		e.kadSelfID = serverHash
		e.kadID = serverHash
		e.kadMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pi, err := e.ServePeerConn(ctx, conn)
		if err != nil {
			t.Errorf("ServePeerConn: %v", err)
			return
		}
		if pi.ClientID != wantClientID {
			t.Errorf("returned ClientID = %d, want %d", pi.ClientID, wantClientID)
		}
		if pi.Port != wantPort {
			t.Errorf("returned Port = %d, want %d", pi.Port, wantPort)
		}
		if pi.UserHash != wantHash {
			t.Errorf("returned UserHash = %v, want %v", pi.UserHash, wantHash)
		}
		if pi.Name != "peername" {
			t.Errorf("returned Name = %q, want peername", pi.Name)
		}
		if pi.Version != "1.2.3" {
			t.Errorf("returned Version = %q, want 1.2.3", pi.Version)
		}
	}()

	// Client side: dial, send OP_HELLO, read OP_HELLOANSWER.
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hello := Hello{
		Hash:     wantHash,
		ClientID: wantClientID,
		Port:     wantPort,
		Tags:     []Tag{{Type: 0x02, Key: 1, Str: "peername"}, {Type: 0x02, Key: 2, Str: "1.2.3"}},
	}
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLO, Payload: hello.Marshal()}.Marshal())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rl := time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f, err := readED2KFrame(conn)
	if err != nil {
		t.Fatalf("read answer: %v", err)
	}
	if f.Opcode != OP_HELLOANSWER {
		t.Fatalf("opcode = %v, want OP_HELLOANSWER", f.Opcode)
	}
	ans, err := DecodeHelloAnswer(f.Payload)
	if err != nil {
		t.Fatalf("decode answer: %v", err)
	}
	if ans.ClientID != serverClientID {
		t.Fatalf("answer ClientID = %d, want %d", ans.ClientID, serverClientID)
	}
	if ans.Port != serverPort {
		t.Fatalf("answer Port = %d, want %d", ans.Port, serverPort)
	}
	if ans.UserHash != serverHash {
		t.Fatalf("answer UserHash = %v, want %v", ans.UserHash, serverHash)
	}
	_ = ctx
}

func TestServerPeerConnHandshakeReject(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Send OP_REJECT instead of OP_HELLO.
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_REJECT, Payload: []byte{}}.Marshal())
	}()

	e := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// Server side: we act as server on our conn? Actually helper expects peer hello.
	// Here simulate server helper reading a reject frame from conn.
	_, err = e.ServePeerConn(ctx, conn)
	if err == nil {
		t.Fatal("expected error on reject")
	}
}

func TestServerPeerConnHandshakeMalformed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Truncated HELLO payload.
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLO, Payload: []byte{0x10, 1, 2, 3}}.Marshal())
	}()

	e := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = e.ServePeerConn(ctx, conn)
	if err == nil {
		t.Fatal("expected decode error")
	}
}
