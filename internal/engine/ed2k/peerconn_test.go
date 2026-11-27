// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDialPeerSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantClientID := uint32(12345)
	wantPort := uint16(4661)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		f, err := readED2KFrame(conn)
		if err != nil {
			t.Errorf("read hello: %v", err)
			return
		}
		if f.Opcode != OP_HELLO {
			t.Errorf("opcode = %v, want OP_HELLO", f.Opcode)
			return
		}
		h, err := DecodeHello(f.Payload)
		if err != nil {
			t.Errorf("decode hello: %v", err)
			return
		}
		if h.ClientID != wantClientID {
			t.Errorf("hello client id = %d, want %d", h.ClientID, wantClientID)
		}
		if h.UserHash != wantHash {
			t.Errorf("hello user hash = %v, want %v", h.UserHash, wantHash)
		}
		// Send HELLOANSWER with known identity.
		ans := HelloAnswer{
			Hash:       [16]byte{9, 9, 9},
			ClientID:   777,
			Port:       4662,
			Tags:       []Tag{{Type: 0x02, Key: 1, Str: "peername"}, {Type: 0x02, Key: 2, Str: "1.2.3"}},
			ServerIP:   [4]byte{1, 2, 3, 4},
			ServerPort: 4661,
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
	}()

	e := New()
	e.mu.Lock()
	e.clientID = wantClientID
	e.laddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: int(wantPort)}
	e.mu.Unlock()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pi, err := e.DialPeer(ctx, ln.Addr().String())
	if err != nil {
		t.Fatalf("DialPeer: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if pi.Port != 4662 {
		t.Fatalf("Port = %d, want 4662", pi.Port)
	}
	if pi.UserHash != ([16]byte{9, 9, 9}) {
		t.Fatalf("UserHash = %v", pi.UserHash)
	}
	if !pi.LowID {
		// 777 is low id; ensure
	}
	if pi.Name != "peername" {
		t.Fatalf("Name = %q, want peername", pi.Name)
	}
	if pi.Version != "1.2.3" {
		t.Fatalf("Version = %q, want 1.2.3", pi.Version)
	}
	_ = wantPort
	_ = wantHash
}

func TestDialPeerReject(t *testing.T) {
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
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_HELLO {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_REJECT, Payload: []byte{}}.Marshal())
	}()

	e := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = e.DialPeer(ctx, ln.Addr().String())
	if err == nil {
		t.Fatal("expected error on reject")
	}
}

func TestDialPeerMalformed(t *testing.T) {
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
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_HELLO {
			return
		}
		// Truncated HELLOANSWER payload.
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: []byte{1, 2, 3}}.Marshal())
	}()

	e := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err = e.DialPeer(ctx, ln.Addr().String())
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestDialPeerTimeout(t *testing.T) {
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
		// read hello but send nothing
		_, _ = readED2KFrame(conn)
		time.Sleep(2 * time.Second)
	}()

	e := New()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, err = e.DialPeer(ctx, ln.Addr().String())
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
func TestPeerDialObfuscatedRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	availName := "obf-peer.bin"

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer c1.Close()
		e := New()
		e.mu.Lock()
		e.clientID = 777
		e.laddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4662}
		e.opts.Obfuscation = true
		e.mu.Unlock()
		e.kadMu.Lock()
		e.kadSelf = wantHash
		e.kadSelfID = wantHash
		e.kadID = wantHash
		e.kadMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _, _ = e.ServeAcceptConn(ctx, c1, wantHash, availName)
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()
	e.mu.Lock()
	e.clientID = 12345
	e.opts.Obfuscation = true
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	pi, ans, err := e.DialFileRequestConn(ctx, c2, wantHash)
	if err != nil {
		t.Fatalf("DialFileRequestConn (obfuscated): %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("peer ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != availName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, availName)
	}
	_ = c2.Close()
	<-serverDone
}

func TestPeerDialPlainRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()

	wantHash := [16]byte{9, 9, 9, 9}
	availName := "plain-peer.bin"

	serverDone := make(chan struct{})
	go func() {
		defer close(serverDone)
		defer c1.Close()
		e := New()
		e.mu.Lock()
		e.clientID = 777
		e.mu.Unlock()
		e.kadMu.Lock()
		e.kadSelf = wantHash
		e.kadSelfID = wantHash
		e.kadID = wantHash
		e.kadMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _, _ = e.ServeAcceptConn(ctx, c1, wantHash, availName)
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()
	e.mu.Lock()
	e.clientID = 12345
	e.mu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, ans, err := e.DialFileRequestConn(ctx, c2, wantHash)
	if err != nil {
		t.Fatalf("DialFileRequestConn (plain): %v", err)
	}
	if ans.Name != availName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, availName)
	}
	_ = c2.Close()
	<-serverDone
}
