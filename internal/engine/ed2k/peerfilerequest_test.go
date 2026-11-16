// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestDialPeerFileSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantClientID := uint32(12345)
	wantPort := uint16(4661)
	wantName := "peerfile.txt"

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Handshake: read HELLO.
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_HELLO {
			t.Errorf("read hello: %v", err)
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
		// Send HELLOANSWER.
		ans := HelloAnswer{
			Hash:     [16]byte{9, 9, 9},
			ClientID: 777,
			Port:     4662,
			Tags:     []Tag{{Type: 0x02, Key: 1, Str: "peername"}, {Type: 0x02, Key: 2, Str: "1.2.3"}},
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())

		// Read OP_FILEREQUEST.
		f2, err := readED2KFrame(conn)
		if err != nil {
			t.Errorf("read filerequest: %v", err)
			return
		}
		if f2.Opcode != OP_FILEREQUEST {
			t.Errorf("opcode = %v, want OP_FILEREQUEST", f2.Opcode)
			return
		}
		fr, err := DecodeFileRequest(f2.Payload)
		if err != nil {
			t.Errorf("decode filerequest: %v", err)
			return
		}
		if fr.Hash != wantHash {
			t.Errorf("filerequest hash = %v, want %v", fr.Hash, wantHash)
		}
		// Send OP_FILEREQANSWER.
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: wantName}.Marshal()}.Marshal())
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
	pi, ans, err := e.DialPeerFile(ctx, ln.Addr().String(), wantHash)
	if err != nil {
		t.Fatalf("DialPeerFile: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if pi.Name != "peername" {
		t.Fatalf("Name = %q, want peername", pi.Name)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
	if ans.Hash != wantHash {
		t.Fatalf("answer Hash = %v, want %v", ans.Hash, wantHash)
	}
	_ = wantPort
}

func TestDialPeerFileNotFound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantClientID := uint32(12345)

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
		ans := HelloAnswer{Hash: [16]byte{9, 9, 9}, ClientID: 777, Port: 4662}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
		// read filerequest
		_, _ = readED2KFrame(conn)
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILENOTFOUND, Payload: FileNotFound{Hash: wantHash}.Marshal()}.Marshal())
	}()

	e := New()
	e.mu.Lock()
	e.clientID = wantClientID
	e.mu.Unlock()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = e.DialPeerFile(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestDialPeerFileMalformed(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

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
		ans := HelloAnswer{Hash: [16]byte{9, 9, 9}, ClientID: 777, Port: 4662}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		// Truncated answer payload.
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: []byte{1, 2, 3}}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, err = e.DialPeerFile(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestDialPeerFileTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = readED2KFrame(conn)
		// send helloanswer then nothing
		ans := HelloAnswer{Hash: [16]byte{9, 9, 9}, ClientID: 777, Port: 4662}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
		time.Sleep(2 * time.Second)
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, err = e.DialPeerFile(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestRequestFileConnSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "connfile.txt"

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
		ans := HelloAnswer{Hash: [16]byte{9, 9, 9}, ClientID: 777, Port: 4662}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
		f2, _ := readED2KFrame(conn)
		if f2.Opcode != OP_FILEREQUEST {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: wantName}.Marshal()}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pi, ans, err := requestFile(ctx, conn, wantHash, e)
	if err != nil {
		t.Fatalf("requestFile: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
}