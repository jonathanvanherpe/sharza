// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServerFileRequestConnSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantClientID := uint32(12345)
	wantPort := uint16(4661)
	availName := "avail.txt"

	serverHash := [16]byte{9, 9, 9}
	serverClientID := uint32(777)
	serverPort := uint16(4662)

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
		pi, fr, err := e.ServeFileRequestConn(ctx, conn, wantHash, availName)
		if err != nil {
			t.Errorf("ServeFileRequestConn: %v", err)
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
		if fr.Hash != wantHash {
			t.Errorf("returned request Hash = %v, want %v", fr.Hash, wantHash)
		}
	}()

	// Client side.
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

	// Send OP_FILEREQUEST.
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQUEST, Payload: FileRequest{Hash: wantHash}.Marshal()}.Marshal())

	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f2, err := readED2KFrame(conn)
	if err != nil {
		t.Fatalf("read filereqanswer: %v", err)
	}
	if f2.Opcode != OP_FILEREQANSWER {
		t.Fatalf("opcode = %v, want OP_FILEREQANSWER", f2.Opcode)
	}
	ra, err := DecodeFileReqAnswer(f2.Payload)
	if err != nil {
		t.Fatalf("decode answer: %v", err)
	}
	if ra.Hash != wantHash {
		t.Fatalf("answer Hash = %v, want %v", ra.Hash, wantHash)
	}
	if ra.Name != availName {
		t.Fatalf("answer Name = %q, want %q", ra.Name, availName)
	}
	_ = ctx
}

func TestServerFileRequestConnNotFound(t *testing.T) {
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
		e := New()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// No available file supplied -> not found.
		pi, fr, err := e.ServeFileRequestConn(ctx, conn)
		if err != nil {
			// helper still returns fr; but write notfound succeeded, no err
			t.Errorf("ServeFileRequestConn: %v", err)
			return
		}
		if fr.Hash != wantHash {
			t.Errorf("returned request Hash = %v, want %v", fr.Hash, wantHash)
		}
		_ = pi
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hello := Hello{Hash: wantHash, ClientID: wantClientID, Port: 4661}
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

	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQUEST, Payload: FileRequest{Hash: wantHash}.Marshal()}.Marshal())

	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f2, err := readED2KFrame(conn)
	if err != nil {
		t.Fatalf("read notfound: %v", err)
	}
	if f2.Opcode != OP_FILENOTFOUND {
		t.Fatalf("opcode = %v, want OP_FILENOTFOUND", f2.Opcode)
	}
	nf, err := DecodeFileNotFound(f2.Payload)
	if err != nil {
		t.Fatalf("decode notfound: %v", err)
	}
	if nf.Hash != wantHash {
		t.Fatalf("notfound Hash = %v, want %v", nf.Hash, wantHash)
	}
	_ = ctx
}

func TestServerFileRequestConnNotFoundMismatched(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	otherHash := [16]byte{9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9}
	wantClientID := uint32(12345)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, err = e.ServeFileRequestConn(ctx, conn, otherHash, "other.txt")
		if err != nil {
			t.Errorf("ServeFileRequestConn: %v", err)
		}
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hello := Hello{Hash: wantHash, ClientID: wantClientID, Port: 4661}
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLO, Payload: hello.Marshal()}.Marshal())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rl := time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f, _ := readED2KFrame(conn)
	if f.Opcode != OP_HELLOANSWER {
		t.Fatalf("opcode = %v, want OP_HELLOANSWER", f.Opcode)
	}

	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQUEST, Payload: FileRequest{Hash: wantHash}.Marshal()}.Marshal())

	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f2, err := readED2KFrame(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f2.Opcode != OP_FILENOTFOUND {
		t.Fatalf("opcode = %v, want OP_FILENOTFOUND", f2.Opcode)
	}
	_ = ctx
}

func TestServerFileRequestConnMalformed(t *testing.T) {
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
		// Send an unexpected opcode instead of OP_HELLO.
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: 0x99, Payload: []byte{}}.Marshal())
	}()

	e := New()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, _, err = e.ServeFileRequestConn(ctx, conn)
	if err == nil {
		t.Fatal("expected error on unexpected opcode")
	}
}

func TestServerFileRequestConnMalformedRequest(t *testing.T) {
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
		// Read HELLO.
		f, err := readED2KFrame(conn)
		if err != nil || f.Opcode != OP_HELLO {
			return
		}
		ans := HelloAnswer{Hash: [16]byte{9, 9, 9}, ClientID: 777, Port: 4662}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
		// Read (truncated) filerequest; helper should error.
		_, _ = readED2KFrame(conn)
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.mu.Lock()
	e.clientID = wantClientID
	e.mu.Unlock()
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hello := Hello{Hash: wantHash, ClientID: wantClientID, Port: 4661}
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLO, Payload: hello.Marshal()}.Marshal())

	// Read helloanswer.
	rl := time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f, err := readED2KFrame(conn)
	if err != nil || f.Opcode != OP_HELLOANSWER {
		t.Fatalf("read helloanswer: %v", err)
	}

	// Send truncated OP_FILEREQUEST.
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQUEST, Payload: []byte{1, 2, 3}}.Marshal())

	_, _, err = e.ServeFileRequestConn(ctx, conn, wantHash, "avail.txt")
	if err == nil {
		t.Fatal("expected decode error")
	}
}
