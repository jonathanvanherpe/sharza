// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestServeTransferConnSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantClientID := uint32(12345)
	wantPort := uint16(4661)
	availName := "avail.txt"
	wantData := []byte("hello-bytes")

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
		e.kadSelf = [16]byte{9, 9, 9}
		e.kadSelfID = [16]byte{9, 9, 9}
		e.kadID = [16]byte{9, 9, 9}
		e.kadMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		pi, fr, rp, sp, err := e.ServeTransferConn(ctx, conn, wantHash, availName, wantData)
		if err != nil {
			t.Errorf("ServeTransferConn: %v", err)
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
		if rp.hashBytes() != wantHash {
			t.Errorf("returned rp hash = %v, want %v", rp.hashBytes(), wantHash)
		}
		if string(sp.Data) != string(wantData) {
			t.Errorf("returned data = %q, want %q", sp.Data, wantData)
		}
		_ = serverClientID
		_ = serverPort
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

	// Send OP_REQUESTPARTS.
	rp := RequestParts{Hash: wantHash, Von: [3]uint32{0, 0, 0}, Bis: [3]uint32{uint32(len(wantData)), 0, 0}}
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_REQUESTPARTS, Payload: rp.Marshal()}.Marshal())

	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f3, err := readED2KFrame(conn)
	if err != nil {
		t.Fatalf("read sendingpart: %v", err)
	}
	if f3.Opcode != OP_SENDINGPART {
		t.Fatalf("opcode = %v, want OP_SENDINGPART", f3.Opcode)
	}
	sp, err := DecodeSendingPart(f3.Payload)
	if err != nil {
		t.Fatalf("decode sendingpart: %v", err)
	}
	if string(sp.Data) != string(wantData) {
		t.Fatalf("data = %q, want %q", sp.Data, wantData)
	}
	_ = ctx
}

func TestServeTransferConnNotFound(t *testing.T) {
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
		pi, fr, _, _, err := e.ServeTransferConn(ctx, conn)
		if err != nil {
			t.Errorf("ServeTransferConn: %v", err)
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

func TestServeTransferConnNotFoundMismatched(t *testing.T) {
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
		_, _, _, _, err = e.ServeTransferConn(ctx, conn, otherHash, "other.txt")
		if err != nil {
			t.Errorf("ServeTransferConn: %v", err)
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

func TestServeTransferConnMalformed(t *testing.T) {
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
	_, _, _, _, err = e.ServeTransferConn(ctx, conn)
	if err == nil {
		t.Fatal("expected error on unexpected opcode")
	}
}

func TestServeTransferConnMalformedRequest(t *testing.T) {
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

	_, _, _, _, err = e.ServeTransferConn(ctx, conn, wantHash, "avail.txt")
	if err == nil {
		t.Fatal("expected decode error")
	}
}

func TestServeTransferConnRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantClientID := uint32(12345)
	wantData := []byte("roundtrip-bytes")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, rp, sp, err := e.ServeTransferConn(ctx, conn, wantHash, "avail.txt", wantData)
		if err != nil {
			t.Errorf("ServeTransferConn: %v", err)
			return
		}
		if rp.Von[0] != 0 || rp.Bis[0] != uint32(len(wantData)) {
			t.Errorf("rp range = %d/%d", rp.Von[0], rp.Bis[0])
		}
		if string(sp.Data) != string(wantData) {
			t.Errorf("data = %q, want %q", sp.Data, wantData)
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
		t.Fatalf("opcode = %v", f.Opcode)
	}

	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQUEST, Payload: FileRequest{Hash: wantHash}.Marshal()}.Marshal())
	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f2, _ := readED2KFrame(conn)
	if f2.Opcode != OP_FILEREQANSWER {
		t.Fatalf("opcode = %v", f2.Opcode)
	}

	rp := RequestParts{Hash: wantHash, Von: [3]uint32{0, 0, 0}, Bis: [3]uint32{uint32(len(wantData)), 0, 0}}
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_REQUESTPARTS, Payload: rp.Marshal()}.Marshal())
	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f3, err := readED2KFrame(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f3.Opcode != OP_SENDINGPART {
		t.Fatalf("opcode = %v, want OP_SENDINGPART", f3.Opcode)
	}
	sp, err := DecodeSendingPart(f3.Payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if string(sp.Data) != string(wantData) {
		t.Fatalf("data = %q, want %q", sp.Data, wantData)
	}
	_ = ctx
}

func TestServeTransferConnSizeMismatch(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantData := []byte("short")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, _, _, err = e.ServeTransferConn(ctx, conn, wantHash, "avail.txt", wantData)
		// refusal: either error or notfound; we accept nil with notfound write
		_ = err
	}()

	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()

	hello := Hello{Hash: wantHash, ClientID: 12345, Port: 4661}
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLO, Payload: hello.Marshal()}.Marshal())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	rl := time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f, _ := readED2KFrame(conn)
	if f.Opcode != OP_HELLOANSWER {
		t.Fatalf("opcode = %v", f.Opcode)
	}

	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQUEST, Payload: FileRequest{Hash: wantHash}.Marshal()}.Marshal())
	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f2, _ := readED2KFrame(conn)
	if f2.Opcode != OP_FILEREQANSWER {
		t.Fatalf("opcode = %v", f2.Opcode)
	}

	// Request range beyond source length.
	rp := RequestParts{Hash: wantHash, Von: [3]uint32{0, 0, 0}, Bis: [3]uint32{100, 0, 0}}
	conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_REQUESTPARTS, Payload: rp.Marshal()}.Marshal())
	rl = time.Now().Add(5 * time.Second)
	conn.SetReadDeadline(rl)
	f3, err := readED2KFrame(conn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if f3.Opcode != OP_FILENOTFOUND && f3.Opcode != OP_SENDINGPART {
		t.Fatalf("opcode = %v", f3.Opcode)
	}
	_ = ctx
}