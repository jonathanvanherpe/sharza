// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestTransferSmokeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "transfer.txt"
	wantData := []byte("hello-bytes")

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
		f3, err := readED2KFrame(conn)
		if err != nil || f3.Opcode != OP_REQUESTPARTS {
			return
		}
		rp, err := DecodeRequestParts(f3.Payload)
		if err != nil {
			return
		}
		if rp.Von[0] != 10 || rp.Bis[0] != 11 {
			return
		}
		sp := SendingPart{Hash: wantHash, Von: 10, Bis: 10 + uint32(len(wantData)), Data: wantData}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp.Marshal()}.Marshal())
	}()

	e := New()
	e.mu.Lock()
	e.clientID = 12345
	e.laddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4661}
	e.mu.Unlock()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pi, ans, sp, err := e.DialTransfer(ctx, ln.Addr().String(), wantHash, [3]uint32{10, 20, 30}, [3]uint32{11, 21, 31})
	if err != nil {
		t.Fatalf("DialTransfer: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
	if string(sp.Data) != string(wantData) {
		t.Fatalf("data = %q, want %q", sp.Data, wantData)
	}
}

func TestTransferSmokeNotFound(t *testing.T) {
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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILENOTFOUND, Payload: FileNotFound{Hash: wantHash}.Marshal()}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, _, err = e.DialTransfer(ctx, ln.Addr().String(), wantHash, [3]uint32{0, 0, 0}, [3]uint32{1, 1, 1})
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestTransferSmokeConnHelper(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "conntransfer.txt"
	wantData := []byte("conn-bytes")

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
		_, _ = readED2KFrame(conn)
		sp := SendingPart{Hash: wantHash, Von: 5, Bis: 5 + uint32(len(wantData)), Data: wantData}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp.Marshal()}.Marshal())
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
	pi, ans, sp, err := dialTransfer(ctx, conn, wantHash, [3]uint32{5, 0, 0}, [3]uint32{9, 0, 0}, e)
	if err != nil {
		t.Fatalf("dialTransfer: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
	if string(sp.Data) != string(wantData) {
		t.Fatalf("data = %q, want %q", sp.Data, wantData)
	}
}

func TestTransferSmokeRequestPartsAlias(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "alias.txt"
	wantData := []byte("alias-bytes")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = readED2KFrame(conn)
		ans := HelloAnswer{Hash: [16]byte{9, 9, 9}, ClientID: 777, Port: 4662}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: wantName}.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		sp := SendingPart{Hash: wantHash, Von: 1, Bis: 1 + uint32(len(wantData)), Data: wantData}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp.Marshal()}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, _, sp, err := e.RequestParts(ctx, ln.Addr().String(), RequestParts{Hash: wantHash, Von: [3]uint32{1, 0, 0}, Bis: [3]uint32{2, 0, 0}})
	if err != nil {
		t.Fatalf("RequestParts: %v", err)
	}
	if string(sp.Data) != string(wantData) {
		t.Fatalf("data = %q, want %q", sp.Data, wantData)
	}
}

func TestTransferTimeout(t *testing.T) {
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
	_, _, _, err = e.DialTransfer(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}
