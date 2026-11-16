// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestFileRequestSmokeSuccess(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "smoke.txt"

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
	pi, ans, err := e.DialFileRequest(ctx, ln.Addr().String(), wantHash)
	if err != nil {
		t.Fatalf("DialFileRequest: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
}

func TestFileRequestSmokeNotFound(t *testing.T) {
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
	_, _, err = e.DialFileRequest(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestFileRequestSmokeConnHelper(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "connsmoke.txt"

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
	pi, ans, err := dialFileRequest(ctx, conn, wantHash, e)
	if err != nil {
		t.Fatalf("dialFileRequest: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
}
