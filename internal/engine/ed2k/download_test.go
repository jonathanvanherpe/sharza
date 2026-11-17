// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestDownloadSmokeFull(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "download.txt"
	wantData := []byte("hello-download-bytes-12345")

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
		// first request
		f3, _ := readED2KFrame(conn)
		if f3.Opcode != OP_REQUESTPARTS {
			return
		}
		sp := SendingPart{Hash: wantHash, Von: 0, Bis: uint32(len(wantData)), Data: wantData}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp.Marshal()}.Marshal())
		// second request -> empty
		_, _ = readED2KFrame(conn)
		sp2 := SendingPart{Hash: wantHash, Von: uint32(len(wantData)), Bis: uint32(len(wantData)), Data: nil}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp2.Marshal()}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	pi, ans, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("buf = %q, want %q", buf.String(), string(wantData))
	}
}

func TestDownloadSmokeEmpty(t *testing.T) {
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
		_, _ = readED2KFrame(conn)
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "empty.txt"}.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		sp := SendingPart{Hash: wantHash, Von: 0, Bis: 0, Data: nil}
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
	buf := &bytes.Buffer{}
	_, _, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
}

func TestDownloadSmokeNotFound(t *testing.T) {
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
	buf := &bytes.Buffer{}
	_, _, _, err = e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestDownloadSmokeReject(t *testing.T) {
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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_REJECT}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	_, _, _, err = e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err == nil {
		t.Fatal("expected reject error")
	}
}

func TestDownloadSmokeConnHelper(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantData := []byte("conn-download")

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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "conn.txt"}.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		sp := SendingPart{Hash: wantHash, Von: 0, Bis: uint32(len(wantData)), Data: wantData}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		sp2 := SendingPart{Hash: wantHash, Von: uint32(len(wantData)), Bis: uint32(len(wantData)), Data: nil}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp2.Marshal()}.Marshal())
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
	buf := &bytes.Buffer{}
	pi, ans, n, err := dialDownload(ctx, conn, wantHash, buf, e)
	if err != nil {
		t.Fatalf("dialDownload: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != "conn.txt" {
		t.Fatalf("answer Name = %q, want conn.txt", ans.Name)
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("buf mismatch")
	}
}

func TestDownloadTimeout(t *testing.T) {
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
	buf := &bytes.Buffer{}
	_, _, _, err = e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestDownloadPartialChunks(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantData := []byte("chunked-data-payload")

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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "chunked.txt"}.Marshal()}.Marshal())
		// send in two chunks
		half := len(wantData) / 2
		f, _ := readED2KFrame(conn)
		_ = f
		sp := SendingPart{Hash: wantHash, Von: 0, Bis: uint32(half), Data: wantData[:half]}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		sp2 := SendingPart{Hash: wantHash, Von: uint32(half), Bis: uint32(len(wantData)), Data: wantData[half:]}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp2.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		sp3 := SendingPart{Hash: wantHash, Von: uint32(len(wantData)), Bis: uint32(len(wantData)), Data: nil}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp3.Marshal()}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	_, _, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("buf mismatch")
	}
}
