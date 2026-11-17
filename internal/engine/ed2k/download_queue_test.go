// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestDownloadQueueGranted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "download-queue.txt"
	wantData := []byte("queued-granted-bytes-xyz")

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
		if err != nil || f3.Opcode != OP_QUEUEREQUEST {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_STARTUPLOAD, Payload: StartUpload{}.Marshal()}.Marshal())
		f4, _ := readED2KFrame(conn)
		if f4.Opcode != OP_REQUESTPARTS {
			return
		}
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
	buf := &bytes.Buffer{}
	pi, ans, res, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != wantName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, wantName)
	}
	if !res.Granted {
		t.Fatalf("expected granted")
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("buf = %q, want %q", buf.String(), string(wantData))
	}
}

func TestDownloadQueueQueued(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantRank := uint32(99)

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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "q.txt"}.Marshal()}.Marshal())
		f3, _ := readED2KFrame(conn)
		if f3.Opcode != OP_QUEUEREQUEST {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_QUEUERANK, Payload: QueueRank{Rank: wantRank}.Marshal()}.Marshal())
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
	pi, ans, res, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	_ = ans
	if res.Granted {
		t.Fatalf("expected queued, not granted")
	}
	if res.Rank != wantRank {
		t.Fatalf("Rank = %d, want %d", res.Rank, wantRank)
	}
	if n != 0 {
		t.Fatalf("n = %d, want 0", n)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected no bytes transferred")
	}
}

func TestDownloadQueueConnHelper(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantData := []byte("conn-queue-download")

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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "connq.txt"}.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_STARTUPLOAD, Payload: StartUpload{}.Marshal()}.Marshal())
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
	pi, ans, res, n, err := dialDownload(ctx, conn, wantHash, buf, e)
	if err != nil {
		t.Fatalf("dialDownload: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d", pi.ClientID)
	}
	if ans.Name != "connq.txt" {
		t.Fatalf("answer Name = %q", ans.Name)
	}
	if !res.Granted {
		t.Fatalf("expected granted")
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("buf mismatch")
	}
}