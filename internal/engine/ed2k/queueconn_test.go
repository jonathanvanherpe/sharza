// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestQueueSmokeGranted(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "queue.txt"

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
		qr, err := DecodeQueueRequest(f3.Payload)
		if err != nil {
			return
		}
		if qr.Hash != wantHash {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_STARTUPLOAD, Payload: StartUpload{}.Marshal()}.Marshal())
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pi, ans, res, err := e.DialQueue(ctx, ln.Addr().String(), wantHash)
	if err != nil {
		t.Fatalf("DialQueue: %v", err)
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
}

func TestQueueSmokeQueued(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantRank := uint32(42)

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
	_, _, res, err := e.DialQueue(ctx, ln.Addr().String(), wantHash)
	if err != nil {
		t.Fatalf("DialQueue: %v", err)
	}
	if res.Granted {
		t.Fatalf("expected queued, not granted")
	}
	if res.Rank != wantRank {
		t.Fatalf("Rank = %d, want %d", res.Rank, wantRank)
	}
}

func TestQueueSmokeNotFound(t *testing.T) {
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
	_, _, _, err = e.DialQueue(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestQueueSmokeReject(t *testing.T) {
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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "q.txt"}.Marshal()}.Marshal())
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
	_, _, _, err = e.DialQueue(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected reject error")
	}
}

func TestQueueSmokeConnHelper(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantRank := uint32(7)

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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "conn.txt"}.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
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
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	pi, ans, res, err := dialQueue(ctx, conn, wantHash, e)
	if err != nil {
		t.Fatalf("dialQueue: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != "conn.txt" {
		t.Fatalf("answer Name = %q", ans.Name)
	}
	if res.Rank != wantRank {
		t.Fatalf("Rank = %d, want %d", res.Rank, wantRank)
	}
}

func TestQueueSmokeConnHelperAlias(t *testing.T) {
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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "alias.txt"}.Marshal()}.Marshal())
		_, _ = readED2KFrame(conn)
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_STARTUPLOAD, Payload: StartUpload{}.Marshal()}.Marshal())
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
	pi, _, res, err := dialQueueConn(ctx, conn, wantHash, e)
	if err != nil {
		t.Fatalf("dialQueueConn: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("ClientID = %d", pi.ClientID)
	}
	if !res.Granted {
		t.Fatalf("expected granted")
	}
}

func TestQueueTimeout(t *testing.T) {
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
	_, _, _, err = e.DialQueue(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected timeout error")
	}
}

func TestQueueRejectAfterQueue(t *testing.T) {
	// alias of reject path already covered; ensure RequestQueue alias works
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
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: "q.txt"}.Marshal()}.Marshal())
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
	_, _, _, err = e.RequestQueue(ctx, ln.Addr().String(), wantHash)
	if err == nil {
		t.Fatal("expected not-found error")
	}
}
