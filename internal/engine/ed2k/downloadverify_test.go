// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// TestDownloadVerifiedExchange is the integration slice: an in-process
// client/server exchange where the listener runs ServeTransferConn and the
// dialer runs DialDownloadVerified (queue handling included). The transferred
// bytes are verified cleanly against a PartMet built from the same bytes.
func TestDownloadVerifiedExchange(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	availName := "verified-exchange.bin"
	wantData := bytes.Repeat([]byte("verify-exchange-payload-"), 16)

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
		e.kadSelf = wantHash
		e.kadSelfID = wantHash
		e.kadID = wantHash
		e.kadMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _, err = e.ServeTransferConn(ctx, conn, wantHash, availName, wantData)
		if err != nil {
			t.Errorf("ServeTransferConn: %v", err)
		}
	}()

	clientHash := wantHash
	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.mu.Lock()
	e.clientID = 12345
	e.mu.Unlock()
	e.kadMu.Unlock()

	// Build a PartMet from the bytes that will be served.
	partSize := uint64(64)
	fileSize := uint64(len(wantData))
	nParts := int((fileSize + partSize - 1) / partSize)
	parts := make([][16]byte, nParts)
	for i := 0; i < nParts; i++ {
		start := uint64(i) * partSize
		end := start + partSize
		if end > fileSize {
			end = fileSize
		}
		parts[i] = md4Sum(wantData[start:end])
	}
	fileHash := md4Sum(wantData)
	pm := PartMet{
		FileSize:   fileSize,
		FileHash:   fileHash,
		PartSize:   partSize,
		PartHashes: parts,
		FileName:   availName,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	pi, ans, res, n, corrupt, err := e.DialDownloadVerified(ctx, ln.Addr().String(), clientHash, pm, buf)
	if err != nil {
		t.Fatalf("DialDownloadVerified: %v", err)
	}
	if pi.ClientID != serverClientID {
		t.Fatalf("peer ClientID = %d, want %d", pi.ClientID, serverClientID)
	}
	if ans.Name != availName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, availName)
	}
	if !res.Granted {
		t.Fatalf("expected granted queue result, got %+v", res)
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("downloaded bytes mismatch")
	}

	// PartMetVerify returns ok with no corrupt parts.
	ok, corrupt2 := PartMetVerify(buf.Bytes(), pm)
	if !ok {
		t.Fatalf("PartMetVerify not ok; corrupt=%v", corrupt2)
	}
	if len(corrupt2) != 0 {
		t.Fatalf("expected no corrupt parts, got %v", corrupt2)
	}
	if len(corrupt) != 0 {
		t.Fatalf("DialDownloadVerified corrupt = %v, want none", corrupt)
	}

	r, verr := PartVerify(pm, buf.Bytes())
	if verr != nil {
		t.Fatalf("PartVerify error: %v", verr)
	}
	if !r.Verified {
		t.Fatalf("PartVerify not verified: %+v", r)
	}
	if len(r.CorruptParts) != 0 {
		t.Fatalf("expected no corrupt parts, got %v", r.CorruptParts)
	}
	if r.DataSize != len(wantData) {
		t.Fatalf("byte count = %d, want %d", r.DataSize, len(wantData))
	}
}

// TestDownloadVerifiedDownloaderOption exercises the Downloader verified option.
func TestDownloadVerifiedDownloaderOption(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	availName := "dv.bin"
	wantData := []byte("downloader-verified-payload")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		f, _ := readED2KFrame(conn)
		if f.Opcode != OP_HELLO {
			return
		}
		ans := HelloAnswer{Hash: [16]byte{9, 9, 9}, ClientID: 777, Port: 4662}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_HELLOANSWER, Payload: ans.Marshal()}.Marshal())
		f2, _ := readED2KFrame(conn)
		if f2.Opcode != OP_FILEREQUEST {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_FILEREQANSWER, Payload: FileReqAnswer{Hash: wantHash, Name: availName}.Marshal()}.Marshal())
		qf, _ := readED2KFrame(conn)
		if qf.Opcode != OP_QUEUEREQUEST {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_STARTUPLOAD, Payload: StartUpload{}.Marshal()}.Marshal())
		rf, _ := readED2KFrame(conn)
		_ = rf
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

	partSize := uint64(64)
	fileSize := uint64(len(wantData))
	nParts := int((fileSize + partSize - 1) / partSize)
	parts := make([][16]byte, nParts)
	for i := 0; i < nParts; i++ {
		start := uint64(i) * partSize
		end := start + partSize
		if end > fileSize {
			end = fileSize
		}
		parts[i] = md4Sum(wantData[start:end])
	}
	pm := PartMet{
		FileSize:   fileSize,
		FileHash:   md4Sum(wantData),
		PartSize:   partSize,
		PartHashes: parts,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	d := e.DownloaderVerified(ln.Addr().String(), wantHash, pm)
	_, _, _, n, corrupt, err := d.DownloadVerified(ctx, buf)
	if err != nil {
		t.Fatalf("DownloadVerified: %v", err)
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if len(corrupt) != 0 {
		t.Fatalf("corrupt = %v", corrupt)
	}
}
