// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// TestDownloadPartMetVerifies is the P4 exit-gate slice: a file fetched over
// the C2C path (queue handling included) is verified cleanly against a
// PartMet record built from the same bytes. A scripted TCP peer stands in
// for amuled, which is unavailable in this environment.
func TestDownloadPartMetVerifies(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	wantName := "verified.bin"
	wantData := bytes.Repeat([]byte("partmet-verification-payload-"), 8)

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
		// Queue round-trip (OP_QUEUEREQUEST -> OP_STARTUPLOAD).
		f3, err := readED2KFrame(conn)
		if err != nil || f3.Opcode != OP_QUEUEREQUEST {
			return
		}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_STARTUPLOAD, Payload: StartUpload{}.Marshal()}.Marshal())
		// First request: whole file in one part.
		f4, _ := readED2KFrame(conn)
		if f4.Opcode != OP_REQUESTPARTS {
			return
		}
		sp := SendingPart{Hash: wantHash, Von: 0, Bis: uint32(len(wantData)), Data: wantData}
		conn.Write(Frame{Protocol: ProtocolEDonkey, Opcode: OP_SENDINGPART, Payload: sp.Marshal()}.Marshal())
		// Second request: empty terminator.
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
		t.Fatalf("expected granted queue result")
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("downloaded bytes mismatch")
	}

	// Build a PartMet from the same data.
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
		parts[i] = md4Sum(buf.Bytes()[start:end])
	}
	fileHash := md4Sum(buf.Bytes())
	pm := PartMet{
		FileSize:   fileSize,
		FileHash:   fileHash,
		PartSize:   partSize,
		PartHashes: parts,
		FileName:   wantName,
	}

	// PartMetVerify: Verified (no corrupt parts).
	ok, corrupt := PartMetVerify(buf.Bytes(), pm)
	if !ok {
		t.Fatalf("PartMetVerify not ok; corrupt=%v", corrupt)
	}
	if len(corrupt) != 0 {
		t.Fatalf("expected no corrupt parts, got %v", corrupt)
	}

	// PartVerify: Verified (no corrupt parts) plus correct byte count.
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
	if r.VerifiedPartCount != nParts {
		t.Fatalf("verified part count = %d, want %d", r.VerifiedPartCount, nParts)
	}

}
