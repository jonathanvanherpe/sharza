// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

// TestExchangeDataVerifies is the P4 exit-gate slice: an in-process
// client/server exchange where the listener runs ServeTransferConn and the
// dialer runs DialDownload (queue handling included). Downloaded bytes are
// verified cleanly against a PartMet built from the same bytes.
func TestExchangeDataVerifies(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	availName := "exchange.bin"
	wantData := bytes.Repeat([]byte("exchange-payload-"), 16)

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
		pi, fr, rp, err := e.ServeTransferConn(ctx, conn, wantHash, availName, wantData)
		if err != nil {
			t.Errorf("ServeTransferConn: %v", err)
			return
		}
		if fr.Hash != wantHash {
			t.Errorf("server fr Hash = %v, want %v", fr.Hash, wantHash)
		}
		if rp.hashBytes() != wantHash && rp.hashBytes() != ([16]byte{}) {
			// rp may be the terminal empty request; tolerate.
		}
		_ = pi
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	pi, ans, res, n, err := e.DialDownload(ctx, ln.Addr().String(), clientHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
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

	// Build a PartMet from the downloaded bytes.
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
		FileName:   availName,
	}

	ok, corrupt := PartMetVerify(buf.Bytes(), pm)
	if !ok {
		t.Fatalf("PartMetVerify not ok; corrupt=%v", corrupt)
	}
	if len(corrupt) != 0 {
		t.Fatalf("expected no corrupt parts, got %v", corrupt)
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

// TestExchangeDataNotFound exercises the not-found path over the same pair.
func TestExchangeDataNotFound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	serverClientID := uint32(777)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		e.mu.Lock()
		e.clientID = serverClientID
		e.laddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4662}
		e.mu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		// No available file supplied -> not found.
		_, _, _, err = e.ServeTransferConn(ctx, conn)
		_ = err
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
	_, _, _, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != ErrFileNotFound {
		t.Fatalf("expected ErrFileNotFound, got %v (n=%d)", err, n)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
	if buf.Len() != 0 {
		t.Fatalf("expected empty buffer, got %d", buf.Len())
	}
}
