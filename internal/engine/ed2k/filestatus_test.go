// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"errors"
	"testing"
)

func TestFileStatusRequestRoundTrip(t *testing.T) {
	h := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	r := FileStatusRequest{Hash: h}
	b := r.Marshal()
	if len(b) != 16 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeFileStatusRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Hash != h || g.FileHash != h || g.MD4 != h {
		t.Fatalf("hash mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip mismatch")
	}
	// aliases
	r2 := FileStatusRequest{FileHash: h}
	if !bytes.Equal(r2.Marshal(), b) {
		t.Fatal("FileHash alias")
	}
	r3 := FileStatusRequest{MD4: h}
	if !bytes.Equal(r3.Marshal(), b) {
		t.Fatal("MD4 alias")
	}
}

func TestFileStatusRequestTrailingAndTruncated(t *testing.T) {
	if _, err := DecodeFileStatusRequest([]byte{1, 2}); err == nil {
		t.Fatal("expected truncated")
	}
	if _, err := DecodeFileStatusRequest(make([]byte, 17)); err == nil {
		t.Fatal("expected trailing")
	}
}

func TestFileStatusEmptyBitmap(t *testing.T) {
	h := [16]byte{9}
	fs := FileStatus{Hash: h, Count: 0}
	b := fs.Marshal()
	if len(b) != 18 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeFileStatus(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Count != 0 || g.NumParts != 0 || g.BlockCount != 0 || g.NumBlocks != 0 {
		t.Fatalf("count=%d", g.Count)
	}
	if len(g.Status) != 0 || len(g.Bitmap) != 0 || len(g.Bits) != 0 || len(g.Available) != 0 {
		t.Fatalf("bitmap not empty")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip")
	}
}

func TestFileStatusNonEmptyBitmap(t *testing.T) {
	h := [16]byte{7}
	status := []byte{0x0F, 0x80}
	fs := FileStatus{Hash: h, Count: 9, Status: status}
	b := fs.Marshal()
	if len(b) != 16+2+2 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeFileStatus(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Count != 9 {
		t.Fatalf("count=%d", g.Count)
	}
	if !bytes.Equal(g.Status, status) {
		t.Fatalf("status=%v", g.Status)
	}
	if !bytes.Equal(g.Bitmap, status) || !bytes.Equal(g.Bits, status) || !bytes.Equal(g.Available, status) {
		t.Fatal("alias mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip")
	}
}

func TestFileStatusBitOrder(t *testing.T) {
	// Shareaza: part i corresponds to bit (1 << (i % 8)) of byte i/8.
	status := []byte{0x00}
	status[0] = 1<<0 | 1<<3 | 1<<7
	fs := FileStatus{Count: 8, Status: status}
	if !fs.Bit(0) || fs.Bit(1) || fs.Bit(2) || !fs.Bit(3) {
		t.Fatal("low bits")
	}
	if !fs.Bit(7) {
		t.Fatal("bit7")
	}
	// multi-byte
	status2 := []byte{0xFF, 0x01}
	fs2 := FileStatus{Count: 9, Status: status2}
	if !fs2.Bit(8) {
		t.Fatal("bit8")
	}
	if fs2.Bit(9) {
		t.Fatal("bit9 should be 0")
	}
	// decode preserves bit order
	b := fs2.Marshal()
	g, err := DecodeFileStatus(b)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		if g.Bit(i) != fs2.Bit(i) {
			t.Fatalf("bit %d mismatch", i)
		}
	}
}

func TestFileStatusTrailingAndTruncated(t *testing.T) {
	h := [16]byte{1}
	status := []byte{0xAB}
	fs := FileStatus{Hash: h, Count: 8, Status: status}
	b := fs.Marshal()
	// truncated: remove last byte
	if _, err := DecodeFileStatus(b[:len(b)-1]); err == nil {
		t.Fatal("expected truncated")
	}
	// truncated header
	if _, err := DecodeFileStatus(b[:17]); err == nil {
		t.Fatal("expected truncated header")
	}
	// trailing bytes
	trail := append(append([]byte{}, b...), 0x00)
	if _, err := DecodeFileStatus(trail); err == nil {
		t.Fatal("expected trailing")
	}
}

func TestFileStatusCountAliases(t *testing.T) {
	h := [16]byte{5}
	status := []byte{0x55}
	for _, fs := range []FileStatus{
		{Hash: h, NumParts: 8, Status: status},
		{Hash: h, BlockCount: 8, Bitmap: status},
		{Hash: h, NumBlocks: 8, Bits: status},
		{Hash: h, Count: 8, Available: status},
	} {
		b := fs.Marshal()
		g, err := DecodeFileStatus(b)
		if err != nil {
			t.Fatal(err)
		}
		if g.Count != 8 {
			t.Fatalf("count=%d", g.Count)
		}
	}
}

func TestFileStatusHashAliases(t *testing.T) {
	h := [16]byte{42}
	for _, fs := range []FileStatus{
		{FileHash: h, Count: 0},
		{MD4: h, Count: 0},
	} {
		b := fs.Marshal()
		g, err := DecodeFileStatus(b)
		if err != nil {
			t.Fatal(err)
		}
		if g.Hash != h {
			t.Fatal("hash mismatch")
		}
	}
}

func TestFileStatusErrorsWrapped(t *testing.T) {
	if _, err := DecodeFileStatus(make([]byte, 10)); err == nil || !errors.Is(err, ErrFileStatus) {
		t.Fatal("expected ErrFileStatus")
	}
	if _, err := DecodeFileStatusRequest(make([]byte, 10)); err == nil || !errors.Is(err, ErrFileStatusRequest) {
		t.Fatal("expected ErrFileStatusRequest")
	}
}