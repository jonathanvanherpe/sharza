// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func makePartMetVerifyData(t *testing.T) (PartMet, []byte) {
	t.Helper()
	partSize := uint64(64)
	fileSize := uint64(64*3 + 10)
	data := bytes.Repeat([]byte{0xAB}, int(fileSize))
	nParts := int((fileSize + partSize - 1) / partSize)
	parts := make([][16]byte, nParts)
	for i := 0; i < nParts; i++ {
		start := uint64(i) * partSize
		end := start + partSize
		if end > fileSize {
			end = fileSize
		}
		parts[i] = md4Sum(data[start:end])
	}
	fileHash := md4Sum(data)
	pm := PartMet{
		FileSize:   fileSize,
		FileHash:   fileHash,
		PartSize:   partSize,
		PartHashes: parts,
	}
	return pm, data
}

func TestPartMetVerifyBasic(t *testing.T) {
	pm, data := makePartMetVerifyData(t)
	ok, corrupt := PartMetVerify(data, pm)
	if !ok {
		t.Fatalf("expected ok, got corrupt=%v", corrupt)
	}
	if len(corrupt) != 0 {
		t.Fatalf("expected no corrupt indices, got %v", corrupt)
	}
}

func TestPartMetVerifySingleCorruptPart(t *testing.T) {
	pm, data := makePartMetVerifyData(t)
	pm.FileHash = [16]byte{} // per-part only scenario
	pm.Hash = [16]byte{}
	pm.MD4 = [16]byte{}
	bad := append([]byte(nil), data...)
	bad[5] ^= 0xFF
	ok, corrupt := PartMetVerify(bad, pm)
	if ok {
		t.Fatal("expected not ok")
	}
	if len(corrupt) != 1 || corrupt[0] != 0 {
		t.Fatalf("expected [0], got %v", corrupt)
	}
}

func TestPartMetVerifySizeMismatch(t *testing.T) {
	pm, data := makePartMetVerifyData(t)
	ok, _ := PartMetVerify(data[:len(data)-1], pm)
	if ok {
		t.Fatal("expected not ok on size mismatch")
	}
}

func TestPartMetVerifyEmpty(t *testing.T) {
	data := []byte{}
	fileHash := md4Sum(data)
	pm := PartMet{FileSize: 0, FileHash: fileHash, PartSize: 64, PartHashes: nil}
	ok, corrupt := PartMetVerify(data, pm)
	if !ok {
		t.Fatalf("expected ok for empty, corrupt=%v", corrupt)
	}
}

func TestPartMetVerifyTruncatedNoPanic(t *testing.T) {
	pm, data := makePartMetVerifyData(t)
	for n := 0; n <= len(data); n += 7 {
		ok, corrupt := PartMetVerify(data[:n], pm)
		_ = ok
		_ = corrupt
	}
}

func TestPartMetVerifyAliasFields(t *testing.T) {
	partSize := uint64(64)
	fileSize := uint64(100)
	data := bytes.Repeat([]byte{0x37}, int(fileSize))
	nParts := int((fileSize + partSize - 1) / partSize)
	parts := make([][16]byte, nParts)
	for i := 0; i < nParts; i++ {
		start := uint64(i) * partSize
		end := start + partSize
		if end > fileSize {
			end = fileSize
		}
		parts[i] = md4Sum(data[start:end])
	}
	fileHash := md4Sum(data)
	pm := PartMet{Size: fileSize, Hash: fileHash, PartLen: partSize, Parts: parts}
	ok, corrupt := PartMetVerify(data, pm)
	if !ok {
		t.Fatalf("alias PartMet should verify: %v", corrupt)
	}
}

func TestPartMetVerifyAliases(t *testing.T) {
	pm, data := makePartMetVerifyData(t)
	o1, c1 := PartMetVerify(data, pm)
	o2, c2 := VerifyPartMet(data, pm)
	o3, c3 := PartMetCheck(data, pm)
	o4, c4 := CheckPartMet(data, pm)
	if o1 != o2 || o1 != o3 || o1 != o4 {
		t.Fatal("alias ok mismatch")
	}
	if len(c1) != len(c2) || len(c1) != len(c3) || len(c1) != len(c4) {
		t.Fatal("alias corrupt mismatch")
	}
}

func TestPartMetPartHash(t *testing.T) {
	data := []byte{1, 2, 3, 4, 5}
	got := PartMetPartHash(data, 2, 1)
	want := md4Sum(data[2:4])
	if got != want {
		t.Fatalf("mismatch: %x vs %x", got, want)
	}
	// out of range
	if PartMetPartHash(data, 2, 10) != ([16]byte{}) {
		t.Fatal("expected zero for out of range")
	}
}

func TestPartMetVerifyRootMismatch(t *testing.T) {
	pm, data := makePartMetVerifyData(t)
	pm.FileHash[0] ^= 0xFF
	// update aliases not needed; normalized picks FileHash since non-zero
	ok, corrupt := PartMetVerify(data, pm)
	if ok {
		t.Fatal("expected not ok on root mismatch")
	}
	if len(corrupt) == 0 {
		t.Fatal("expected corrupt indices on root mismatch")
	}
}

func FuzzPartMetVerifyLocal(f *testing.F) {
	f.Add([]byte("abc"), uint64(2), uint64(3))
	f.Fuzz(func(t *testing.T, data []byte, partSize uint64, fileSize uint64) {
		pm := PartMet{FileSize: fileSize, PartSize: partSize}
		PartMetVerify(data, pm)
		PartMetPartHash(data, partSize, 0)
	})
}