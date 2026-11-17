// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func makePartMetAndData(t *testing.T) (PartMet, []byte) {
	t.Helper()
	partSize := uint64(64)
	fileSize := uint64(64*3 + 10)
	data := bytes.Repeat([]byte{0xAB}, int(fileSize))
	// part hashes
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

func TestPartVerifyBasic(t *testing.T) {
	pm, data := makePartMetAndData(t)
	res, err := VerifyPartMet(pm, data)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatalf("expected verified, got %+v", res)
	}
	if !res.SizeMatch {
		t.Fatal("size mismatch")
	}
	if !res.FileHashMatch {
		t.Fatal("file hash mismatch")
	}
	if len(res.PartsVerified) != 4 {
		t.Fatalf("parts verified len = %d, want 4", len(res.PartsVerified))
	}
	for i, ok := range res.PartsVerified {
		if !ok {
			t.Fatalf("part %d not verified", i)
		}
	}
}

func TestPartVerifyMutationPart(t *testing.T) {
	pm, data := makePartMetAndData(t)
	corrupt := append([]byte(nil), data...)
	corrupt[5] ^= 0xFF
	res, err := VerifyPartMet(pm, corrupt)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified {
		t.Fatal("expected not verified after part corruption")
	}
	if res.FileHashMatch {
		t.Fatal("file hash should mismatch")
	}
}

func TestPartVerifyMutationHash(t *testing.T) {
	pm, data := makePartMetAndData(t)
	pm.PartHashes[0][0] ^= 0xFF
	pm.PartHashes = append([][16]byte(nil), pm.PartHashes...)
	// update aliases? normalized uses PartHashes
	res, err := VerifyPartMet(pm, data)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified {
		t.Fatal("expected not verified after hash corruption")
	}
	if res.PartsVerified[0] {
		t.Fatal("part 0 should not verify")
	}
}

func TestPartVerifySizeMismatch(t *testing.T) {
	pm, data := makePartMetAndData(t)
	res, err := VerifyPartMet(pm, data[:len(data)-1])
	if err != nil {
		t.Fatal(err)
	}
	if res.Verified {
		t.Fatal("expected not verified on size mismatch")
	}
	if res.SizeMatch {
		t.Fatal("size should not match")
	}
}

func TestPartVerifyAICH(t *testing.T) {
	pm, data := makePartMetAndData(t)
	root := AICHRoot(data, AICHBlockSize)
	res, err := VerifyPartMet(pm, data, root)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatal("expected verified with AICH root")
	}
	if !res.AICHMatch {
		t.Fatal("AICH should match")
	}
	// wrong root
	wrong := root
	wrong[0] ^= 0xFF
	res2, err := VerifyPartMet(pm, data, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if res2.Verified {
		t.Fatal("expected not verified with wrong AICH root")
	}
	if res2.AICHMatch {
		t.Fatal("AICH should not match")
	}
}

func TestPartVerifyAliases(t *testing.T) {
	pm, data := makePartMetAndData(t)
	r1, _ := VerifyPart(pm, data)
	r2, _ := PartVerify(pm, data)
	r3, _ := pm.Verify(data)
	if r1.Verified != r2.Verified || r1.Verified != r3.Verified {
		t.Fatal("alias mismatch")
	}
	// alias fields
	if pm2 := pm; true {
		_ = pm2
	}
}

func TestPartVerifyEmpty(t *testing.T) {
	data := []byte{}
	fileHash := md4Sum(data)
	pm := PartMet{FileSize: 0, FileHash: fileHash, PartSize: 64, PartHashes: nil}
	res, err := VerifyPartMet(pm, data)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatalf("empty file should verify: %+v", res)
	}
}

func TestPartVerifyAliasFieldsPartMet(t *testing.T) {
	// alias-tolerant PartMet
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
	res, err := VerifyPartMet(pm, data)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Verified {
		t.Fatalf("alias PartMet should verify: %+v", res)
	}
}