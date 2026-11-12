// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestPartMetRoundTrip(t *testing.T) {
	h := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	parts := [][16]byte{
		{0xAA, 0xBB},
		{0xCC, 0xDD},
	}
	cases := []struct {
		name string
		pm   PartMet
	}{
		{"empty", PartMet{}},
		{"basic", PartMet{FileSize: 12345, FileHash: h, PartSize: 9728000, PartHashes: parts, FileName: "foo.bar"}},
		{"alias-fields", PartMet{Size: 99, Hash: h, PartLen: 1000, Parts: parts, Name: "alias.txt"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c.pm.Marshal()
			g, err := DecodePartMet(b)
			if err != nil {
				t.Fatal(err)
			}
			if g.FileSize != c.pm.normalizedSize() {
				t.Fatalf("file size mismatch: %d vs %d", g.FileSize, c.pm.normalizedSize())
			}
			if g.FileHash != c.pm.normalizedHash() {
				t.Fatalf("file hash mismatch")
			}
			if g.PartSize != c.pm.normalizedPartSize() {
				t.Fatalf("part size mismatch: %d vs %d", g.PartSize, c.pm.normalizedPartSize())
			}
			if len(g.PartHashes) != len(c.pm.normalizedParts()) {
				t.Fatalf("part count mismatch")
			}
			for i := range g.PartHashes {
				if g.PartHashes[i] != c.pm.normalizedParts()[i] {
					t.Fatalf("part hash %d mismatch", i)
				}
			}
			if g.FileName != c.pm.normalizedName() {
				t.Fatalf("file name mismatch: %q vs %q", g.FileName, c.pm.normalizedName())
			}
			if !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("re-encode mismatch")
			}
			// alias helpers
			if !bytes.Equal(c.pm.Encode(), b) {
				t.Fatal("Encode mismatch")
			}
			if !bytes.Equal(c.pm.Bytes(), b) {
				t.Fatal("Bytes mismatch")
			}
			g2, err := ParsePartMet(b)
			if err != nil || g2.FileSize != g.FileSize {
				t.Fatal("ParsePartMet mismatch")
			}
		})
	}
}

// helper accessors for tests (unexported, same package)
func (p PartMet) normalizedSize() uint64 {
	s, _, _, _, _ := p.normalized()
	return s
}
func (p PartMet) normalizedHash() [16]byte {
	_, h, _, _, _ := p.normalized()
	return h
}
func (p PartMet) normalizedPartSize() uint64 {
	_, _, ps, _, _ := p.normalized()
	return ps
}
func (p PartMet) normalizedParts() [][16]byte {
	_, _, _, ps, _ := p.normalized()
	return ps
}
func (p PartMet) normalizedName() string {
	_, _, _, _, n := p.normalized()
	return n
}

func TestPartMetMalformed(t *testing.T) {
	cases := [][]byte{
		{},                                    // empty
		{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, // too short
	}
	for i, c := range cases {
		if _, err := DecodePartMet(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
	// trailing bytes
	b := PartMet{FileSize: 10, FileName: "x"}.Marshal()
	if _, err := DecodePartMet(append(b, 0x00)); err == nil {
		t.Fatal("expected error on trailing bytes")
	}
	// too many parts: craft count
	bad := make([]byte, 8+16+8+4)
	binary.LittleEndian.PutUint32(bad[8+16+8:], MaxPartMetParts+1)
	if _, err := DecodePartMet(bad); err == nil {
		t.Fatal("expected error on too many parts")
	}
	// method/alias decode
	var pm PartMet
	if err := pm.Decode(b); err != nil {
		t.Fatal(err)
	}
	if err := pm.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	// fuzz-ish: round trip via top-level helpers
	if !bytes.Equal(MarshalPartMet(pm), EncodePartMet(pm)) {
		t.Fatal("top-level helper mismatch")
	}
}

func FuzzPartMet(f *testing.F) {
	f.Add([]byte{})
	f.Add(PartMet{FileSize: 100, FileHash: [16]byte{1}, PartSize: 10, PartHashes: [][16]byte{{2}}, FileName: "a"}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		pm, err := DecodePartMet(data)
		if err != nil {
			return
		}
		b := pm.Marshal()
		g, err := DecodePartMet(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}
