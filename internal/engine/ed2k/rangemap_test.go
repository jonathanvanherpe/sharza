// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import "testing"

func TestCanonicalBlocksForPartTable(t *testing.T) {
	cases := []struct {
		name      string
		partIndex uint64
		partSize  uint64
		fileSize  uint64
		blockSize uint64
		want      []uint64
	}{
		{"empty file", 0, 8, 0, 4, nil},
		{"zero part size", 0, 0, 16, 4, nil},
		{"zero block size", 0, 8, 16, 0, nil},
		{"part out of range", 5, 8, 16, 4, nil},
		{"exact alignment part0", 0, 8, 16, 4, []uint64{0, 1}},
		{"exact alignment part1", 1, 8, 16, 4, []uint64{2, 3}},
		{"partial tail part", 1, 8, 10, 4, []uint64{2}},
		{"file smaller than one block", 0, 8, 3, 4, []uint64{0}},
		{"non-aligned part0", 0, 5, 12, 3, []uint64{0, 1}},
		{"non-aligned part1", 1, 5, 12, 3, []uint64{1, 2, 3}},
		{"non-aligned part2", 2, 5, 12, 3, []uint64{3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CanonicalBlocksForPart(c.partIndex, c.partSize, c.fileSize, c.blockSize)
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d (%v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got[%d] = %d, want %d (got %v)", i, got[i], c.want[i], got)
				}
			}
		})
	}
}

func TestPartsForBlockTable(t *testing.T) {
	cases := []struct {
		name       string
		blockIndex uint64
		partSize   uint64
		fileSize   uint64
		blockSize  uint64
		want       []uint64
	}{
		{"empty file", 0, 8, 0, 4, nil},
		{"zero part size", 0, 0, 16, 4, nil},
		{"zero block size", 0, 8, 16, 0, nil},
		{"block out of range", 9, 8, 16, 4, nil},
		{"exact alignment block0", 0, 8, 16, 4, []uint64{0}},
		{"exact alignment block2", 2, 8, 16, 4, []uint64{1}},
		{"partial tail block", 2, 8, 10, 4, []uint64{1}},
		{"file smaller than one block", 0, 8, 3, 4, []uint64{0}},
		{"non-aligned block1", 1, 5, 12, 3, []uint64{0, 1}},
		{"non-aligned block3", 3, 5, 12, 3, []uint64{1, 2}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := PartsForBlock(c.blockIndex, c.partSize, c.fileSize, c.blockSize)
			if len(got) != len(c.want) {
				t.Fatalf("len = %d, want %d (%v)", len(got), len(c.want), got)
			}
			for i := range got {
				if got[i] != c.want[i] {
					t.Fatalf("got[%d] = %d, want %d (got %v)", i, got[i], c.want[i], got)
				}
			}
		})
	}
}

func TestMapAliases(t *testing.T) {
	if got := MapPartToBlocks(0, 8, 16, 4); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("MapPartToBlocks: %v", got)
	}
	if got := MapBlockToParts(2, 8, 16, 4); len(got) != 1 || got[0] != 1 {
		t.Fatalf("MapBlockToParts: %v", got)
	}
}

func TestRangeMapMethods(t *testing.T) {
	rm := NewRangeMap(16, 8, 4)
	if got := rm.CanonicalBlocksForPart(1); len(got) != 2 || got[0] != 2 {
		t.Fatalf("method part: %v", got)
	}
	if got := rm.PartsForBlock(3); len(got) != 1 || got[0] != 1 {
		t.Fatalf("method block: %v", got)
	}
	if got := rm.MapPartToBlocks(0); len(got) != 2 {
		t.Fatalf("MapPartToBlocks method: %v", got)
	}
	if got := rm.MapBlockToParts(0); len(got) != 1 {
		t.Fatalf("MapBlockToParts method: %v", got)
	}
	// alias fields
	rm2 := RangeMap{Size: 16, PartLen: 8, CanonicalBlockSize: 4}
	if got := rm2.PartsForBlock(0); len(got) != 1 || got[0] != 0 {
		t.Fatalf("alias fields: %v", got)
	}
}

func TestRangeMapConsistency(t *testing.T) {
	// Every canonical block of every part maps back to a part containing it.
	fileSize, partSize, blockSize := uint64(100), uint64(30), uint64(7)
	nBlocks := (fileSize + blockSize - 1) / blockSize
	for b := uint64(0); b < nBlocks; b++ {
		parts := PartsForBlock(b, partSize, fileSize, blockSize)
		if len(parts) == 0 {
			t.Fatalf("block %d has no parts", b)
		}
		for _, p := range parts {
			blocks := CanonicalBlocksForPart(p, partSize, fileSize, blockSize)
			found := false
			for _, bb := range blocks {
				if bb == b {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("block %d not in part %d's blocks", b, p)
			}
		}
	}
}
