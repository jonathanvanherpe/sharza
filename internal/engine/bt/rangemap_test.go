// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import "testing"

func TestCanonicalBlocksForPieceTable(t *testing.T) {
	cases := []struct {
		name      string
		pieceIndex uint64
		pieceSize  uint64
		fileSize   uint64
		blockSize  uint64
		want      []uint64
	}{
		{"empty file", 0, 8, 0, 4, nil},
		{"zero piece size", 0, 0, 16, 4, nil},
		{"zero block size", 0, 8, 16, 0, nil},
		{"piece out of range", 5, 8, 16, 4, nil},
		{"exact alignment piece0", 0, 8, 16, 4, []uint64{0, 1}},
		{"exact alignment piece1", 1, 8, 16, 4, []uint64{2, 3}},
		{"partial tail piece", 1, 8, 10, 4, []uint64{2}},
		{"file smaller than one block", 0, 8, 3, 4, []uint64{0}},
		{"non-aligned piece0", 0, 5, 12, 3, []uint64{0, 1}},
		{"non-aligned piece1", 1, 5, 12, 3, []uint64{1, 2, 3}},
		{"non-aligned piece2", 2, 5, 12, 3, []uint64{3}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := CanonicalBlocksForPiece(c.pieceIndex, c.pieceSize, c.fileSize, c.blockSize)
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

func TestPiecesForBlockTable(t *testing.T) {
	cases := []struct {
		name       string
		blockIndex uint64
		pieceSize  uint64
		fileSize   uint64
		blockSize  uint64
		want       []uint64
	}{
		{"empty file", 0, 8, 0, 4, nil},
		{"zero piece size", 0, 0, 16, 4, nil},
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
			got := PiecesForBlock(c.blockIndex, c.pieceSize, c.fileSize, c.blockSize)
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
	if got := MapPieceToBlocks(0, 8, 16, 4); len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("MapPieceToBlocks: %v", got)
	}
	if got := MapBlockToPieces(2, 8, 16, 4); len(got) != 1 || got[0] != 1 {
		t.Fatalf("MapBlockToPieces: %v", got)
	}
	if got := BlocksForPiece(0, 8, 16, 4); len(got) != 2 {
		t.Fatalf("BlocksForPiece: %v", got)
	}
	if got := PieceToBlocks(0, 8, 16, 4); len(got) != 2 {
		t.Fatalf("PieceToBlocks: %v", got)
	}
	if got := BlocksToPieces(2, 8, 16, 4); len(got) != 1 {
		t.Fatalf("BlocksToPieces: %v", got)
	}
	if got := BlockToPieces(2, 8, 16, 4); len(got) != 1 {
		t.Fatalf("BlockToPieces: %v", got)
	}
}

func TestRangeMapMethods(t *testing.T) {
	rm := NewRangeMap(16, 8, 4)
	if got := rm.CanonicalBlocksForPiece(1); len(got) != 2 || got[0] != 2 {
		t.Fatalf("method piece: %v", got)
	}
	if got := rm.PiecesForBlock(3); len(got) != 1 || got[0] != 1 {
		t.Fatalf("method block: %v", got)
	}
	if got := rm.MapPieceToBlocks(0); len(got) != 2 {
		t.Fatalf("MapPieceToBlocks method: %v", got)
	}
	if got := rm.MapBlockToPieces(0); len(got) != 1 {
		t.Fatalf("MapBlockToPieces method: %v", got)
	}
	// alias fields
	rm2 := RangeMap{Size: 16, PieceLength: 8, CanonicalBlockSize: 4}
	if got := rm2.PiecesForBlock(0); len(got) != 1 || got[0] != 0 {
		t.Fatalf("alias fields: %v", got)
	}
	rm3 := RangeMap{TotalSize: 16, PartSize: 8, BlockLen: 4}
	if got := rm3.PiecesForBlock(0); len(got) != 1 || got[0] != 0 {
		t.Fatalf("alias fields2: %v", got)
	}
	rm4 := RangeMap{Length: 16, PartLen: 8, BlockSize: 4}
	if got := rm4.PiecesForBlock(0); len(got) != 1 || got[0] != 0 {
		t.Fatalf("alias fields3: %v", got)
	}
}

func TestRangeMapConsistency(t *testing.T) {
	fileSize, pieceSize, blockSize := uint64(100), uint64(30), uint64(7)
	nBlocks := (fileSize + blockSize - 1) / blockSize
	for b := uint64(0); b < nBlocks; b++ {
		pieces := PiecesForBlock(b, pieceSize, fileSize, blockSize)
		if len(pieces) == 0 {
			t.Fatalf("block %d has no pieces", b)
		}
		for _, p := range pieces {
			blocks := CanonicalBlocksForPiece(p, pieceSize, fileSize, blockSize)
			found := false
			for _, bb := range blocks {
				if bb == b {
					found = true
					break
				}
			}
			if !found {
				t.Fatalf("block %d not in piece %d's blocks", b, p)
			}
		}
	}
}

func TestNewRangeMapFromPieces(t *testing.T) {
	rm := NewRangeMapFromPieces(8, 16, 4)
	if got := rm.CanonicalBlocksForPiece(1); len(got) != 2 || got[0] != 2 {
		t.Fatalf("from pieces: %v", got)
	}
}

func TestOverflowGuard(t *testing.T) {
	// out of range index returns nil
	if got := CanonicalBlocksForPiece(^uint64(0), 8, 16, 4); got != nil {
		t.Fatalf("overflow piece: %v", got)
	}
	if got := PiecesForBlock(^uint64(0), 8, 16, 4); got != nil {
		t.Fatalf("overflow block: %v", got)
	}
}