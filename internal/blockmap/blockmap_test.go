// SPDX-License-Identifier: GPL-3.0-or-later

package blockmap

import (
	"testing"
)

const oneMiB = 1 << 20

func TestBlockCountBoundary(t *testing.T) {
	cases := []struct {
		name     string
		fileSize uint64
		blockSz  uint64
		want     uint64
	}{
		{"zero", 0, 0, 0},
		{"one byte", 1, 0, 1},
		{"one MiB", oneMiB, 0, 1},
		{"one MiB plus one", oneMiB + 1, 0, 2},
		{"two and a half MiB", uint64(2.5 * oneMiB), 0, 3},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			bm := New(c.fileSize, c.blockSz)
			if got := bm.BlockCount(); got != c.want {
				t.Fatalf("BlockCount = %d, want %d", got, c.want)
			}
			if bm.FileSize() != c.fileSize {
				t.Fatalf("FileSize = %d, want %d", bm.FileSize(), c.fileSize)
			}
			bs := c.blockSz
			if bs == 0 {
				bs = DefaultBlockSize
			}
			if bm.BlockSize() != bs {
				t.Fatalf("BlockSize = %d, want %d", bm.BlockSize(), bs)
			}
		})
	}
}

func TestBlockByteRange(t *testing.T) {
	bm := New(2*oneMiB+5, 0)
	if bm.BlockCount() != 3 {
		t.Fatalf("count = %d", bm.BlockCount())
	}
	// block 0
	s, e, ok := bm.BlockByteRange(0)
	if !ok || s != 0 || e != oneMiB {
		t.Fatalf("block0 = %d,%d,%v", s, e, ok)
	}
	// block 1
	s, e, ok = bm.BlockByteRange(1)
	if !ok || s != oneMiB || e != 2*oneMiB {
		t.Fatalf("block1 = %d,%d,%v", s, e, ok)
	}
	// last partial block
	s, e, ok = bm.BlockByteRange(2)
	if !ok || s != 2*oneMiB || e != 2*oneMiB+5 {
		t.Fatalf("block2 = %d,%d,%v", s, e, ok)
	}
	// out of range
	if _, _, ok := bm.BlockByteRange(3); ok {
		t.Fatal("expected ok=false for out-of-range block")
	}
	// empty file has no blocks
	empty := New(0, 0)
	if _, _, ok := empty.BlockByteRange(0); ok {
		t.Fatal("empty file should have no block 0")
	}
}

func TestVerifiedRoundTrip(t *testing.T) {
	bm := New(3*oneMiB, 0)
	if bm.VerifiedCount() != 0 {
		t.Fatalf("initial verified = %d", bm.VerifiedCount())
	}
	indices := []uint64{0, 1, 2}
	for _, i := range indices {
		bm.SetVerified(i)
	}
	for _, i := range indices {
		if !bm.IsVerified(i) {
			t.Fatalf("block %d not verified after SetVerified", i)
		}
	}
	if bm.VerifiedCount() != 3 {
		t.Fatalf("verified count = %d, want 3", bm.VerifiedCount())
	}
	if !bm.AllVerified() {
		t.Fatal("AllVerified should be true")
	}
	if len(bm.Unverified()) != 0 {
		t.Fatalf("Unverified len = %d, want 0", len(bm.Unverified()))
	}
}

func TestAllVerifiedFalseUntilComplete(t *testing.T) {
	bm := New(3*oneMiB, 0)
	bm.SetVerified(0)
	bm.SetVerified(2)
	if bm.AllVerified() {
		t.Fatal("AllVerified true with a gap")
	}
	if bm.VerifiedCount() != 2 {
		t.Fatalf("verified = %d", bm.VerifiedCount())
	}
	unv := bm.Unverified()
	if len(unv) != 1 || unv[0] != 1 {
		t.Fatalf("Unverified = %v, want [1]", unv)
	}
	// out-of-range SetVerified is a no-op
	bm.SetVerified(999)
	if bm.VerifiedCount() != 2 {
		t.Fatalf("out-of-range SetVerified changed count: %d", bm.VerifiedCount())
	}
	// IsVerified out of range false
	if bm.IsVerified(999) {
		t.Fatal("IsVerified out of range should be false")
	}
}

func TestUnverifiedOrder(t *testing.T) {
	bm := New(5*oneMiB, 0)
	bm.SetVerified(1)
	bm.SetVerified(3)
	got := bm.Unverified()
	want := []uint64{0, 2, 4}
	if len(got) != len(want) {
		t.Fatalf("len %d vs %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Unverified[%d]=%d want %d", i, got[i], want[i])
		}
	}
}

func TestDefaultBlockSizeZero(t *testing.T) {
	if DefaultBlockSize != 1<<20 {
		t.Fatalf("DefaultBlockSize = %d", DefaultBlockSize)
	}
	bm := New(100, 0)
	if bm.BlockSize() != DefaultBlockSize {
		t.Fatalf("default not applied: %d", bm.BlockSize())
	}
}

func TestNewBlockSizeCustom(t *testing.T) {
	bm := New(10, 4)
	if bm.BlockCount() != 3 {
		t.Fatalf("count = %d", bm.BlockCount())
	}
	// ranges
	s, e, _ := bm.BlockByteRange(2)
	if s != 8 || e != 10 {
		t.Fatalf("last range = %d,%d", s, e)
	}
}

func TestEmptyFileAllVerified(t *testing.T) {
	bm := New(0, 0)
	if bm.BlockCount() != 0 {
		t.Fatalf("count = %d", bm.BlockCount())
	}
	if !bm.AllVerified() {
		t.Fatal("empty file should be all verified")
	}
	if bm.VerifiedCount() != 0 {
		t.Fatalf("verified = %d", bm.VerifiedCount())
	}
	if len(bm.Unverified()) != 0 {
		t.Fatalf("unverified len = %d", len(bm.Unverified()))
	}
}

func FuzzBlockMap(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(1), uint64(0))
	f.Add(uint64(oneMiB), uint64(0))
	f.Add(uint64(oneMiB+1), uint64(0))
	f.Add(uint64(2*oneMiB+oneMiB/2), uint64(0))
	f.Add(uint64(100), uint64(4))
	f.Fuzz(func(t *testing.T, fileSize, blockSize uint64) {
		bm := New(fileSize, blockSize)
		bs := blockSize
		if bs == 0 {
			bs = DefaultBlockSize
		}
		// block count formula
		var want uint64
		if fileSize > 0 {
			want = (fileSize-1)/bs + 1
		}
		if bm.BlockCount() != want {
			t.Fatalf("BlockCount = %d, want %d", bm.BlockCount(), want)
		}
		// byte ranges partition [0, fileSize)
		if bm.BlockCount() <= 100000 {
			var pos uint64
			for i := uint64(0); i < bm.BlockCount(); i++ {
				s, e, ok := bm.BlockByteRange(i)
				if !ok {
					t.Fatalf("BlockByteRange(%d) ok=false", i)
				}
				if s != pos {
					t.Fatalf("block %d start %d, want %d", i, s, pos)
				}
				if e <= s {
					t.Fatalf("block %d empty range", i)
				}
				if e > fileSize {
					t.Fatalf("block %d end %d > fileSize %d", i, e, fileSize)
				}
				pos = e
			}
			if pos != fileSize {
				t.Fatalf("ranges end at %d, want %d", pos, fileSize)
			}
		}
		// out-of-range byte range
		if _, _, ok := bm.BlockByteRange(bm.BlockCount()); ok && bm.BlockCount() > 0 {
			// blockCount index is out of range; ok must be false
			t.Fatal("BlockByteRange(blockCount) should be false")
		}
		// verified round-trip on last block (if any)
		n := bm.BlockCount()
		if n > 0 {
			last := n - 1
			bm.SetVerified(last)
			if !bm.IsVerified(last) {
				t.Fatal("IsVerified false after SetVerified")
			}
			if bm.VerifiedCount() < 1 {
				t.Fatal("VerifiedCount 0 after set")
			}
			if n > 1 && bm.AllVerified() {
				t.Fatal("AllVerified true with gaps")
			}
		} else {
			if !bm.AllVerified() {
				t.Fatal("empty file not all verified")
			}
		}
		// Unverified length consistency
		if uint64(len(bm.Unverified())) != n-bm.VerifiedCount() {
			t.Fatal("Unverified length mismatch")
		}
	})
}
