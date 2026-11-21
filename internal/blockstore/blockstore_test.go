// SPDX-License-Identifier: GPL-3.0-or-later

package blockstore

import (
	"bytes"
	"sync"
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
)

const oneMiB = 1 << 20

func newStore(blocks uint64) *BlockStore {
	bm := blockmap.New(blocks*blockmap.DefaultBlockSize, 0)
	return New(bm)
}

func TestPutGet(t *testing.T) {
	bs := newStore(3)
	data := []byte("hello block")
	if !bs.PutBlock(0, data) {
		t.Fatal("PutBlock failed")
	}
	got := bs.Block(0)
	if !bytes.Equal(got, data) {
		t.Fatalf("Block = %q, want %q", got, data)
	}
	// mutation of returned slice does not affect store
	got[0] = 'X'
	if bs.Block(0)[0] == 'X' {
		t.Fatal("Block returned mutable reference")
	}
	if bs.Block(1) != nil {
		t.Fatal("unset block should be nil")
	}
}

func TestBounds(t *testing.T) {
	bs := newStore(2)
	if bs.PutBlock(2, []byte("x")) {
		t.Fatal("out-of-range PutBlock should fail")
	}
	if bs.Block(2) != nil {
		t.Fatal("out-of-range Block should be nil")
	}
	if bs.MarkVerified(2, "net") {
		t.Fatal("out-of-range MarkVerified should fail")
	}
	if bs.IsVerified(2) || bs.IsVerified(2, "net") {
		t.Fatal("out-of-range IsVerified should be false")
	}
	if bs.VerifiedBy(2) != "" {
		t.Fatal("out-of-range VerifiedBy should be empty")
	}
	if len(bs.UnverifiedBlocks()) != 2 {
		t.Fatalf("unverified len = %d", len(bs.UnverifiedBlocks()))
	}
}

func TestPerNetworkIndependence(t *testing.T) {
	bs := newStore(2)
	bs.PutBlock(0, []byte("data"))
	bs.MarkVerified(0, "bt")
	if !bs.IsVerified(0) {
		t.Fatal("should be verified by any")
	}
	if !bs.IsVerified(0, "bt") {
		t.Fatal("should be verified by bt")
	}
	if bs.IsVerified(0, "ed2k") {
		t.Fatal("should not be verified by ed2k")
	}
	if bs.VerifiedBy(0) != "bt" {
		t.Fatalf("VerifiedBy = %q, want bt", bs.VerifiedBy(0))
	}
	// marking via second network does not verify for first
	bs.MarkVerified(1, "ed2k")
	if bs.IsVerified(1, "bt") {
		t.Fatal("ed2k mark verified bt")
	}
	if bs.VerifiedBy(1) != "ed2k" {
		t.Fatalf("VerifiedBy = %q", bs.VerifiedBy(1))
	}
}

func TestMutatingBytesDoesNotVerify(t *testing.T) {
	bs := newStore(1)
	bs.PutBlock(0, []byte("data"))
	if bs.IsVerified(0) {
		t.Fatal("PutBlock should not verify")
	}
	if bs.VerifiedCount() != 0 {
		t.Fatal("verified count should be 0")
	}
	if len(bs.UnverifiedBlocks()) != 1 {
		t.Fatal("block should remain unverified")
	}
}

func TestVerifiedCountTransitions(t *testing.T) {
	bs := newStore(3)
	bs.MarkVerified(0, "bt")
	if bs.VerifiedCount() != 1 {
		t.Fatalf("count = %d", bs.VerifiedCount())
	}
	if bs.VerifiedCount("bt") != 1 {
		t.Fatalf("bt count = %d", bs.VerifiedCount("bt"))
	}
	if bs.VerifiedCount("ed2k") != 0 {
		t.Fatalf("ed2k count = %d", bs.VerifiedCount("ed2k"))
	}
	bs.MarkVerified(1, "bt")
	bs.MarkVerified(1, "ed2k")
	if bs.VerifiedCount() != 2 {
		t.Fatalf("unique verified count = %d", bs.VerifiedCount())
	}
	bs.MarkVerified(2, "ed2k")
	if !bs.AllVerified() {
		t.Fatal("AllVerified should be true")
	}
	if len(bs.UnverifiedBlocks()) != 0 {
		t.Fatalf("unverified len = %d", len(bs.UnverifiedBlocks()))
	}
}

func TestEmptyStoreAllVerified(t *testing.T) {
	bs := New(blockmap.New(0, 0))
	if !bs.AllVerified() {
		t.Fatal("empty store should be all verified")
	}
	if bs.VerifiedCount() != 0 {
		t.Fatal("verified count")
	}
	if len(bs.UnverifiedBlocks()) != 0 {
		t.Fatal("unverified len")
	}
}

func TestConstructorSizes(t *testing.T) {
	bs := New(uint64(2*oneMiB+5), uint64(0))
	if bs.BlockMap().BlockCount() != 3 {
		t.Fatalf("count = %d", bs.BlockMap().BlockCount())
	}
	bs2 := New(3 * oneMiB)
	if bs2.BlockMap().BlockCount() != 3 {
		t.Fatalf("count2 = %d", bs2.BlockMap().BlockCount())
	}
}

func TestConcurrency(t *testing.T) {
	bs := newStore(8)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			bs.PutBlock(uint64(i), []byte{byte(i)})
			bs.MarkVerified(uint64(i), "net")
		}(i)
	}
	wg.Wait()
	if bs.VerifiedCount() != 8 {
		t.Fatalf("verified = %d", bs.VerifiedCount())
	}
	if !bs.AllVerified() {
		t.Fatal("not all verified")
	}
	// concurrent reads
	var wg2 sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg2.Add(1)
		go func(i int) {
			defer wg2.Done()
			_ = bs.Block(uint64(i))
			_ = bs.IsVerified(uint64(i), "net")
			_ = bs.VerifiedBy(uint64(i))
		}(i)
	}
	wg2.Wait()
}

func FuzzBlockStore(f *testing.F) {
	f.Add(uint64(0), uint64(0))
	f.Add(uint64(1), uint64(0))
	f.Add(uint64(oneMiB), uint64(0))
	f.Add(uint64(oneMiB+1), uint64(0))
	f.Add(uint64(3*oneMiB), uint64(4))
	f.Fuzz(func(t *testing.T, fileSize, blockSize uint64) {
		bs := New(fileSize, blockSize)
		n := bs.BlockMap().BlockCount()
		// bounds safety
		if n > 0 {
			last := n - 1
			if !bs.PutBlock(last, []byte("x")) {
				t.Fatal("PutBlock last failed")
			}
			if !bytes.Equal(bs.Block(last), []byte("x")) {
				t.Fatal("get mismatch")
			}
			if bs.PutBlock(n, []byte("x")) {
				t.Fatal("out-of-range PutBlock succeeded")
			}
			if bs.Block(n) != nil {
				t.Fatal("out-of-range Block not nil")
			}
			bs.MarkVerified(last, "net")
			if !bs.IsVerified(last, "net") {
				t.Fatal("not verified")
			}
			if bs.IsVerified(last, "other") {
				t.Fatal("false verify other")
			}
		} else {
			if !bs.AllVerified() {
				t.Fatal("empty not all verified")
			}
		}
		if uint64(len(bs.UnverifiedBlocks())) != n-bs.VerifiedCount() {
			t.Fatal("unverified length mismatch")
		}
	})
}
