// SPDX-License-Identifier: GPL-3.0-or-later

package swarm

import (
	"bytes"
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
	"github.com/jonathanvanherpe/sharza/internal/blockstore"
	"github.com/jonathanvanherpe/sharza/internal/scheduler"
)

func newSwarm(blocks uint64) *Swarm {
	bm := blockmap.New(blocks*blockmap.DefaultBlockSize, 0)
	bs := blockstore.New(bm)
	sc := scheduler.New(bm)
	return New(bs, sc)
}

func TestDisjointLeases(t *testing.T) {
	sw := newSwarm(4)
	a := sw.Lease("bt", 4)
	b := sw.Lease("ed2k", 4)
	seen := make(map[uint64]bool)
	for _, idx := range a {
		seen[idx] = true
	}
	for _, idx := range b {
		if seen[idx] {
			t.Fatalf("block %d handed to both networks", idx)
		}
	}
	if len(a)+len(b) != 4 {
		t.Fatalf("total leased = %d, want 4", len(a)+len(b))
	}
}

func TestPerNetworkVerification(t *testing.T) {
	sw := newSwarm(2)
	idxs := sw.Lease("bt", 1)
	if len(idxs) != 1 {
		t.Fatalf("lease len = %d, want 1", len(idxs))
	}
	idx := idxs[0]
	data := []byte("payload-bytes")
	if !sw.Complete("bt", idx, data) {
		t.Fatal("Complete returned false")
	}
	if !sw.BlockStore.IsVerified(idx, "bt") {
		t.Fatal("block not verified for bt")
	}
	if sw.BlockStore.IsVerified(idx, "ed2k") {
		t.Fatal("block verified for ed2k without completion")
	}
	got := sw.Block(idx)
	if !bytes.Equal(got, data) {
		t.Fatalf("Block = %q, want %q", got, data)
	}
	// completed block not handed out again
	more := sw.Lease("ed2k", 10)
	for _, b := range more {
		if b == idx {
			t.Fatal("completed block re-leased")
		}
	}
}

func TestNoDuplicateCompletion(t *testing.T) {
	sw := newSwarm(2)
	idxs := sw.Lease("bt", 1)
	if len(idxs) != 1 {
		t.Fatal("lease failed")
	}
	idx := idxs[0]
	data := []byte("x")
	if !sw.Complete("bt", idx, data) {
		t.Fatal("first Complete returned false")
	}
	if sw.Complete("bt", idx, data) {
		t.Fatal("duplicate completion by same network accepted")
	}
	if sw.Complete("ed2k", idx, data) {
		t.Fatal("duplicate completion by other network accepted")
	}
	if sw.VerifiedCount() != 1 {
		t.Fatalf("VerifiedCount = %d, want 1", sw.VerifiedCount())
	}
}

func TestCompletionOnlyAfterAllBlocks(t *testing.T) {
	sw := newSwarm(2)
	if sw.IsComplete() {
		t.Fatal("empty-ish: IsComplete true before any work")
	}
	idxs := sw.Lease("bt", 1)
	if len(idxs) != 1 {
		t.Fatal("lease failed")
	}
	sw.Complete("bt", idxs[0], []byte("a"))
	if sw.IsComplete() {
		t.Fatal("IsComplete true after partial completion")
	}
	if len(sw.Unverified()) != 1 {
		t.Fatalf("Unverified len = %d, want 1", len(sw.Unverified()))
	}
	if sw.VerifiedCount() != 1 {
		t.Fatalf("VerifiedCount = %d, want 1", sw.VerifiedCount())
	}
	more := sw.Lease("ed2k", 10)
	for _, idx := range more {
		sw.Complete("ed2k", idx, []byte("b"))
	}
	if !sw.IsComplete() {
		t.Fatal("IsComplete false after all blocks completed")
	}
	if len(sw.Unverified()) != 0 {
		t.Fatalf("Unverified len = %d, want 0", len(sw.Unverified()))
	}
	if sw.VerifiedCount() != 2 {
		t.Fatalf("VerifiedCount = %d, want 2", sw.VerifiedCount())
	}
}

func TestConstructorVariants(t *testing.T) {
	bm := blockmap.New(2*blockmap.DefaultBlockSize, 0)
	bs := blockstore.New(bm)
	sc := scheduler.New(bm)
	sw := New(bs, sc, "bt", "ed2k")
	if sw.BlockCount() != 2 {
		t.Fatalf("block count = %d", sw.BlockCount())
	}
	if sw.NetworkCount() != 2 {
		t.Fatalf("network count = %d", sw.NetworkCount())
	}
	sw2 := New(bm)
	if sw2.BlockCount() != 2 {
		t.Fatalf("block count = %d", sw2.BlockCount())
	}
	sw3 := New(2 * blockmap.DefaultBlockSize)
	if sw3.BlockCount() != 2 {
		t.Fatalf("block count = %d", sw3.BlockCount())
	}
	sw4 := New()
	if sw4.BlockCount() != 0 {
		t.Fatalf("block count = %d", sw4.BlockCount())
	}
}