// SPDX-License-Identifier: GPL-3.0-or-later

package swarm

import (
	"bytes"
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
)

func TestCrossNetworkNoDuplicateAndAllVerified(t *testing.T) {
	const blockCount = 4
	sw := New(blockCount*blockmap.DefaultBlockSize, "bt", "ed2k")
	if sw.BlockCount() != blockCount {
		t.Fatalf("BlockCount = %d, want %d", sw.BlockCount(), blockCount)
	}

	btBlocks := sw.Lease("bt", 1)
	edBlocks := sw.Lease("ed2k", blockCount)

	seen := make(map[uint64]bool)
	for _, b := range btBlocks {
		seen[b] = true
	}
	for _, b := range edBlocks {
		if seen[b] {
			t.Fatalf("block %d handed to both networks", b)
		}
		seen[b] = true
	}
	if len(seen) != int(sw.BlockCount()) {
		t.Fatalf("leased union covers %d blocks, want %d (bt=%v ed2k=%v)",
			len(seen), sw.BlockCount(), btBlocks, edBlocks)
	}

	for _, b := range btBlocks {
		if !sw.Complete("bt", b, []byte{byte(0x10 + b)}) {
			t.Fatalf("Complete(bt, %d) returned false", b)
		}
	}
	for _, b := range edBlocks {
		if !sw.Complete("ed2k", b, []byte{byte(0x50 + b)}) {
			t.Fatalf("Complete(ed2k, %d) returned false", b)
		}
	}

	if !sw.IsComplete() {
		t.Fatal("IsComplete() = false, want true")
	}
	if sw.VerifiedCount() != sw.BlockCount() {
		t.Fatalf("VerifiedCount = %d, want %d", sw.VerifiedCount(), sw.BlockCount())
	}
	for i := uint64(0); i < sw.BlockCount(); i++ {
		if sw.VerifiedBy(i) == "" {
			t.Fatalf("block %d has empty VerifiedBy()", i)
		}
	}
	if sw.VerifiedCount("bt") == 0 {
		t.Fatal("bt contributed no blocks")
	}
	if sw.VerifiedCount("ed2k") == 0 {
		t.Fatal("ed2k contributed no blocks")
	}
}

func TestCrossNetworkWholeFileSourceJoins(t *testing.T) {
	const blockCount = 4
	sw := New(blockCount*blockmap.DefaultBlockSize, "bt", "ed2k")
	for i := uint64(0); i < sw.BlockCount(); i++ {
		if !sw.Complete("gnutella", i, nil) {
			t.Fatalf("Complete(gnutella, %d) returned false", i)
		}
	}
	if !sw.IsComplete() {
		t.Fatal("IsComplete() = false after whole-file source joined")
	}
	if bt := sw.Lease("bt", blockCount); len(bt) != 0 {
		t.Fatalf("bt re-leased blocks after whole-file completion: %v", bt)
	}
	if ed := sw.Lease("ed2k", blockCount); len(ed) != 0 {
		t.Fatalf("ed2k re-leased blocks after whole-file completion: %v", ed)
	}
}

func TestCrossNetworkDuplicateCompletionRejected(t *testing.T) {
	const blockCount = 4
	sw := New(blockCount*blockmap.DefaultBlockSize, "bt", "ed2k")
	idxs := sw.Lease("bt", 1)
	if len(idxs) != 1 {
		t.Fatalf("lease len = %d, want 1", len(idxs))
	}
	idx := idxs[0]
	first := []byte("first-payload")
	if !sw.Complete("bt", idx, first) {
		t.Fatal("first Complete returned false")
	}
	if sw.Complete("bt", idx, []byte("second-payload")) {
		t.Fatal("duplicate completion by same network accepted")
	}
	if sw.Complete("ed2k", idx, []byte("second-payload")) {
		t.Fatal("duplicate completion by other network accepted")
	}
	if !bytes.Equal(sw.Block(idx), first) {
		t.Fatalf("stored bytes overwritten: got %q, want %q", sw.Block(idx), first)
	}
	if sw.VerifiedCount() != 1 {
		t.Fatalf("VerifiedCount = %d, want 1", sw.VerifiedCount())
	}
}
