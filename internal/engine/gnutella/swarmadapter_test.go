// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/swarm"
)

func TestSwarmAdapterLeaseCoversAllUnverifiedBlocks(t *testing.T) {
	const fileSize = 100
	const blockSize = 40
	a := NewAdapter(fileSize, blockSize, "gnutella")
	if a == nil {
		t.Fatal("nil adapter")
	}
	leased := a.Lease("gnutella")
	want := []uint64{0, 1, 2}
	if len(leased) != len(want) {
		t.Fatalf("leased blocks = %v, want %v", leased, want)
	}
	for i := range want {
		if leased[i] != want[i] {
			t.Fatalf("leased[%d] = %d, want %d (%v)", i, leased[i], want[i], leased)
		}
	}

	if !a.Complete("gnutella") {
		t.Fatalf("Complete returned false")
	}
	sw := a.Swarm
	if sw == nil {
		t.Fatal("nil swarm")
	}
	for i := uint64(0); i < sw.BlockCount(); i++ {
		if !sw.IsVerified(i) {
			t.Fatalf("canonical block %d not verified after completing whole file", i)
		}
	}
	if !a.IsComplete("gnutella") {
		t.Fatalf("IsComplete = false, want true")
	}
}

func TestSwarmAdapterCompletedFileMarksAllBlocks(t *testing.T) {
	const fileSize, blockSize = uint64(16), uint64(4)
	a := NewAdapter(fileSize, blockSize, "g2")
	if !a.Complete("g2") {
		t.Fatal("Complete returned false")
	}
	for i := uint64(0); i < a.Swarm.BlockCount(); i++ {
		if !a.Swarm.IsVerified(i) {
			t.Fatalf("block %d not verified", i)
		}
	}
	if !a.IsComplete() {
		t.Fatal("IsComplete false after complete")
	}
}

func TestSwarmAdapterIsCompleteFlipsTrue(t *testing.T) {
	const fileSize, blockSize = uint64(16), uint64(4)
	a := NewAdapter(fileSize, blockSize)
	if a.IsComplete() {
		t.Fatal("IsComplete true before work")
	}
	a.Complete()
	if !a.IsComplete() {
		t.Fatal("IsComplete false after complete")
	}
}

func TestSwarmAdapterWholeFileCompletionTracking(t *testing.T) {
	const fileSize, blockSize = uint64(16), uint64(4)
	a := NewAdapter(fileSize, blockSize)
	if a.IsWholeFileVerified() {
		t.Fatal("verified before complete")
	}
	a.Complete()
	if !a.IsWholeFileVerified() {
		t.Fatal("not tracked verified")
	}
	if !a.IsPartVerified(0) {
		t.Fatal("part 0 not tracked")
	}
}

func TestSwarmAdapterConstructorAliases(t *testing.T) {
	a := NewSwarmAdapter(100, 40)
	if a == nil || a.Swarm == nil {
		t.Fatal("alias constructor failed")
	}
	b := NewGnutellaAdapter(a.Swarm, a.Scheduler)
	if b == nil {
		t.Fatal("nil")
	}
	c := NewG2Adapter(a.Swarm, a.Scheduler)
	if c == nil {
		t.Fatal("nil")
	}
	_ = swarm.New
}

func TestSwarmAdapterDefaultNetwork(t *testing.T) {
	a := NewAdapter(uint64(100))
	if a.Network != "gnutella" {
		t.Fatalf("default network = %s", a.Network)
	}
	g := NewAdapter(uint64(100), "g2")
	if g.Network != "g2" {
		t.Fatalf("network = %s", g.Network)
	}
}
