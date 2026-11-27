// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/swarm"
)

func TestSwarmAdapterLeaseMapsToPieces(t *testing.T) {
	const fileSize = 100
	const pieceSize = 30
	const blockSize = 40
	a := NewAdapter(fileSize, pieceSize, blockSize, "bt")
	if a == nil {
		t.Fatal("nil adapter")
	}
	leased := a.Lease("bt", 1)
	want := []uint64{0, 1}
	if len(leased) != len(want) {
		t.Fatalf("leased pieces = %v, want %v", leased, want)
	}
	for i := range want {
		if leased[i] != want[i] {
			t.Fatalf("leased[%d] = %d, want %d (%v)", i, leased[i], want[i], leased)
		}
	}

	if !a.Complete("bt", 0) {
		t.Fatalf("Complete returned false")
	}
	if !a.IsPieceVerified(0) {
		t.Fatalf("piece 0 not marked verified")
	}
	sw := a.Swarm
	if sw == nil {
		t.Fatal("nil swarm")
	}
	if !sw.IsVerified(0) {
		t.Fatalf("canonical block 0 not verified after completing piece 0")
	}
	if a.IsComplete("bt") {
		t.Fatalf("IsComplete = true, want false")
	}
}

func TestSwarmAdapterConstructorAliases(t *testing.T) {
	a := NewSwarmAdapter(100, 30, 40)
	if a == nil || a.RangeMap == nil {
		t.Fatal("alias constructor failed")
	}
	b := NewBTAdapter(a.RangeMap, a.Swarm, a.Scheduler)
	if b == nil {
		t.Fatal("nil")
	}
	_ = swarm.New
}
