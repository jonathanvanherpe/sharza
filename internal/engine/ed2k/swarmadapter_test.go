// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/swarm"
)

func TestSwarmAdapterLeaseMapsToParts(t *testing.T) {
	const fileSize = 100
	const partSize = 30
	const blockSize = 40
	a := NewAdapter(fileSize, partSize, blockSize, "ed2k")
	if a == nil {
		t.Fatal("nil adapter")
	}
	leased := a.Lease("ed2k", 1)
	want := []uint64{0, 1}
	if len(leased) != len(want) {
		t.Fatalf("leased parts = %v, want %v", leased, want)
	}
	for i := range want {
		if leased[i] != want[i] {
			t.Fatalf("leased[%d] = %d, want %d (%v)", i, leased[i], want[i], leased)
		}
	}

	if !a.Complete("ed2k", 0) {
		t.Fatalf("Complete returned false")
	}
	if !a.IsPartVerified(0) {
		t.Fatalf("part 0 not marked verified")
	}
	sw := a.Swarm
	if sw == nil {
		t.Fatal("nil swarm")
	}
	if !sw.IsVerified(0) {
		t.Fatalf("canonical block 0 not verified after completing part 0")
	}
	if a.IsComplete("ed2k") {
		t.Fatalf("IsComplete = true, want false")
	}
}

func TestSwarmAdapterCompletedPartMarksBlocks(t *testing.T) {
	const fileSize, partSize, blockSize = uint64(16), uint64(8), uint64(4)
	a := NewAdapter(fileSize, partSize, blockSize)

	if !a.Complete("ed2k", 1) {
		t.Fatal("Complete returned false")
	}
	if !a.Swarm.IsVerified(2) || !a.Swarm.IsVerified(3) {
		t.Fatalf("blocks 2/3 not verified: %v %v", a.Swarm.IsVerified(2), a.Swarm.IsVerified(3))
	}
	if a.Swarm.IsVerified(0) || a.Swarm.IsVerified(1) {
		t.Fatal("blocks 0/1 unexpectedly verified")
	}
}

func TestSwarmAdapterIsComplete(t *testing.T) {
	const fileSize, partSize, blockSize = uint64(16), uint64(8), uint64(4)
	a := NewAdapter(fileSize, partSize, blockSize)
	if a.IsComplete() {
		t.Fatal("IsComplete true before work")
	}
	a.Complete("ed2k", 0)
	if a.IsComplete() {
		t.Fatal("IsComplete true after partial")
	}
	a.Complete("ed2k", 1)
	if !a.IsComplete() {
		t.Fatal("IsComplete false after all parts")
	}
}

func TestSwarmAdapterVerifiedPartTracking(t *testing.T) {
	const fileSize, partSize, blockSize = uint64(16), uint64(8), uint64(4)
	a := NewAdapter(fileSize, partSize, blockSize)
	if a.IsPartVerified(0) {
		t.Fatal("part 0 verified before complete")
	}
	a.Complete("ed2k", 0)
	if !a.IsPartVerified(0) {
		t.Fatal("part 0 not tracked verified")
	}
	if a.IsPartVerified(1) {
		t.Fatal("part 1 tracked verified early")
	}
	vp := a.VerifiedParts()
	if len(vp) != 1 || vp[0] != 0 {
		t.Fatalf("VerifiedParts = %v", vp)
	}
}

func TestSwarmAdapterDefaultPartSize(t *testing.T) {
	a := NewAdapter(uint64(100))
	if a.PartSize() != DefaultPartSize {
		t.Fatalf("default part size = %d, want %d", a.PartSize(), DefaultPartSize)
	}
}

func TestSwarmAdapterAliases(t *testing.T) {
	a := NewSwarmAdapter(100, 30, 40)
	if a == nil || a.RangeMap == nil {
		t.Fatal("alias constructor failed")
	}
	b := NewED2KAdapter(a.RangeMap, a.Swarm, a.Scheduler)
	if b == nil {
		t.Fatal("nil")
	}
	_ = swarm.New
}

func TestSwarmAdapterConstructorAliases(t *testing.T) {
	a := NewAdapter(100, 30, 40)
	if a == nil || a.RangeMap == nil {
		t.Fatal("nil")
	}
	b := NewSwarmAdapter(a.RangeMap, a.Swarm, a.Scheduler)
	if b == nil {
		t.Fatal("nil")
	}
}