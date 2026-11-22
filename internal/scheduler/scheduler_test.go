// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"sync"
	"testing"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
)

func newSched(blocks uint64) *Scheduler {
	bm := blockmap.New(blocks*blockmap.DefaultBlockSize, 0)
	return New(bm)
}

func TestLeaseBasic(t *testing.T) {
	s := newSched(3)
	bs := s.Lease("a", 2)
	if len(bs) != 2 {
		t.Fatalf("lease len = %d, want 2", len(bs))
	}
	for _, b := range bs {
		if !s.IsLeased(b) {
			t.Fatalf("block %d not leased", b)
		}
	}
	if s.LeasedCount() != 2 {
		t.Fatalf("leased count = %d", s.LeasedCount())
	}
	bs2 := s.Lease("b", 5)
	if len(bs2) != 1 {
		t.Fatalf("second lease len = %d, want 1", len(bs2))
	}
	if bs2[0] == bs[0] || bs2[0] == bs[1] {
		t.Fatal("duplicate block handed out")
	}
}

func TestLeaseNoneAvailable(t *testing.T) {
	s := newSched(1)
	s.Lease("a", 1)
	bs := s.Lease("b", 1)
	if len(bs) != 0 {
		t.Fatalf("expected no blocks, got %v", bs)
	}
}

func TestLeaseVerifiedExcluded(t *testing.T) {
	s := newSched(3)
	s.bm.SetVerified(1)
	bs := s.Lease("a", 5)
	for _, b := range bs {
		if b == 1 {
			t.Fatal("verified block leased")
		}
	}
	if len(bs) != 2 {
		t.Fatalf("len = %d, want 2", len(bs))
	}
}

func TestNoDuplicateConcurrent(t *testing.T) {
	s := newSched(4)
	var wg sync.WaitGroup
	seen := make(map[uint64]bool)
	var mu sync.Mutex
	dups := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			bs := s.Lease("o", 1)
			if len(bs) == 0 {
				return
			}
			idx := bs[0]
			mu.Lock()
			if seen[idx] {
				dups++
			}
			seen[idx] = true
			mu.Unlock()
		}()
	}
	wg.Wait()
	if dups != 0 {
		t.Fatalf("duplicate leases: %d", dups)
	}
}

func TestExpiredReclaimable(t *testing.T) {
	s := newSched(1)
	s.SetLeaseTimeout(10 * time.Millisecond)
	defer s.SetLeaseTimeout(100 * time.Millisecond)
	bs := s.Lease("a", 1)
	if len(bs) != 1 {
		t.Fatal("lease failed")
	}
	idx := bs[0]
	time.Sleep(50 * time.Millisecond)
	if s.IsLeased(idx) {
		t.Fatal("expired lease still reported leased")
	}
	bs2 := s.Lease("b", 1)
	if len(bs2) != 1 || bs2[0] != idx {
		t.Fatalf("reclaim got %v, want [%d]", bs2, idx)
	}
}

func TestReleaseSemantics(t *testing.T) {
	s := newSched(1)
	bs := s.Lease("a", 1)
	if len(bs) != 1 {
		t.Fatal("lease failed")
	}
	idx := bs[0]
	if !s.Release("a", []uint64{idx}) {
		t.Fatal("release failed")
	}
	if s.IsLeased(idx) {
		t.Fatal("still leased after release")
	}
	if s.LeasedCount() != 0 {
		t.Fatalf("leased count = %d", s.LeasedCount())
	}
	av := s.Available()
	if len(av) != 1 || av[0] != idx {
		t.Fatalf("available = %v", av)
	}
	bs2 := s.Lease("b", 1)
	if len(bs2) != 1 || bs2[0] != idx {
		t.Fatalf("re-lease got %v", bs2)
	}
}

func TestReleaseWrongOwner(t *testing.T) {
	s := newSched(1)
	bs := s.Lease("a", 1)
	idx := bs[0]
	if s.Release("b", []uint64{idx}) {
		t.Fatal("release by wrong owner succeeded")
	}
	if !s.IsLeased(idx) {
		t.Fatal("lease dropped by wrong owner")
	}
}

func TestCompleteSemantics(t *testing.T) {
	s := newSched(2)
	bs := s.Lease("a", 1)
	idx := bs[0]
	s.Complete(idx)
	if !s.bm.IsVerified(idx) {
		t.Fatal("block not verified after Complete")
	}
	if s.IsLeased(idx) {
		t.Fatal("lease not cleared after Complete")
	}
	bs2 := s.Lease("b", 5)
	for _, b := range bs2 {
		if b == idx {
			t.Fatal("completed block re-leased")
		}
	}
}

func TestCompleteClearsLease(t *testing.T) {
	s := newSched(1)
	bs := s.Lease("a", 1)
	idx := bs[0]
	s.Complete(idx)
	if s.LeasedCount() != 0 {
		t.Fatalf("leased count = %d", s.LeasedCount())
	}
}

func TestAvailableExcludesLeased(t *testing.T) {
	s := newSched(3)
	s.Lease("a", 1)
	av := s.Available()
	if len(av) != 2 {
		t.Fatalf("available len = %d, want 2", len(av))
	}
}

func TestReleasePartialOwnership(t *testing.T) {
	s := newSched(2)
	b0 := s.Lease("a", 1)
	b1 := s.Lease("b", 1)
	if !s.Release("a", []uint64{b0[0], b1[0]}) {
		t.Fatal("release failed")
	}
	if !s.IsLeased(b1[0]) {
		t.Fatal("b's lease wrongly cleared")
	}
}

func FuzzScheduler(f *testing.F) {
	f.Add(uint8(0), uint64(0))
	f.Add(uint8(1), uint64(1))
	f.Fuzz(func(t *testing.T, op uint8, idx uint64) {
		s := newSched(4)
		switch op % 6 {
		case 0:
			s.Lease("o", 1)
		case 1:
			s.AcquireBlock(idx%4, "o")
		case 2:
			s.Release("o", []uint64{idx % 4})
		case 3:
			s.IsLeased(idx % 4)
		case 4:
			s.Available()
		case 5:
			s.Complete(idx % 4)
		}
		_ = s.LeasedCount()
	})
}
