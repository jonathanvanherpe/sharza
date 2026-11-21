// SPDX-License-Identifier: GPL-3.0-or-later

package scheduler

import (
	"sync"
	"testing"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
)

const twoMiB = 2 << 20

func newSched(blocks uint64) *Scheduler {
	bm := blockmap.New(blocks*blockmap.DefaultBlockSize, 0)
	return New(bm)
}

func TestAcquireBasic(t *testing.T) {
	s := newSched(3)
	idx, lease, ok := s.Acquire("a")
	if !ok {
		t.Fatal("Acquire failed")
	}
	if lease.Block != idx || lease.Owner != "a" {
		t.Fatalf("lease mismatch: %+v idx=%d", lease, idx)
	}
	if s.IsLeased(idx) == false {
		t.Fatal("not leased")
	}
	if s.LeasedCount() != 1 {
		t.Fatalf("leased count = %d", s.LeasedCount())
	}
	// same block not handed again
	idx2, _, ok2 := s.Acquire("b")
	if !ok2 {
		t.Fatal("second acquire failed")
	}
	if idx2 == idx {
		t.Fatal("duplicate block handed out")
	}
}

func TestReleaseReavailable(t *testing.T) {
	s := newSched(1)
	idx, _, ok := s.Acquire("a")
	if !ok {
		t.Fatal("acquire failed")
	}
	if !s.Release(idx, "a") {
		t.Fatal("release failed")
	}
	if s.IsLeased(idx) {
		t.Fatal("still leased after release")
	}
	if s.LeasedCount() != 0 {
		t.Fatalf("leased count = %d", s.LeasedCount())
	}
	// available again
	av := s.Available()
	if len(av) != 1 || av[0] != idx {
		t.Fatalf("available = %v", av)
	}
	// reacquire
	idx2, _, ok2 := s.Acquire("b")
	if !ok2 || idx2 != idx {
		t.Fatalf("reacquire got %d %v, want %d", idx2, ok2, idx)
	}
}

func TestReleaseWrongOwner(t *testing.T) {
	s := newSched(1)
	idx, _, _ := s.Acquire("a")
	if s.Release(idx, "b") {
		t.Fatal("release by wrong owner succeeded")
	}
	if !s.IsLeased(idx) {
		t.Fatal("lease dropped by wrong owner")
	}
}

func TestAcquireBlock(t *testing.T) {
	s := newSched(2)
	if !s.AcquireBlock(1, "a") {
		t.Fatal("AcquireBlock failed")
	}
	if s.AcquireBlock(1, "b") {
		t.Fatal("double AcquireBlock succeeded")
	}
	// verified block cannot be leased
	bm := s.bm
	bm.SetVerified(0)
	if s.AcquireBlock(0, "c") {
		t.Fatal("leased verified block")
	}
}

func TestExpiredReclaimable(t *testing.T) {
	// shorten timeout
	s := newSched(1)
	s.SetLeaseTimeout(10 * time.Millisecond)
	defer s.SetLeaseTimeout(100 * time.Millisecond)
	idx, _, ok := s.Acquire("a")
	if !ok {
		t.Fatal("acquire failed")
	}
	time.Sleep(50 * time.Millisecond)
	// expired, should be reclaimable
	if s.IsLeased(idx) {
		t.Fatal("expired lease still reported leased")
	}
	idx2, _, ok2 := s.Acquire("b")
	if !ok2 || idx2 != idx {
		t.Fatalf("reclaim got %d %v, want %d", idx2, ok2, idx)
	}
}

func TestAvailableExcludesLeased(t *testing.T) {
	s := newSched(3)
	s.Acquire("a")
	av := s.Available()
	if len(av) != 2 {
		t.Fatalf("available len = %d, want 2", len(av))
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
		go func(n int) {
			defer wg.Done()
			idx, _, ok := s.Acquire("o")
			if !ok {
				return
			}
			mu.Lock()
			if seen[idx] {
				dups++
			}
			seen[idx] = true
			mu.Unlock()
		}(i)
	}
	wg.Wait()
	if dups != 0 {
		t.Fatalf("duplicate acquisitions: %d", dups)
	}
}

func FuzzScheduler(f *testing.F) {
	f.Add(uint8(0), uint64(0), "a")
	f.Add(uint8(1), uint64(1), "b")
	f.Fuzz(func(t *testing.T, op uint8, idx uint64, owner string) {
		s := newSched(4)
		switch op % 5 {
		case 0:
			s.Acquire(owner)
		case 1:
			s.AcquireBlock(idx%4, owner)
		case 2:
			s.Release(idx%4, owner)
		case 3:
			s.IsLeased(idx % 4)
		case 4:
			s.Available()
		}
		_ = s.LeasedCount()
	})
}
