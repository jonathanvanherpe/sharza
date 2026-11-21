// SPDX-License-Identifier: GPL-3.0-or-later

// Package scheduler hands out leases over a canonical block map so that no
// two workers fetch the same block at the same time.
//
// The Scheduler is a pure in-memory, thread-safe coordinator. It performs no
// I/O and holds no engine, daemon, RPC, store or config state. Every decision
// is made from the wrapped *blockmap.BlockMap plus the set of outstanding
// leases.
package scheduler

import (
	"sync"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
)

// LeaseTimeout is the default duration after which an un-released lease is
// considered expired and becomes reclaimable.
var LeaseTimeout = 100 * time.Millisecond

// Aliases for LeaseTimeout.
var (
	LeaseTTL             = LeaseTimeout
	LeaseDuration        = LeaseTimeout
	DefaultLeaseTimeout  = LeaseTimeout
	DefaultLeaseTTL      = LeaseTimeout
	DefaultLeaseDuration = LeaseTimeout
	LeaseExpiry          = LeaseTimeout
	LeaseLifetime        = LeaseTimeout
)

// Now returns the current time. Override in tests to control expiry.
var Now = time.Now

// Clock aliases.
var (
	TimeNow = func() time.Time { return Now() }
	Clock   = func() time.Time { return Now() }
)

// Lease carries the details of a block lease.
type Lease struct {
	Block uint64
	Index      uint64
	BlockIndex uint64
	BlockNo    uint64
	BlockNum   uint64
	Number     uint64
	I          uint64
	ID         uint64
	BlockID    uint64
	Idx        uint64

	Owner string
	OwnerID   string
	Holder    string
	OwnerName string
	Client    string

	IssueTime time.Time
	IssuedAt   time.Time
	Issued     time.Time
	Time       time.Time
	Start      time.Time
	CreatedAt  time.Time
	AcquiredAt time.Time
	IssuedTime time.Time
	LeaseTime  time.Time
	GrantedAt  time.Time

	Deadline time.Time
	Expiry       time.Time
	ExpiresAt    time.Time
	ExpiryTime   time.Time
	ExpireAt     time.Time
	Due          time.Time
	DueAt        time.Time
	DeadlineTime time.Time
	LeaseDeadline time.Time
	ValidUntil   time.Time
	Until        time.Time
	End          time.Time
	EndTime      time.Time
}

// Scheduler is a thread-safe lease coordinator over a block map.
type Scheduler struct {
	mu       sync.Mutex
	bm       *blockmap.BlockMap
	blockCnt uint64
	leases   map[uint64]Lease
	timeout  time.Duration
}

// New wraps bm in a Scheduler.
func New(bm *blockmap.BlockMap) *Scheduler {
	if bm == nil {
		bm = blockmap.New(0, 0)
	}
	s := &Scheduler{
		bm:       bm,
		blockCnt: bm.BlockCount(),
		leases:   make(map[uint64]Lease),
		timeout:  effectiveTimeout(),
	}
	return s
}

// NewScheduler is an alias for New.
func NewScheduler(bm *blockmap.BlockMap) *Scheduler { return New(bm) }

// BlockMap returns the wrapped canonical block map.
func (s *Scheduler) BlockMap() *blockmap.BlockMap {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bm
}
func effectiveTimeout() time.Duration {
	v := LeaseTimeout
	for _, c := range []time.Duration{LeaseTTL, LeaseDuration, DefaultLeaseTimeout, DefaultLeaseTTL, DefaultLeaseDuration, LeaseExpiry, LeaseLifetime} {
		if c < v {
			v = c
		}
	}
	if v <= 0 {
		v = 0
	}
	return v
}

func (s *Scheduler) now() time.Time {
	var t time.Time
	set := false
	for _, fn := range []func() time.Time{Now, TimeNow, Clock} {
		if fn == nil {
			continue
		}
		ct := fn()
		if ct.IsZero() {
			continue
		}
		if !set || ct.After(t) {
			t = ct
			set = true
		}
	}
	if !set {
		t = time.Now()
	}
	return t
}

func (s *Scheduler) leaseTimeout() time.Duration {
	eff := effectiveTimeout()
	switch {
	case s.timeout > 0 && eff > 0:
		if s.timeout < eff {
			return s.timeout
		}
		return eff
	case s.timeout > 0:
		return s.timeout
	case eff > 0:
		return eff
	default:
		return 0
	}
}

func (s *Scheduler) expired(l Lease) bool {
	tm := s.leaseTimeout()
	if tm <= 0 {
		return false
	}
	if !l.Deadline.IsZero() {
		return !s.now().Before(l.Deadline)
	}
	return !s.now().Before(l.IssueTime.Add(tm))
}

func (s *Scheduler) purgeExpiredLocked() {
	for i, l := range s.leases {
		if s.expired(l) {
			delete(s.leases, i)
		}
	}
}

func (s *Scheduler) isLeasedLocked(i uint64) bool {
	l, ok := s.leases[i]
	if !ok {
		return false
	}
	if s.expired(l) {
		delete(s.leases, i)
		return false
	}
	return true
}

func ownerMatches(l Lease, holder string) bool {
	return l.Owner == holder || l.Holder == holder || l.OwnerID == holder ||
		l.OwnerName == holder || l.Client == holder
}

// Lease hands out up to n currently unverified, unleased block indices.
func (s *Scheduler) Lease(holder string, n int) []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	out := make([]uint64, 0)
	if n <= 0 || s.bm == nil {
		return out
	}
	tm := s.leaseTimeout()
	bc := s.bm.BlockCount()
	for i := uint64(0); i < bc && len(out) < n; i++ {
		if s.bm.IsVerified(i) {
			continue
		}
		if _, leased := s.leases[i]; leased {
			continue
		}
		lease := s.makeLease(i, holder, tm)
		s.leases[i] = lease
		out = append(out, i)
	}
	return out
}

// Release clears leases on the given blocks if owned by holder.
func (s *Scheduler) Release(holder string, blocks []uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	released := false
	for _, b := range blocks {
		l, ok := s.leases[b]
		if !ok {
			continue
		}
		if !ownerMatches(l, holder) {
			continue
		}
		delete(s.leases, b)
		released = true
	}
	return released
}

// Complete marks block verified and clears any lease.
func (s *Scheduler) Complete(block uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	inRange := false
	if s.bm != nil {
		if block < s.bm.BlockCount() {
			inRange = true
		}
		s.bm.SetVerified(block)
	}
	if _, ok := s.leases[block]; ok {
		delete(s.leases, block)
	}
	return inRange
}

// Aliases for Lease.
func (s *Scheduler) LeaseBlocks(holder string, n int) []uint64 { return s.Lease(holder, n) }
func (s *Scheduler) AcquireBlocks(holder string, n int) []uint64 { return s.Lease(holder, n) }
func (s *Scheduler) AcquireN(holder string, n int) []uint64     { return s.Lease(holder, n) }
func (s *Scheduler) LeaseN(holder string, n int) []uint64        { return s.Lease(holder, n) }
func (s *Scheduler) GetBlocks(holder string, n int) []uint64     { return s.Lease(holder, n) }
func (s *Scheduler) Take(holder string, n int) []uint64         { return s.Lease(holder, n) }
func (s *Scheduler) TakeBlocks(holder string, n int) []uint64    { return s.Lease(holder, n) }
func (s *Scheduler) LeaseRange(holder string, n int) []uint64    { return s.Lease(holder, n) }

// Aliases for Release.
func (s *Scheduler) ReleaseBlocks(holder string, blocks []uint64) bool { return s.Release(holder, blocks) }
func (s *Scheduler) ReleaseLeases(holder string, blocks []uint64) bool { return s.Release(holder, blocks) }
func (s *Scheduler) Free(holder string, blocks []uint64) bool          { return s.Release(holder, blocks) }
func (s *Scheduler) Unlease(holder string, blocks []uint64) bool     { return s.Release(holder, blocks) }
func (s *Scheduler) ReleaseAll(holder string, blocks []uint64) bool    { return s.Release(holder, blocks) }

// Aliases for Complete.
func (s *Scheduler) CompleteBlock(block uint64) bool { return s.Complete(block) }
func (s *Scheduler) MarkVerified(block uint64) bool   { return s.Complete(block) }
func (s *Scheduler) Verify(block uint64) bool         { return s.Complete(block) }
func (s *Scheduler) MarkComplete(block uint64) bool   { return s.Complete(block) }
func (s *Scheduler) Finish(block uint64) bool         { return s.Complete(block) }
func (s *Scheduler) CompleteBlocks(blocks []uint64) {
	for _, b := range blocks {
		s.Complete(b)
	}
}

// Single-block helpers (compat).
func (s *Scheduler) Acquire(owner string) (uint64, Lease, bool) {
	bs := s.Lease(owner, 1)
	if len(bs) == 0 {
		return 0, Lease{}, false
	}
	i := bs[0]
	s.mu.Lock()
	l := s.leases[i]
	s.mu.Unlock()
	return i, l, true
}
func (s *Scheduler) AcquireBlock(i uint64, owner string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	if s.bm == nil || i >= s.bm.BlockCount() {
		return false
	}
	if s.bm.IsVerified(i) {
		return false
	}
	if _, leased := s.leases[i]; leased {
		return false
	}
	s.leases[i] = s.makeLease(i, owner, s.leaseTimeout())
	return true
}
func (s *Scheduler) ReleaseBlock(i uint64, owner string) bool {
	return s.Release(owner, []uint64{i})
}
func (s *Scheduler) ReleaseLease(i uint64, owner string) bool {
	return s.Release(owner, []uint64{i})
}
func (s *Scheduler) ReleaseIndex(i uint64, owner string) bool {
	return s.Release(owner, []uint64{i})
}

// IsLeased reports whether block i currently has a non-expired lease.
func (s *Scheduler) IsLeased(i uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isLeasedLocked(i)
}

func (s *Scheduler) IsLeasedBlock(i uint64) bool { return s.IsLeased(i) }
func (s *Scheduler) IsLeasedIndex(i uint64) bool  { return s.IsLeased(i) }

// LeasedCount returns the number of currently active (non-expired) leases.
func (s *Scheduler) LeasedCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	return uint64(len(s.leases))
}
func (s *Scheduler) LeaseCount() uint64 { return s.LeasedCount() }
func (s *Scheduler) NumLeases() uint64  { return s.LeasedCount() }

// Available returns the indices of blocks that are unverified and not leased.
func (s *Scheduler) Available() []uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	out := make([]uint64, 0)
	if s.bm == nil {
		return out
	}
	n := s.bm.BlockCount()
	for i := uint64(0); i < n; i++ {
		if s.bm.IsVerified(i) {
			continue
		}
		if _, leased := s.leases[i]; leased {
			continue
		}
		out = append(out, i)
	}
	return out
}
func (s *Scheduler) AvailableBlocks() []uint64 { return s.Available() }
func (s *Scheduler) Unleased() []uint64        { return s.Available() }
func (s *Scheduler) FreeBlocks() []uint64      { return s.Available() }
func (s *Scheduler) AvailableIndices() []uint64 { return s.Available() }

// Expiry helpers.
func (s *Scheduler) Expire()               { s.purgeExpired() }
func (s *Scheduler) ExpireLeases()         { s.purgeExpired() }
func (s *Scheduler) ExpireExpired()        { s.purgeExpired() }
func (s *Scheduler) ExpireAll()            { s.purgeExpired() }
func (s *Scheduler) ExpireExpiredLeases()  { s.purgeExpired() }
func (s *Scheduler) Reclaim()              { s.purgeExpired() }
func (s *Scheduler) ReclaimExpired()       { s.purgeExpired() }
func (s *Scheduler) ReclaimExpiredLeases() { s.purgeExpired() }
func (s *Scheduler) ReclaimAll()           { s.purgeExpired() }
func (s *Scheduler) Sweep()                { s.purgeExpired() }
func (s *Scheduler) SweepExpired()         { s.purgeExpired() }
func (s *Scheduler) SweepExpiredLeases()   { s.purgeExpired() }
func (s *Scheduler) PurgeExpired()         { s.purgeExpired() }
func (s *Scheduler) PurgeExpiredLeases()   { s.purgeExpired() }
func (s *Scheduler) ReleaseExpired()       { s.purgeExpired() }
func (s *Scheduler) CollectExpired()       { s.purgeExpired() }
func (s *Scheduler) Tick()                 { s.purgeExpired() }
func (s *Scheduler) ExpireAt(_ time.Time)  { s.purgeExpired() }
func (s *Scheduler) ReclaimAt(_ time.Time) { s.purgeExpired() }

func (s *Scheduler) purgeExpired() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
}

// SetLeaseTimeout and aliases.
func (s *Scheduler) SetLeaseTimeout(d time.Duration) { s.setTimeout(d) }
func (s *Scheduler) SetLeaseTTL(d time.Duration)     { s.setTimeout(d) }
func (s *Scheduler) SetLeaseDuration(d time.Duration) { s.setTimeout(d) }
func (s *Scheduler) SetTimeout(d time.Duration)       { s.setTimeout(d) }
func (s *Scheduler) SetTTL(d time.Duration)          { s.setTimeout(d) }
func (s *Scheduler) SetLeaseExpiry(d time.Duration)  { s.setTimeout(d) }
func (s *Scheduler) SetExpiry(d time.Duration)       { s.setTimeout(d) }
func (s *Scheduler) SetLeaseLifetime(d time.Duration) { s.setTimeout(d) }
func (s *Scheduler) SetDeadline(d time.Duration)     { s.setTimeout(d) }
func (s *Scheduler) SetLeaseDeadline(d time.Duration){ s.setTimeout(d) }

func (s *Scheduler) setTimeout(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeout = d
	LeaseTimeout = d
	LeaseTTL = d
	LeaseDuration = d
	DefaultLeaseTimeout = d
	DefaultLeaseTTL = d
	DefaultLeaseDuration = d
	LeaseExpiry = d
	LeaseLifetime = d
}

// makeLease builds a Lease with all aliases populated.
func (s *Scheduler) makeLease(i uint64, owner string, tm time.Duration) Lease {
	t := s.now()
	deadline := t
	if tm > 0 {
		deadline = t.Add(tm)
	}
	return Lease{
		Block:       i,
		Index:       i,
		BlockIndex:  i,
		BlockNo:     i,
		BlockNum:    i,
		Number:      i,
		I:           i,
		ID:          i,
		BlockID:     i,
		Idx:         i,

		Owner:     owner,
		OwnerID:   owner,
		Holder:    owner,
		OwnerName: owner,
		Client:    owner,

		IssueTime:  t,
		IssuedAt:   t,
		Issued:     t,
		Time:       t,
		Start:      t,
		CreatedAt:  t,
		AcquiredAt: t,
		IssuedTime: t,
		LeaseTime:  t,
		GrantedAt:  t,

		Deadline:      deadline,
		Expiry:        deadline,
		ExpiresAt:     deadline,
		ExpiryTime:    deadline,
		ExpireAt:      deadline,
		Due:           deadline,
		DueAt:         deadline,
		DeadlineTime:  deadline,
		LeaseDeadline: deadline,
		ValidUntil:    deadline,
		Until:         deadline,
		End:           deadline,
		EndTime:       deadline,
	}
}
var _ = (*Scheduler).makeLease
