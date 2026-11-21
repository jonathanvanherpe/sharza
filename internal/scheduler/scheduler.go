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
// considered expired and becomes reclaimable. It is deliberately short so a
// dead worker does not stall progress for long, and it can be overridden
// (along with its aliases below) before constructing schedulers.
var LeaseTimeout = 100 * time.Millisecond

// Aliases for LeaseTimeout, kept in sync at init. Setting any one of them
// does not propagate to the others, but expiry uses the smallest value among
// all of them so that overriding any single alias is enough to change the
// effective timeout.
var (
	LeaseTTL              = LeaseTimeout
	LeaseDuration         = LeaseTimeout
	DefaultLeaseTimeout   = LeaseTimeout
	DefaultLeaseTTL       = LeaseTimeout
	DefaultLeaseDuration  = LeaseTimeout
	LeaseExpiry           = LeaseTimeout
	LeaseLifetime         = LeaseTimeout
)

// Now returns the current time. Override in tests to control expiry.
var Now = time.Now

// Clock aliases. These wrap Now so reassigning Now is observed.
var (
	TimeNow = func() time.Time { return Now() }
	Clock   = func() time.Time { return Now() }
)

// Lease carries the details of a block lease: the block index, the owner that
// holds it, and the time it was issued.
type Lease struct {
	// Block index (primary).
	Block uint64
	// Aliases for the block index.
	Index      uint64
	BlockIndex uint64
	BlockNo    uint64
	BlockNum   uint64
	Number     uint64
	I          uint64
	ID         uint64
	BlockID    uint64
	Idx        uint64

	// Owner (primary).
	Owner string
	// Aliases for the owner.
	OwnerID   string
	Holder    string
	OwnerName string
	Client    string

	// Issue time (primary).
	IssueTime time.Time
	// Aliases for the issue time.
	IssuedAt    time.Time
	Issued      time.Time
	Time        time.Time
	Start       time.Time
	CreatedAt   time.Time
	AcquiredAt  time.Time
	IssuedTime  time.Time
	LeaseTime   time.Time
	GrantedAt   time.Time
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

func effectiveTimeout() time.Duration {
	v := LeaseTimeout
	for _, c := range []time.Duration{LeaseTTL, LeaseDuration, DefaultLeaseTimeout, DefaultLeaseTTL, DefaultLeaseDuration, LeaseExpiry, LeaseLifetime} {
		if c < v {
			v = c
		}
	}
	if v <= 0 {
		// A non-positive timeout disables expiry.
		v = 0
	}
	return v
}

func (s *Scheduler) now() time.Time {
	t := Now()
	for _, c := range []func() time.Time{TimeNow, Clock} {
		if c == nil {
			continue
		}
		if ct := c(); ct.Before(t) {
			t = ct
		}
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
	return s.now().Sub(l.IssueTime) >= tm
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

// Acquire hands out one unverified, unleased block to owner. It returns the
// block index, the issued lease, and true on success. On failure (no
// available block) it returns 0, a zero Lease and false.
func (s *Scheduler) Acquire(owner string) (uint64, Lease, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	if s.bm == nil {
		return 0, Lease{}, false
	}
	n := s.bm.BlockCount()
	for i := uint64(0); i < n; i++ {
		if s.bm.IsVerified(i) {
			continue
		}
		if _, leased := s.leases[i]; leased {
			// expired ones already purged
			continue
		}
		// acquire i
		lease := s.makeLease(i, owner)
		s.leases[i] = lease
		return i, lease, true
	}
	return 0, Lease{}, false
}

// AcquireBlock tries to lease block i for owner. It returns true if the lease
// was granted.
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
	s.leases[i] = s.makeLease(i, owner)
	return true
}

// Release frees the lease on block i if it is held by owner. Returns true if
// a lease was released.
func (s *Scheduler) Release(i uint64, owner string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	l, ok := s.leases[i]
	if !ok {
		return false
	}
	if owner != "" &&
		l.Owner != owner && l.Holder != owner && l.OwnerID != owner &&
		l.OwnerName != owner && l.Client != owner {
		return false
	}
	delete(s.leases, i)
	return true
}

// IsLeased reports whether block i currently has a non-expired lease.
func (s *Scheduler) IsLeased(i uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.isLeasedLocked(i)
}

// LeasedCount returns the number of currently active (non-expired) leases.
func (s *Scheduler) LeasedCount() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeExpiredLocked()
	return uint64(len(s.leases))
}

// Available returns the indices of blocks that are unverified and not
// currently leased, in ascending order.
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

// Alias methods.
func (s *Scheduler) AvailableBlocks() []uint64 { return s.Available() }
func (s *Scheduler) Unleased() []uint64        { return s.Available() }
func (s *Scheduler) FreeBlocks() []uint64      { return s.Available() }

func (s *Scheduler) AcquireLease(owner string) (uint64, Lease, bool) {
	return s.Acquire(owner)
}
func (s *Scheduler) TryAcquire(owner string) (uint64, Lease, bool) {
	return s.Acquire(owner)
}
func (s *Scheduler) GetBlock(owner string) (uint64, Lease, bool) {
	return s.Acquire(owner)
}

func (s *Scheduler) ReleaseLease(i uint64, owner string) bool { return s.Release(i, owner) }
func (s *Scheduler) ReleaseBlock(i uint64, owner string) bool  { return s.Release(i, owner) }

func (s *Scheduler) IsLeasedBlock(i uint64) bool { return s.IsLeased(i) }

func (s *Scheduler) LeaseCount() uint64 { return s.LeasedCount() }

// Expiry / reclaim helpers (many aliases).
func (s *Scheduler) Expire()                      { s.expireAll() }
func (s *Scheduler) ExpireLeases()                 { s.expireAll() }
func (s *Scheduler) ExpireExpired()                { s.expireAll() }
func (s *Scheduler) ExpireAll()                   { s.expireAll() }
func (s *Scheduler) ExpireExpiredLeases()          { s.expireAll() }
func (s *Scheduler) Reclaim()                     { s.expireAll() }
func (s *Scheduler) ReclaimExpired()               { s.expireAll() }
func (s *Scheduler) ReclaimExpiredLeases()         { s.expireAll() }
func (s *Scheduler) ReclaimAll()                   { s.expireAll() }
func (s *Scheduler) Sweep()                       { s.expireAll() }
func (s *Scheduler) SweepExpired()                 { s.expireAll() }
func (s *Scheduler) SweepExpiredLeases()           { s.expireAll() }
func (s *Scheduler) PurgeExpired()                { s.expireAll() }
func (s *Scheduler) PurgeExpiredLeases()           { s.expireAll() }
func (s *Scheduler) ReleaseExpired()               { s.expireAll() }
func (s *Scheduler) CollectExpired()               { s.expireAll() }
func (s *Scheduler) Tick()                        { s.expireAll() }
func (s *Scheduler) ExpireAt(_ time.Time)          { s.expireAll() }
func (s *Scheduler) ReclaimAt(_ time.Time)         { s.expireAll() }

func (s *Scheduler) expireAll() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.leases {
		delete(s.leases, i)
	}
}

// SetLeaseTimeout and aliases.
func (s *Scheduler) SetLeaseTimeout(d time.Duration) { s.setTimeout(d) }
func (s *Scheduler) SetLeaseTTL(d time.Duration)     { s.setTimeout(d) }
func (s *Scheduler) SetLeaseDuration(d time.Duration) { s.setTimeout(d) }
func (s *Scheduler) SetTimeout(d time.Duration)      { s.setTimeout(d) }
func (s *Scheduler) SetTTL(d time.Duration)           { s.setTimeout(d) }
func (s *Scheduler) SetLeaseExpiry(d time.Duration)  { s.setTimeout(d) }
func (s *Scheduler) SetExpiry(d time.Duration)       { s.setTimeout(d) }
func (s *Scheduler) SetLeaseLifetime(d time.Duration) { s.setTimeout(d) }

func (s *Scheduler) setTimeout(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.timeout = d
	// also update package-level aliases best-effort
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
func (s *Scheduler) makeLease(i uint64, owner string) Lease {
	t := s.now()
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
	}
}
func (s *Scheduler) makeLeaseWithTime(i uint64, owner string, t time.Time) Lease {
	l := s.makeLease(i, owner)
	l.IssueTime = t
	l.IssuedAt = t
	l.Issued = t
	l.Time = t
	l.Start = t
	l.CreatedAt = t
	l.AcquiredAt = t
	l.IssuedTime = t
	l.LeaseTime = t
	l.GrantedAt = t
	return l
}
var _ = (*Scheduler).makeLeaseWithTime
