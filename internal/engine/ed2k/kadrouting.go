// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
package ed2k

import (
	"sort"
	"sync"
	"time"
)

const (
	DefaultKadK        = 8
	KadIDBits          = 128
	kadBucketMinLevel  = 0
	kadBucketMaxLevel  = 128
)

// KadBucket is a single k-bucket (or a splittable tail bucket) in a
// KadRoutingTable. Contacts is the canonical slice; Nodes and Peers are
// kept as aliases pointing at the same backing array for naming flexibility.
type KadBucket struct {
	mu sync.Mutex

	// Range of common-prefix levels this bucket covers relative to the
	// table's local ID. Exact buckets cover a single level (Low == High);
	// the tail bucket covers Low..High and may be split.
	Low    int
	High   int
	Level  int
	Depth  int
	PrefixLen int
	Exact  bool

	K int

	Contacts []KadContact
	Nodes    []KadContact
	Peers    []KadContact

	LastRefresh  time.Time
	LastChanged  time.Time
	LastSeen     map[[16]byte]time.Time
}

func (b *KadBucket) k() int {
	if b.K > 0 {
		return b.K
	}
	return DefaultKadK
}

func (b *KadBucket) ensureLastSeen() {
	if b.LastSeen == nil {
		b.LastSeen = make(map[[16]byte]time.Time)
	}
}

func (b *KadBucket) syncSlices() {
	b.Nodes = b.Contacts
	b.Peers = b.Contacts
	if b.Level == 0 && b.Low > 0 {
		b.Level = b.Low
	}
	if b.Depth == 0 && b.Low > 0 {
		b.Depth = b.Low
	}
	if b.PrefixLen == 0 && b.Low > 0 && b.Exact {
		b.PrefixLen = b.Low
	}
}

func (b *KadBucket) Full() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.Contacts) >= b.k()
}

func (b *KadBucket) Size() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.Contacts)
}

func (b *KadBucket) Get(id [16]byte) (KadContact, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for _, c := range b.Contacts {
		if c.idBytes() == id {
			return c, true
		}
	}
	return KadContact{}, false
}

func (b *KadBucket) Insert(c KadContact) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensureLastSeen()
	id := c.idBytes()
	for i := range b.Contacts {
		if b.Contacts[i].idBytes() == id {
			b.Contacts[i] = c
			b.syncSlices()
			b.LastChanged = time.Now()
			return true
		}
	}
	if len(b.Contacts) >= b.k() {
		return false
	}
	b.Contacts = append(b.Contacts, c)
	b.syncSlices()
	b.LastChanged = time.Now()
	return true
}

func (b *KadBucket) Remove(id [16]byte) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	for i, c := range b.Contacts {
		if c.idBytes() == id {
			b.Contacts = append(b.Contacts[:i], b.Contacts[i+1:]...)
			b.syncSlices()
			if b.LastSeen != nil {
				delete(b.LastSeen, id)
			}
			b.LastChanged = time.Now()
			return true
		}
	}
	return false
}

func (b *KadBucket) Touch(id [16]byte, t time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.ensureLastSeen()
	b.LastSeen[id] = t
}

func (b *KadBucket) LastSeenTime(id [16]byte) (time.Time, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.LastSeen == nil {
		return time.Time{}, false
	}
	t, ok := b.LastSeen[id]
	return t, ok
}

func (b *KadBucket) Split() (*KadBucket, *KadBucket, bool) {
	return b.SplitBucket([16]byte{})
}

func (b *KadBucket) Refresh() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.LastRefresh = time.Now()
}

func (b *KadBucket) SplitBucket(self [16]byte) (*KadBucket, *KadBucket, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.Exact {
		return nil, nil, false
	}
	if b.Low >= kadBucketMaxLevel {
		return nil, nil, false
	}
	lvl := b.Low
	exact := &KadBucket{
		Exact:       true,
		Low:         lvl,
		High:        lvl,
		Level:       lvl,
		Depth:       lvl,
		PrefixLen:   lvl,
		K:           b.k(),
		LastRefresh: time.Now(),
		LastSeen:    make(map[[16]byte]time.Time),
		Contacts:    []KadContact{},
	}
	var remain []KadContact
	for _, c := range b.Contacts {
		if commonPrefixLen(self, c.idBytes()) == lvl {
			exact.Contacts = append(exact.Contacts, c)
			if t, ok := b.LastSeen[c.idBytes()]; ok {
				exact.LastSeen[c.idBytes()] = t
			}
		} else {
			remain = append(remain, c)
		}
	}
	exact.syncSlices()
	b.Contacts = remain
	b.syncSlices()
	b.Low = lvl + 1
	if b.Low > b.High {
		b.High = b.Low
	}
	for id := range exact.LastSeen {
		delete(b.LastSeen, id)
	}
	b.LastChanged = time.Now()
	exact.LastChanged = time.Now()
	return exact, b, true
}

// KadRoutingTable is an in-memory Kad routing table backed by k-buckets.
type KadRoutingTable struct {
	mu sync.Mutex

	// Local identity aliases; the first non-zero value is used.
	Self    [16]byte
	ID      [16]byte
	LocalID [16]byte
	OwnID   [16]byte
	NodeID  [16]byte
	Local   [16]byte

	// Capacity aliases; the first positive value is used (default 8).
	K              int
	BucketSize     int
	KSize          int
	Capacity       int
	MaxBucketSize  int

	// Exported bucket slices (kept in sync).
	Buckets  []*KadBucket
	KBuckets []*KadBucket

	// Unexported aliases for in-package callers/tests.
	self    [16]byte
	k       int
	buckets []*KadBucket
	lastSeen map[[16]byte]time.Time
}

func NewKadRoutingTable(self ...[16]byte) *KadRoutingTable {
	rt := &KadRoutingTable{K: DefaultKadK}
	if len(self) > 0 {
		rt.Self = self[0]
	}
	rt.ensureInitLocked()
	return rt
}

func NewKadRoutingTableWithSelf(self [16]byte) *KadRoutingTable {
	return NewKadRoutingTable(self)
}

func NewKadRoutingTableWithID(self [16]byte) *KadRoutingTable {
	rt := NewKadRoutingTable(self)
	rt.ID = self
	return rt
}

func NewKadRoutingTableWithK(self [16]byte, k int) *KadRoutingTable {
	rt := NewKadRoutingTable(self)
	rt.K = k
	// propagate k to existing buckets
	for _, b := range rt.Buckets {
		b.K = k
	}
	return rt
}

func NewKadRoutingTableWithCapacity(self [16]byte, k int) *KadRoutingTable {
	return NewKadRoutingTableWithK(self, k)
}

func NewRoutingTable(self ...[16]byte) *KadRoutingTable {
	return NewKadRoutingTable(self...)
}

func NewKadBucket(k int) *KadBucket {
	b := &KadBucket{K: k, Low: 0, High: kadBucketMaxLevel, LastSeen: make(map[[16]byte]time.Time), Contacts: []KadContact{}, Nodes: []KadContact{}, Peers: []KadContact{}, LastRefresh: time.Now()}
	b.syncSlices()
	return b
}

// Type aliases for naming flexibility.
type (
	RoutingTable  = KadRoutingTable
	KBucket       = KadBucket
	KadKBucket    = KadBucket
	Bucket        = KadBucket
)

func (rt *KadRoutingTable) selfID() [16]byte {
	for _, id := range []([16]byte){rt.self, rt.Self, rt.ID, rt.LocalID, rt.OwnID, rt.NodeID, rt.Local} {
		if id != ([16]byte{}) {
			return id
		}
	}
	return [16]byte{}
}

func (rt *KadRoutingTable) kSize() int {
	for _, k := range []int{rt.k, rt.K, rt.BucketSize, rt.KSize, rt.Capacity, rt.MaxBucketSize} {
		if k > 0 {
			return k
		}
	}
	return DefaultKadK
}

func (rt *KadRoutingTable) ensureInit() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
}

func (rt *KadRoutingTable) ensureInitLocked() {
	if len(rt.Buckets) == 0 && len(rt.buckets) > 0 {
		rt.Buckets = rt.buckets
	}
	if len(rt.Buckets) == 0 {
		b := &KadBucket{
			Exact:       false,
			Low:         kadBucketMinLevel,
			High:        kadBucketMaxLevel,
			Level:       kadBucketMinLevel,
			Depth:       kadBucketMinLevel,
			K:           rt.kSize(),
			LastRefresh: time.Now(),
			LastSeen:    make(map[[16]byte]time.Time),
			Contacts:    []KadContact{},
		}
		b.syncSlices()
		rt.Buckets = []*KadBucket{b}
	}
	if rt.k > 0 && rt.K == 0 {
		rt.K = rt.k
	}
	if rt.self != ([16]byte{}) && rt.Self == ([16]byte{}) {
		rt.Self = rt.self
	}
	for _, b := range rt.Buckets {
		if b.K == 0 {
			b.K = rt.kSize()
		}
		b.ensureLastSeen()
		b.syncSlices()
	}
	rt.KBuckets = rt.Buckets
}

func (rt *KadRoutingTable) syncExported() {
	rt.KBuckets = rt.Buckets
	rt.buckets = rt.Buckets
	rt.k = rt.kSize()
	if rt.Self != ([16]byte{}) {
		rt.self = rt.Self
	}
}

func (rt *KadRoutingTable) sortBucketsLocked() {
	sort.Slice(rt.Buckets, func(i, j int) bool {
		if rt.Buckets[i].Low != rt.Buckets[j].Low {
			return rt.Buckets[i].Low < rt.Buckets[j].Low
		}
		if rt.Buckets[i].Exact != rt.Buckets[j].Exact {
			return !rt.Buckets[i].Exact // tail after exact? arbitrary
		}
		return rt.Buckets[i].High < rt.Buckets[j].High
	})
	rt.syncExported()
}

func (rt *KadRoutingTable) bucketForLevelLocked(lvl int) *KadBucket {
	for {
		for _, b := range rt.Buckets {
			if b.Exact && b.Low == lvl {
				return b
			}
		}
		var tail *KadBucket
		for _, b := range rt.Buckets {
			if !b.Exact && b.Low <= lvl && lvl <= b.High {
				tail = b
				break
			}
		}
		if tail == nil {
			b := &KadBucket{
				Exact:       false,
				Low:         kadBucketMinLevel,
				High:        kadBucketMaxLevel,
				Level:       kadBucketMinLevel,
				Depth:       kadBucketMinLevel,
				K:           rt.kSize(),
				LastRefresh: time.Now(),
				LastSeen:    make(map[[16]byte]time.Time),
				Contacts:    []KadContact{},
			}
			b.syncSlices()
			rt.Buckets = append(rt.Buckets, b)
			rt.sortBucketsLocked()
			tail = b
		}
		if tail.Full() && tail.Low < kadBucketMaxLevel && tail.Low <= lvl && tail.Low <= kadBucketMaxLevel {
			// split
			exact := &KadBucket{
				Exact:       true,
				Low:         tail.Low,
				High:        tail.Low,
				Level:       tail.Low,
				Depth:       tail.Low,
				PrefixLen:   tail.Low,
				K:           rt.kSize(),
				LastRefresh: time.Now(),
				LastSeen:    make(map[[16]byte]time.Time),
				Contacts:    []KadContact{},
			}
			var remain []KadContact
			for _, c := range tail.Contacts {
				if commonPrefixLen(rt.selfID(), c.idBytes()) == tail.Low {
					exact.Contacts = append(exact.Contacts, c)
					if t, ok := tail.LastSeen[c.idBytes()]; ok {
						exact.LastSeen[c.idBytes()] = t
					}
				} else {
					remain = append(remain, c)
				}
			}
			exact.syncSlices()
			tail.Contacts = remain
			tail.syncSlices()
			tail.Low++
			if tail.Low > tail.High {
				tail.High = tail.Low
			}
			for id := range exact.LastSeen {
				delete(tail.LastSeen, id)
			}
			rt.Buckets = append(rt.Buckets, exact)
			rt.sortBucketsLocked()
			continue
		}
		return tail
	}
}

func commonPrefixLen(a, b [16]byte) int {
	n := 0
	for i := 0; i < 16; i++ {
		x := a[i] ^ b[i]
		if x == 0 {
			n += 8
			continue
		}
		for bit := 7; bit >= 0; bit-- {
			if x&(1<<bit) == 0 {
				n++
			} else {
				return n
			}
		}
	}
	return 128
}

func xorDistance(a, b [16]byte) [16]byte {
	var out [16]byte
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func lessBytes(a, b [16]byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}

func (rt *KadRoutingTable) Insert(contact KadContact) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	self := rt.selfID()
	id := contact.idBytes()
	now := time.Now()
	lvl := commonPrefixLen(self, id)
	bucket := rt.bucketForLevelLocked(lvl)

	if _, ok := bucket.Get(id); ok {
		bucket.Remove(id)
		bucket.Insert(contact)
		bucket.Touch(id, now)
		bucket.LastChanged = now
		rt.syncExported()
		return
	}

	if bucket.Full() {
		// evict least recently seen
		if len(bucket.Contacts) > 0 {
			oldestIdx := 0
			oldestTime := bucket.lastSeenForLocked(bucket.Contacts[0].idBytes())
			for i := 1; i < len(bucket.Contacts); i++ {
				t := bucket.lastSeenForLocked(bucket.Contacts[i].idBytes())
				if t.Before(oldestTime) {
					oldestTime = t
					oldestIdx = i
				}
			}
			removedID := bucket.Contacts[oldestIdx].idBytes()
			bucket.Remove(removedID)
		}
	}
	bucket.Insert(contact)
	bucket.Touch(id, now)
	bucket.LastChanged = now
	bucket.LastRefresh = now
	rt.syncExported()
}

func (b *KadBucket) lastSeenForLocked(id [16]byte) time.Time {
	if b.LastSeen == nil {
		return time.Time{}
	}
	t, ok := b.LastSeen[id]
	if !ok {
		return time.Time{}
	}
	return t
}

func (rt *KadRoutingTable) Get(id [16]byte) (KadContact, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	for _, b := range rt.Buckets {
		if c, ok := b.Get(id); ok {
			return c, true
		}
	}
	return KadContact{}, false
}

func (rt *KadRoutingTable) Remove(id [16]byte) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	for _, b := range rt.Buckets {
		b.Remove(id)
	}
	rt.syncExported()
}

func (rt *KadRoutingTable) Size() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	n := 0
	for _, b := range rt.Buckets {
		n += len(b.Contacts)
	}
	return n
}

func (rt *KadRoutingTable) FindClosest(target [16]byte, n int) []KadContact {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	var all []KadContact
	for _, b := range rt.Buckets {
		all = append(all, b.Contacts...)
	}
	sort.Slice(all, func(i, j int) bool {
		di := xorDistance(all[i].idBytes(), target)
		dj := xorDistance(all[j].idBytes(), target)
		return lessBytes(di, dj)
	})
	if n <= 0 {
		return []KadContact{}
	}
	if n > len(all) {
		n = len(all)
	}
	out := make([]KadContact, n)
	copy(out, all[:n])
	return out
}

func (rt *KadRoutingTable) LastSeen(id [16]byte) (time.Time, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	for _, b := range rt.Buckets {
		if t, ok := b.LastSeenTime(id); ok {
			return t, true
		}
	}
	return time.Time{}, false
}

func (rt *KadRoutingTable) Touch(id [16]byte) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	for _, b := range rt.Buckets {
		if _, ok := b.Get(id); ok {
			b.Touch(id, time.Now())
		}
	}
}

func (rt *KadRoutingTable) MarkSeen(id [16]byte) {
	rt.Touch(id)
}

func (rt *KadRoutingTable) Seen(id [16]byte) bool {
	_, ok := rt.Get(id)
	return ok
}

func (rt *KadRoutingTable) Refresh() {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	for _, b := range rt.Buckets {
		b.Refresh()
	}
}

func (rt *KadRoutingTable) RefreshBucket(level int) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	for _, b := range rt.Buckets {
		if b.Low == level {
			b.Refresh()
		}
	}
}

func (rt *KadRoutingTable) Split() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	n := 0
	for _, b := range append([]*KadBucket{}, rt.Buckets...) {
		if !b.Exact && b.Full() {
			if _, _, ok := rt.splitTailLocked(b); ok {
				n++
			}
		}
	}
	rt.syncExported()
	return n
}

func (rt *KadRoutingTable) splitTailLocked(tail *KadBucket) (*KadBucket, *KadBucket, bool) {
	// reuse logic by calling method but need lock already held; SplitBucket locks, so implement unlocked
	if tail.Exact || tail.Low >= kadBucketMaxLevel {
		return nil, nil, false
	}
	lvl := tail.Low
	exact := &KadBucket{
		Exact:       true,
		Low:         lvl,
		High:        lvl,
		Level:       lvl,
		Depth:       lvl,
		PrefixLen:   lvl,
		K:           rt.kSize(),
		LastRefresh: time.Now(),
		LastSeen:    make(map[[16]byte]time.Time),
		Contacts:    []KadContact{},
	}
	var remain []KadContact
	for _, c := range tail.Contacts {
		if commonPrefixLen(rt.selfID(), c.idBytes()) == lvl {
			exact.Contacts = append(exact.Contacts, c)
			if t, ok := tail.LastSeen[c.idBytes()]; ok {
				exact.LastSeen[c.idBytes()] = t
			}
		} else {
			remain = append(remain, c)
		}
	}
	exact.syncSlices()
	tail.Contacts = remain
	tail.syncSlices()
	tail.Low++
	if tail.Low > tail.High {
		tail.High = tail.Low
	}
	for id := range exact.LastSeen {
		delete(tail.LastSeen, id)
	}
	rt.Buckets = append(rt.Buckets, exact)
	rt.sortBucketsLocked()
	return exact, tail, true
}

func (rt *KadRoutingTable) BucketCount() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	return len(rt.Buckets)
}

func (rt *KadRoutingTable) BucketsSnapshot() []*KadBucket {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.ensureInitLocked()
	out := make([]*KadBucket, len(rt.Buckets))
	copy(out, rt.Buckets)
	return out
}
