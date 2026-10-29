// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// routeExpiry is how long a seen-query entry and its reverse route stay
// valid.
const routeExpiry = 5 * time.Minute

// routeEntry is one remembered query.
type routeEntry struct {
	origin *peer
	seenAt time.Time
}

// routeTable holds the seen-query cache and reverse routes.
type routeTable struct {
	mu      sync.Mutex
	entries map[[idSize]byte]routeEntry
}

// newRouteTable returns an empty route table.
func newRouteTable() *routeTable {
	return &routeTable{entries: make(map[[idSize]byte]routeEntry)}
}

// evictLocked removes expired entries. Caller holds mu.
func (r *routeTable) evictLocked(now time.Time) {
	for id, e := range r.entries {
		if now.Sub(e.seenAt) > routeExpiry {
			delete(r.entries, id)
		}
	}
}

// isDuplicate reports whether id has been seen within the expiry window.
func (r *routeTable) isDuplicate(id [idSize]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictLocked(time.Now())
	_, ok := r.entries[id]
	return ok
}

// remember records id as seen with origin.
func (r *routeTable) remember(id [idSize]byte, origin *peer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[[idSize]byte]routeEntry)
	}
	r.evictLocked(time.Now())
	r.entries[id] = routeEntry{origin: origin, seenAt: time.Now()}
}

// origin returns the originating peer for id, or nil.
func (r *routeTable) origin(id [idSize]byte) *peer {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.evictLocked(time.Now())
	e, ok := r.entries[id]
	if !ok {
		return nil
	}
	return e.origin
}
