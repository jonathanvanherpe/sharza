// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// routeExpiry is how long a seen-query entry and its reverse route live.
const routeExpiry = 5 * time.Minute

// routeEntry is one remembered descriptor ID: whether we have seen it
// and, if a peer originated it, which peer to forward answers to.
type routeEntry struct {
	origin *peer
	seenAt time.Time
}

// routeTable holds a seen-query cache and reverse routes (descriptor ID
// -> originating *peer), mutex-guarded, with ~5 minute expiry.
type routeTable struct {
	mu      sync.Mutex
	entries map[[idSize]byte]routeEntry
}

// newRouteTable returns an empty route table.
func newRouteTable() *routeTable {
	return &routeTable{entries: make(map[[idSize]byte]routeEntry)}
}

// isDuplicate reports whether id has been seen (and not expired).
func (rt *routeTable) isDuplicate(id [idSize]byte) bool {
	if rt == nil {
		return false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e, ok := rt.entries[id]
	if !ok {
		return false
	}
	if time.Since(e.seenAt) > routeExpiry {
		delete(rt.entries, id)
		return false
	}
	return true
}

// remember records id as seen, with origin as the peer to forward
// answering QUERYHITs to (nil for a locally originated search). An
// existing entry is not overwritten, so the first origin wins; its
// seenAt is refreshed.
func (rt *routeTable) remember(id [idSize]byte, origin *peer) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if e, ok := rt.entries[id]; ok {
		e.seenAt = time.Now()
		rt.entries[id] = e
		return
	}
	rt.entries[id] = routeEntry{origin: origin, seenAt: time.Now()}
}

// origin returns the originating peer for id, or nil if none is recorded
// (including for a locally originated search or an expired entry).
func (rt *routeTable) origin(id [idSize]byte) *peer {
	if rt == nil {
		return nil
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	e, ok := rt.entries[id]
	if !ok {
		return nil
	}
	if time.Since(e.seenAt) > routeExpiry {
		delete(rt.entries, id)
		return nil
	}
	return e.origin
}