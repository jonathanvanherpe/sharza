// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"sync"
	"time"
)

// queryRouter implements descriptor-ID duplicate suppression and
// reverse-path routing for QUERY/QUERYHIT beyond the direct link.
//
// seen records descriptor IDs we have already processed, with a short
// TTL so a query that loops back after the entry expires is handled
// again rather than suppressed forever. routes maps a descriptor ID to
// the peer connection that forwarded the QUERY to us, so the QUERYHIT
// that answers it can be sent back along the same path.
type queryRouter struct {
	mu     sync.Mutex
	seen   map[[idSize]byte]time.Time
	routes map[[idSize]byte]net.Conn
	ttl    time.Duration
}

// seenTTL is how long a descriptor ID stays in the seen set. It is
// short: long enough to suppress a query that loops through the mesh,
// short enough that a legitimately re-issued query (same ID, new
// search) is not dropped forever.
const seenTTL = 2 * time.Minute

func newQueryRouter() *queryRouter {
	return &queryRouter{
		seen:   make(map[[idSize]byte]time.Time),
		routes: make(map[[idSize]byte]net.Conn),
		ttl:    seenTTL,
	}
}

// markSeen returns true if id has not been seen (or its entry has
// expired), recording it now. A false return means a duplicate: the
// caller must not process or forward the message again.
func (r *queryRouter) markSeen(id [idSize]byte) bool {
	if r == nil {
		return true
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.seen == nil {
		r.seen = make(map[[idSize]byte]time.Time)
	}
	if r.ttl <= 0 {
		r.ttl = seenTTL
	}
	now := time.Now()
	if exp, ok := r.seen[id]; ok && now.Before(exp) {
		return false
	}
	r.seen[id] = now.Add(r.ttl)
	// Opportunistic cleanup of expired entries keeps the map small.
	for k, v := range r.seen {
		if !now.Before(v) {
			delete(r.seen, k)
		}
	}
	return true
}

// learn records that id arrived from upstream. The first arrival wins:
// a duplicate from another peer does not overwrite the reverse path.
func (r *queryRouter) learn(id [idSize]byte, upstream net.Conn) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routes == nil {
		r.routes = make(map[[idSize]byte]net.Conn)
	}
	if _, ok := r.routes[id]; ok {
		return
	}
	r.routes[id] = upstream
}

// upstream returns the peer connection that forwarded the QUERY for id,
// if any.
func (r *queryRouter) upstream(id [idSize]byte) (net.Conn, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.routes == nil {
		return nil, false
	}
	c, ok := r.routes[id]
	return c, ok
}
