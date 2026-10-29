// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import "time"

// seenQueryTTL is how long a descriptor ID stays in the seen-query set.
// A query that has not completed its traversal within this window is
// treated as a new query if it reappears, which is the desired
// behaviour for a long-stale duplicate.
const seenQueryTTL = 2 * time.Minute

// markSeenQuery records id in the seen-query set. It returns true when
// the id was not already present (or had expired), i.e. this is the
// first time we see it, and false when it is a duplicate that must be
// suppressed.
func (e *Engine) markSeenQuery(id [idSize]byte) bool {
	if e == nil {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	// Prune expired entries while we hold the lock.
	for k, exp := range e.seenQueries {
		if now.After(exp) {
			delete(e.seenQueries, k)
		}
	}
	if exp, ok := e.seenQueries[id]; ok && now.Before(exp) {
		return false
	}
	e.seenQueries[id] = now.Add(seenQueryTTL)
	return true
}

// isSeenQuery reports whether id is currently in the seen-query set.
func (e *Engine) isSeenQuery(id [idSize]byte) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	exp, ok := e.seenQueries[id]
	return ok && now.Before(exp)
}

// recordUpstream stores the peer that sent us the query identified by
// id, so a QUERYHIT for that id can be routed back along the reverse
// path.
func (e *Engine) recordUpstream(id [idSize]byte, upstream *peerConn) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if upstream == nil {
		return
	}
	e.forwarding[id] = upstream
}

// upstreamFor returns the recorded upstream peer for id, if any and not
// expired. Forwarding entries do not expire independently of the
// seen-query set; a missing entry means we originated or never
// forwarded this query.
func (e *Engine) upstreamFor(id [idSize]byte) *peerConn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.forwarding[id]
}

// snapshotPeersExcept returns a slice of the engine's live peers with
// origin excluded. The slice is a snapshot: callers may iterate and
// write to the peers without holding the engine mutex.
func (e *Engine) snapshotPeersExcept(origin *peerConn) []*peerConn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*peerConn, 0, len(e.peers))
	for pc := range e.peers {
		if pc == origin {
			continue
		}
		out = append(out, pc)
	}
	return out
}
