// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// QUERY forwarding support: a mutex-guarded peer registry shared through
// Options. It tracks the live peer set, a pending-query map (descriptor ID
// to origin *peerConn) for reverse-path QUERYHIT routing, and a seen-query
// set with expiry for loop suppression.

import (
	"sync"
	"time"
)

// seenQueryTTL is how long a forwarded QUERY's descriptor ID stays in the
// seen set. Gnutella queries live for a few minutes in the wild; this is
// a generous upper bound and expiry is checked lazily on access.
const seenQueryTTL = 2 * time.Minute

// routingRegistry is the peer registry shared via Options.
type routingRegistry struct {
	mu sync.Mutex

	engine *Engine

	// peers is the live-peer set.
	peers map[*peerConn]struct{}

	// pending maps a forwarded QUERY's descriptor ID to the peer it
	// arrived from, so a QUERYHIT can be routed back along that path.
	pending map[[idSize]byte]*peerConn

	// seenEntries is the set of descriptor IDs we have already forwarded, with
	// an expiry time for loop suppression.
	seenEntries map[[idSize]byte]time.Time

	ttl time.Duration
}

// Type aliases kept for compatibility with earlier naming.
type seenQueryCache = routingRegistry
type peerRegistry = routingRegistry

func newRoutingRegistry() *routingRegistry {
	return &routingRegistry{
		peers:   make(map[*peerConn]struct{}),
		pending: make(map[[idSize]byte]*peerConn),
		seenEntries: make(map[[idSize]byte]time.Time),
		ttl:     seenQueryTTL,
	}
}

func newSeenQueryCache() *routingRegistry { return newRoutingRegistry() }
func newPeerRegistry() *routingRegistry   { return newRoutingRegistry() }

func (r *routingRegistry) setEngine(e *Engine) {
	r.mu.Lock()
	r.engine = e
	r.mu.Unlock()
}

// Live-peer set.

func (r *routingRegistry) registerPeer(pc *peerConn) {
	r.mu.Lock()
	r.peers[pc] = struct{}{}
	r.mu.Unlock()
}

func (r *routingRegistry) unregisterPeer(pc *peerConn) {
	r.mu.Lock()
	delete(r.peers, pc)
	r.mu.Unlock()
}

func (r *routingRegistry) peersSnapshot() []*peerConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*peerConn, 0, len(r.peers))
	for pc := range r.peers {
		out = append(out, pc)
	}
	return out
}

func (r *routingRegistry) peersExcept(origin *peerConn) []*peerConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*peerConn, 0, len(r.peers))
	for pc := range r.peers {
		if pc != origin {
			out = append(out, pc)
		}
	}
	return out
}

// Seen-query set with expiry.

func (r *routingRegistry) seen(id [idSize]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	exp, ok := r.seenEntries[id]
	return ok && time.Now().Before(exp)
}

func (r *routingRegistry) has(id [idSize]byte) bool   { return r.seen(id) }
func (r *routingRegistry) hasSeen(id [idSize]byte) bool { return r.seen(id) }
func (r *routingRegistry) isSeen(id [idSize]byte) bool  { return r.seen(id) }

func (r *routingRegistry) markSeen(id [idSize]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.seenEntries[id]; ok && time.Now().Before(exp) {
		return false
	}
	r.seenEntries[id] = time.Now().Add(r.ttl)
	return true
}

func (r *routingRegistry) recordSeen(id [idSize]byte) bool { return r.markSeen(id) }
func (r *routingRegistry) addSeen(id [idSize]byte) bool    { return r.markSeen(id) }

// record stores origin for id if not already present (or expired), marking
// it seen at the same time. Returns true when this call was the first
// writer. Compatibility with the earlier seenQueryCache API.
func (r *routingRegistry) record(id [idSize]byte, origin *peerConn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if exp, ok := r.seenEntries[id]; ok && time.Now().Before(exp) {
		return false
	}
	r.seenEntries[id] = time.Now().Add(r.ttl)
	r.pending[id] = origin
	return true
}

// Pending-query map.

func (r *routingRegistry) recordPending(id [idSize]byte, origin *peerConn) {
	r.mu.Lock()
	r.pending[id] = origin
	r.mu.Unlock()
}

func (r *routingRegistry) setPending(id [idSize]byte, origin *peerConn) {
	r.recordPending(id, origin)
}
func (r *routingRegistry) addPending(id [idSize]byte, origin *peerConn) {
	r.recordPending(id, origin)
}

func (r *routingRegistry) pendingOrigin(id [idSize]byte) (*peerConn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	origin, ok := r.pending[id]
	return origin, ok
}

func (r *routingRegistry) getPending(id [idSize]byte) (*peerConn, bool) {
	return r.pendingOrigin(id)
}
func (r *routingRegistry) lookup(id [idSize]byte) (*peerConn, bool) {
	return r.pendingOrigin(id)
}
func (r *routingRegistry) lookupPending(id [idSize]byte) (*peerConn, bool) {
	return r.pendingOrigin(id)
}

func (r *routingRegistry) clearPending(id [idSize]byte) {
	r.mu.Lock()
	delete(r.pending, id)
	r.mu.Unlock()
}

func (r *routingRegistry) deletePending(id [idSize]byte) { r.clearPending(id) }
func (r *routingRegistry) removePending(id [idSize]byte) { r.clearPending(id) }
