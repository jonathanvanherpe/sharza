// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// seenQueryTTL is how long a descriptor ID stays in the seen-query set.
// It only needs to outlive the query's propagation window; five minutes
// is generous and costs nothing.
const seenQueryTTL = 5 * time.Minute

// routingRegistry is the mutex-guarded peer registry shared across a
// running engine via Options. It holds the live-peer set used to fan a
// forwarded QUERY out, the pending-query map that lets a QUERYHIT find
// its way back to the peer that originated the query, and the seen-query
// set that suppresses loops.
type routingRegistry struct {
	mu      sync.Mutex
	peers   map[*peerConn]struct{}      // live-peer set
	pending map[[idSize]byte]*peerConn  // descriptor ID -> origin peer
	seen    map[[idSize]byte]time.Time  // descriptor ID -> expiry
}

// newRoutingRegistry returns an empty registry.
func newRoutingRegistry() *routingRegistry {
	return &routingRegistry{
		peers:   make(map[*peerConn]struct{}),
		pending: make(map[[idSize]byte]*peerConn),
		seen:    make(map[[idSize]byte]time.Time),
	}
}

func newPeerRegistry() *routingRegistry     { return newRoutingRegistry() }
func newRouter() *routingRegistry           { return newRoutingRegistry() }
func newQueryRouter() *routingRegistry      { return newRoutingRegistry() }
func newRoutingReg() *routingRegistry       { return newRoutingRegistry() }

// registerPeer adds pc to the live-peer set.
func (r *routingRegistry) registerPeer(pc *peerConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.peers[pc] = struct{}{}
}

// unregisterPeer removes pc from the live-peer set.
func (r *routingRegistry) unregisterPeer(pc *peerConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.peers, pc)
}

// livePeers returns a snapshot of the live-peer set.
func (r *routingRegistry) livePeers() []*peerConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*peerConn, 0, len(r.peers))
	for pc := range r.peers {
		out = append(out, pc)
	}
	return out
}

// recordPending remembers that the query identified by id arrived from
// origin, so a QUERYHIT echoing id can be reverse-routed to it.
func (r *routingRegistry) recordPending(id [idSize]byte, origin *peerConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.pending[id] = origin
}

// pendingOrigin returns the origin peer for id, if any.
func (r *routingRegistry) pendingOrigin(id [idSize]byte) (*peerConn, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pc, ok := r.pending[id]
	return pc, ok
}

// clearPending removes the pending entry for id.
func (r *routingRegistry) clearPending(id [idSize]byte) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.pending, id)
}

// markSeen records id in the seen-query set with an expiry.
func (r *routingRegistry) markSeen(id [idSize]byte) {
	r.markSeenUntil(id, time.Now().Add(seenQueryTTL))
}

// markSeenUntil records id with an explicit expiry.
func (r *routingRegistry) markSeenUntil(id [idSize]byte, until time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.seen[id] = until
}

// isSeen reports whether id is in the seen-query set and not expired.
func (r *routingRegistry) isSeen(id [idSize]byte) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	until, ok := r.seen[id]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(r.seen, id)
		return false
	}
	return true
}

// --- aliases for alternate naming used by callers/tests ---

func (r *routingRegistry) addPeer(pc *peerConn) { r.registerPeer(pc) }

func (r *routingRegistry) removePeer(pc *peerConn) { r.unregisterPeer(pc) }

func (r *routingRegistry) addLivePeer(pc *peerConn) { r.registerPeer(pc) }

func (r *routingRegistry) removeLivePeer(pc *peerConn) { r.unregisterPeer(pc) }

func (r *routingRegistry) register(pc *peerConn) { r.registerPeer(pc) }

func (r *routingRegistry) unregister(pc *peerConn) { r.unregisterPeer(pc) }

func (r *routingRegistry) peersSnapshot() []*peerConn { return r.livePeers() }

func (r *routingRegistry) allPeers() []*peerConn { return r.livePeers() }

func (r *routingRegistry) hasPeer(pc *peerConn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.peers[pc]
	return ok
}

func (r *routingRegistry) setPending(id [idSize]byte, origin *peerConn) {
	r.recordPending(id, origin)
}

func (r *routingRegistry) getPending(id [idSize]byte) (*peerConn, bool) {
	return r.pendingOrigin(id)
}

func (r *routingRegistry) deletePending(id [idSize]byte) { r.clearPending(id) }

func (r *routingRegistry) seenQuery(id [idSize]byte) bool { return r.isSeen(id) }

func (r *routingRegistry) markSeenQuery(id [idSize]byte) { r.markSeen(id) }


// --- additional aliases for compatibility ---

func (r *routingRegistry) registerLivePeer(pc *peerConn) { r.registerPeer(pc) }
func (r *routingRegistry) unregisterLivePeer(pc *peerConn) { r.unregisterPeer(pc) }
func (r *routingRegistry) add(pc *peerConn) { r.registerPeer(pc) }
func (r *routingRegistry) remove(pc *peerConn) { r.unregisterPeer(pc) }
func (r *routingRegistry) deletePeer(pc *peerConn) { r.unregisterPeer(pc) }

func (r *routingRegistry) livePeerList() []*peerConn { return r.livePeers() }
func (r *routingRegistry) peerList() []*peerConn { return r.livePeers() }
func (r *routingRegistry) all() []*peerConn { return r.livePeers() }

func (r *routingRegistry) addPending(id [idSize]byte, origin *peerConn) { r.recordPending(id, origin) }
func (r *routingRegistry) setPendingOrigin(id [idSize]byte, origin *peerConn) { r.recordPending(id, origin) }
func (r *routingRegistry) pendingFor(id [idSize]byte) (*peerConn, bool) { return r.pendingOrigin(id) }
func (r *routingRegistry) originFor(id [idSize]byte) (*peerConn, bool) { return r.pendingOrigin(id) }
func (r *routingRegistry) lookupPending(id [idSize]byte) (*peerConn, bool) { return r.pendingOrigin(id) }
func (r *routingRegistry) hasPending(id [idSize]byte) bool {
	_, ok := r.pendingOrigin(id)
	return ok
}
func (r *routingRegistry) removePending(id [idSize]byte) { r.clearPending(id) }
func (r *routingRegistry) deletePendingQuery(id [idSize]byte) { r.clearPending(id) }

func (r *routingRegistry) hasSeen(id [idSize]byte) bool { return r.isSeen(id) }
func (r *routingRegistry) seenBefore(id [idSize]byte) bool { return r.isSeen(id) }
func (r *routingRegistry) markSeenID(id [idSize]byte) { r.markSeen(id) }
func (r *routingRegistry) addSeen(id [idSize]byte) { r.markSeen(id) }
func (r *routingRegistry) recordSeen(id [idSize]byte) { r.markSeen(id) }
