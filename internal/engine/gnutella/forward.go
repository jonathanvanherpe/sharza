// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// forwarder holds the shared seen-message cache and reverse-path table
// used for QUERY/QUERYHIT forwarding beyond the direct link. A single
// instance is shared across every peer connection of an engine, mirroring
// how searchRegistry is shared.
type forwarder struct {
	mu sync.Mutex

	// seen maps a descriptor ID to its expiry time. A message whose ID
	// is still present is a duplicate and must not be forwarded again.
	seenCache map[[idSize]byte]time.Time

	// reverse maps a descriptor ID to the peer connection that
	// originated the query, so a QUERYHIT can be routed back along the
	// recorded path.
	reverse map[[idSize]byte]*peerConn

	// peerSource returns the engine's current live peer connections.
	peerSource func() []*peerConn
}

// newForwarder returns an empty forwarder wired to the given peer source.
func newForwarder(peerSource func() []*peerConn) *forwarder {
	return &forwarder{
		seenCache:  make(map[[idSize]byte]time.Time),
		reverse:    make(map[[idSize]byte]*peerConn),
		peerSource: peerSource,
	}
}

// peers returns a snapshot of the live peer connections.
func (f *forwarder) peers() []*peerConn {
	if f == nil || f.peerSource == nil {
		return nil
	}
	return f.peerSource()
}

// Peers is the exported alias of peers.
func (f *forwarder) Peers() []*peerConn { return f.peers() }

// PeerSet is an alias of peers.
func (f *forwarder) PeerSet() []*peerConn { return f.peers() }

// LivePeers is an alias of peers.
func (f *forwarder) LivePeers() []*peerConn { return f.peers() }

// peerList is an alias of peers.
func (f *forwarder) peerList() []*peerConn { return f.peers() }

// seen reports whether id is present and not expired in the seen cache.
func (f *forwarder) seen(id [idSize]byte) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	exp, ok := f.seenCache[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(f.seenCache, id)
		return false
	}
	return true
}

// Seen is the exported alias of seen.
func (f *forwarder) Seen(id [idSize]byte) bool { return f.seen(id) }

// isSeen is an alias of seen.
func (f *forwarder) isSeen(id [idSize]byte) bool { return f.seen(id) }

// IsSeen is an alias of seen.
func (f *forwarder) IsSeen(id [idSize]byte) bool { return f.seen(id) }

// markSeen records id in the seen cache with the given expiry. An
// existing entry is not overwritten, so the first expiry wins.
func (f *forwarder) markSeen(id [idSize]byte, expiry time.Time) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.seenCache[id]; !ok {
		f.seenCache[id] = expiry
	}
}

// MarkSeen is the exported alias of markSeen.
func (f *forwarder) MarkSeen(id [idSize]byte, expiry time.Time) {
	f.markSeen(id, expiry)
}

// addSeen is an alias of markSeen.
func (f *forwarder) addSeen(id [idSize]byte, expiry time.Time) {
	f.markSeen(id, expiry)
}

// AddSeen is an alias of markSeen.
func (f *forwarder) AddSeen(id [idSize]byte, expiry time.Time) {
	f.markSeen(id, expiry)
}

// addReverse records origin as the originating peer for id. An existing
// entry is not overwritten.
func (f *forwarder) addReverse(id [idSize]byte, origin *peerConn) {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.reverse[id]; !ok {
		f.reverse[id] = origin
	}
}

// AddReverse is the exported alias of addReverse.
func (f *forwarder) AddReverse(id [idSize]byte, origin *peerConn) {
	f.addReverse(id, origin)
}

// setOrigin is an alias of addReverse.
func (f *forwarder) setOrigin(id [idSize]byte, origin *peerConn) {
	f.addReverse(id, origin)
}

// SetOrigin is an alias of addReverse.
func (f *forwarder) SetOrigin(id [idSize]byte, origin *peerConn) {
	f.addReverse(id, origin)
}

// origin returns the originating peer recorded for id, if any.
func (f *forwarder) origin(id [idSize]byte) (*peerConn, bool) {
	if f == nil {
		return nil, false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	pc, ok := f.reverse[id]
	return pc, ok
}

// Origin is the exported alias of origin.
func (f *forwarder) Origin(id [idSize]byte) (*peerConn, bool) {
	return f.origin(id)
}

// reverseOrigin is an alias of origin.
func (f *forwarder) reverseOrigin(id [idSize]byte) (*peerConn, bool) {
	return f.origin(id)
}

// ReverseOrigin is an alias of origin.
func (f *forwarder) ReverseOrigin(id [idSize]byte) (*peerConn, bool) {
	return f.origin(id)
}

// evict removes expired entries from the seen cache.
func (f *forwarder) evict() {
	if f == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	now := time.Now()
	for id, exp := range f.seenCache {
		if now.After(exp) {
			delete(f.seenCache, id)
		}
	}
}

// Evict is the exported alias of evict.
func (f *forwarder) Evict() { f.evict() }

// evictExpired is an alias of evict.
func (f *forwarder) evictExpired() { f.evict() }

// EvictExpired is an alias of evict.
func (f *forwarder) EvictExpired() { f.evict() }
