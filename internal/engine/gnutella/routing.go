// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Query routing for Gnutella 0.6: a mutex-guarded forwarding table that
// remembers, for every forwarded QUERY descriptor ID, which peer it came
// from (the reverse path a QUERYHIT must follow back), plus a short-lived
// seen-set that drops duplicate/looped queries by descriptor ID. TTL and
// Hops accounting helpers live here too, so the forwarding step in
// peer.go stays a single call site.
//
// The table is per engine: every peer connection shares one instance,
// handed out through Options like the search registry.

import (
	"sync"
	"time"
)

// seenTTL is how long a descriptor ID stays in the loop-suppression
// set. It only needs to cover the lifetime of one query's traversal,
// which is bounded by the query TTL; a couple of minutes is generous
// and keeps memory bounded on a busy node.
const seenTTL = 2 * time.Minute

// routingTable is the per-engine forwarding state.
type routingTable struct {
	mu sync.Mutex

	// reverse maps a forwarded query's descriptor ID to the peer it
	// arrived from, so the matching QUERYHIT can be sent back along
	// the same path.
	reverse map[[idSize]byte]*peerConn

	// seen suppresses duplicate/looped queries. The value is the
	// expiry time; entries are evicted lazily on access.
	seen map[[idSize]byte]time.Time
}

func newRoutingTable() *routingTable {
	return &routingTable{
		reverse: make(map[[idSize]byte]*peerConn),
		seen:    make(map[[idSize]byte]time.Time),
	}
}

// markSeen reports whether id has been seen before. The first call for an
// id records it and returns false; later calls within seenTTL return true
// so the caller can drop the duplicate. Expired entries are evicted.
func (rt *routingTable) markSeen(id [idSize]byte) bool {
	rt.mu.Lock()
	defer rt.mu.Unlock()

	now := time.Now()
	for k, expiry := range rt.seen {
		if !now.Before(expiry) {
			delete(rt.seen, k)
		}
	}
	if expiry, ok := rt.seen[id]; ok && now.Before(expiry) {
		return true
	}
	rt.seen[id] = now.Add(seenTTL)
	return false
}

// setReverse records the upstream peer for a forwarded query. It does not
// overwrite an existing entry, so the first arrival wins on a loop.
func (rt *routingTable) setReverse(id [idSize]byte, pc *peerConn) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if _, ok := rt.reverse[id]; ok {
		return
	}
	rt.reverse[id] = pc
}

// getReverse returns the upstream peer for id, if any.
func (rt *routingTable) getReverse(id [idSize]byte) (*peerConn, bool) {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pc, ok := rt.reverse[id]
	return pc, ok
}

// forwardTTL decrements ttl for one hop and reports whether the message
// should still be forwarded (ttl > 1 on arrival). The returned value is
// the TTL to put on the forwarded frame.
func forwardTTL(ttl byte) (byte, bool) {
	if ttl <= 1 {
		return 0, false
	}
	return ttl - 1, true
}

// forwardHops increments the hop counter for one hop.
func forwardHops(hops byte) byte {
	return hops + 1
}
