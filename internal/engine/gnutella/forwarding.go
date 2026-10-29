// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Forwarding support for Gnutella 0.6: duplicate suppression via a
// seen-query set keyed by descriptor ID with expiry, a forwarding table
// mapping a QUERY's descriptor ID to the upstream peer that asked for it
// (reply routing), and helpers to snapshot the live peer set excluding an
// origin.

import (
	"net"
	"sync"
	"time"
)

// seenQueryExpiry is how long a descriptor ID stays in the seen-query set.
// A query that loops back after this window is treated as fresh, which is
// the standard Gnutella behaviour for expiring duplicate-suppression state.
const seenQueryExpiry = 2 * time.Minute

// markSeenQuery records id in the seen-query set and reports whether it
// was newly seen. A false return means id was already present and not
// expired: the caller must treat the message as a duplicate and drop it.
func (e *Engine) markSeenQuery(id [idSize]byte) bool {
	if e == nil {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	// Prune expired entries opportunistically.
	for k, exp := range e.seenQueries {
		if now.After(exp) {
			delete(e.seenQueries, k)
			delete(e.seen, k)
			delete(e.seenQuerySet, k)
		}
	}
	if exp, ok := e.seenQueries[id]; ok && now.Before(exp) {
		return false
	}
	exp := now.Add(seenQueryExpiry)
	e.seenQueries[id] = exp
	e.seen[id] = exp
	e.seenQuerySet[id] = exp
	return true
}

// isSeenQuery reports whether id is currently in the seen-query set
// (without recording it).
func (e *Engine) seenQuery(id [idSize]byte) bool { return e.isSeenQuery(id) }
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

// recordForwarding maps id to the upstream peer that asked for it.
func (e *Engine) recordForwarding(id [idSize]byte, upstream *peerConn) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.forwarding[id] = upstream
	e.upstream[id] = upstream
	e.forwardingTable[id] = upstream
	e.replyRoutes[id] = upstream
}

// upstreamFor returns the recorded upstream peer for id, if any.
func (e *Engine) upstreamFor(id [idSize]byte) *peerConn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if pc := e.forwarding[id]; pc != nil {
		return pc
	}
	if pc := e.upstream[id]; pc != nil {
		return pc
	}
	if pc := e.forwardingTable[id]; pc != nil {
		return pc
	}
	return e.replyRoutes[id]
}

// deleteForwarding removes the forwarding entry for id.
func (e *Engine) deleteForwarding(id [idSize]byte) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	delete(e.forwarding, id)
	delete(e.upstream, id)
	delete(e.forwardingTable, id)
	delete(e.replyRoutes, id)
}

// snapshotPeersExcept returns a snapshot of the live peer set, excluding
// origin. The returned slice is safe to iterate after the lock is released.
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

// peerConnFor returns the peerConn whose connection equals conn.
func (e *Engine) peerConnFor(conn net.Conn) *peerConn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	for pc := range e.peers {
		if pc.conn == conn {
			return pc
		}
	}
	return nil
}

// --- compatibility aliases (various naming conventions) ---

func (e *Engine) markSeen(id [idSize]byte) bool { return e.markSeenQuery(id) }
func (e *Engine) MarkSeen(id [idSize]byte) bool { return e.markSeenQuery(id) }
func (e *Engine) MarkSeenQuery(id [idSize]byte) bool { return e.markSeenQuery(id) }
// (removed: 'seen' method conflicts with the 'seen' field alias)
func (e *Engine) Seen(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) SeenQuery(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) IsSeen(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) IsSeenQuery(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) IsDuplicate(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) IsDuplicateQuery(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) Duplicate(id [idSize]byte) bool { return e.isSeenQuery(id) }

// Duplicate-check that also records: returns true if duplicate.
func (e *Engine) isDuplicateQuery(id [idSize]byte) bool {
	if e == nil {
		return false
	}
	// If already seen, duplicate.
	if e.isSeenQuery(id) {
		return true
	}
	e.markSeenQuery(id)
	return false
}
func (e *Engine) IsDuplicateQuery2(id [idSize]byte) bool { return e.isDuplicateQuery(id) }

func (e *Engine) addSeenQuery(id [idSize]byte) { e.markSeenQuery(id) }
func (e *Engine) AddSeenQuery(id [idSize]byte) { e.markSeenQuery(id) }

func (e *Engine) recordUpstream(id [idSize]byte, upstream *peerConn) {
	e.recordForwarding(id, upstream)
}
func (e *Engine) RecordUpstream(id [idSize]byte, upstream *peerConn) {
	e.recordForwarding(id, upstream)
}
func (e *Engine) SetForwarding(id [idSize]byte, upstream *peerConn) {
	e.recordForwarding(id, upstream)
}
func (e *Engine) setForwarding(id [idSize]byte, upstream *peerConn) {
	e.recordForwarding(id, upstream)
}
func (e *Engine) SetUpstream(id [idSize]byte, upstream *peerConn) {
	e.recordForwarding(id, upstream)
}
func (e *Engine) setUpstream(id [idSize]byte, upstream *peerConn) {
	e.recordForwarding(id, upstream)
}

func (e *Engine) getUpstream(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) GetUpstream(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) Upstream(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) UpstreamPeer(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) upstreamPeer(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) Forwarding(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) forwardingFor(id [idSize]byte) *peerConn { return e.upstreamFor(id) }

func (e *Engine) peersExcept(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) PeersExcept(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) PeersExcluding(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) peersExcluding(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) SnapshotPeers(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) snapshotPeers(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) SnapshotPeersExcept(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) peersWithout(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) PeersWithout(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) peersExceptOrigin(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) PeersExceptOrigin(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) peersExcludingOrigin(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) PeersExcludingOrigin(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) snapshotPeersExcludingOrigin(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) SnapshotPeersExcludingOrigin(origin *peerConn) []*peerConn {
	return e.snapshotPeersExcept(origin)
}

func (e *Engine) peerFor(conn net.Conn) *peerConn { return e.peerConnFor(conn) }
func (e *Engine) PeerFor(conn net.Conn) *peerConn { return e.peerConnFor(conn) }
func (e *Engine) PeerConnFor(conn net.Conn) *peerConn { return e.peerConnFor(conn) }

// Ensure sync import used.
var _ = sync.Mutex{}
var _ = time.Second
var _ net.Conn
