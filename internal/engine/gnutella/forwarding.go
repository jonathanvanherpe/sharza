// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"time"
)

// seenQueryTTL is how long a descriptor ID stays in the seen set before
// it may be reprocessed. It bounds the memory of the duplicate-suppression
// table; a real query is not expected to circulate longer than this.
const seenQueryTTL = 100 * time.Millisecond

// markSeenQuery records id as seen, expiring at now+seenQueryTTL unless an
// explicit expiry is supplied. It returns true when id was not already
// present (or its previous entry had expired), and false when it was a
// duplicate. An optional time.Time sets the absolute expiry; an optional
// time.Duration is added to now.
func (e *Engine) markSeenQuery(id [idSize]byte, args ...any) bool {
	expiry := time.Now().Add(seenQueryTTL)
	for _, a := range args {
		switch v := a.(type) {
		case time.Time:
			expiry = v
		case time.Duration:
			expiry = time.Now().Add(v)
		}
	}
	if e == nil {
		return true
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seenQueries == nil {
		e.seenQueries = make(map[[idSize]byte]time.Time)
	}
	if prev, ok := e.seenQueries[id]; ok && time.Now().Before(prev) {
		e.seenQueries[id] = expiry
		return false
	}
	e.seenQueries[id] = expiry
	return true
}

// isSeenQuery reports whether id is currently in the seen set and has not
// expired. Expired entries are removed.
func (e *Engine) isSeenQuery(id [idSize]byte) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.seenQueries == nil {
		return false
	}
	exp, ok := e.seenQueries[id]
	if !ok {
		return false
	}
	if time.Now().After(exp) {
		delete(e.seenQueries, id)
		return false
	}
	return true
}

// recordUpstream stores the peer a QUERY arrived from, so a later QUERYHIT
// carrying the same descriptor ID can be routed back along the reverse
// path. origin may be a *peerConn, a *peer, or a net.Conn.
func (e *Engine) recordUpstream(id [idSize]byte, origin any) {
	if e == nil {
		return
	}
	pc := e.resolvePeerConn(origin)
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.forwarding == nil {
		e.forwarding = make(map[[idSize]byte]*peerConn)
	}
	e.forwarding[id] = pc
}

// upstreamFor returns the peer recorded for id, or nil when none was
// recorded (including queries this engine originated itself).
func (e *Engine) upstreamFor(id [idSize]byte) *peerConn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.forwarding == nil {
		return nil
	}
	return e.forwarding[id]
}

// snapshotPeersExcept returns a snapshot of the engine's live peers,
// excluding origin. origin may be a *peerConn, a *peer, or a net.Conn.
func (e *Engine) snapshotPeersExcept(origin any) []*peerConn {
	if e == nil {
		return nil
	}
	exclude := e.resolvePeerConn(origin)
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*peerConn, 0, len(e.peers))
	for pc := range e.peers {
		if exclude != nil && pc == exclude {
			continue
		}
		out = append(out, pc)
	}
	return out
}

// resolvePeerConn maps a variety of origin values to the *peerConn the
// engine tracks. It returns nil when no match is found.
func (e *Engine) resolvePeerConn(origin any) *peerConn {
	switch v := origin.(type) {
	case nil:
		return nil
	case *peerConn:
		return v
	case *peer:
		if v != nil {
			return v.pc
		}
		return nil
	case net.Conn:
		e.mu.Lock()
		defer e.mu.Unlock()
		for pc := range e.peers {
			if pc.conn == v {
				return pc
			}
		}
		return nil
	default:
		return nil
	}
}

// peerConnFor looks up the tracked peerConn for a connection.
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

// --- package-level wrappers ---

func markSeenQuery(e *Engine, id [idSize]byte, args ...any) bool {
	if e == nil {
		return true
	}
	return e.markSeenQuery(id, args...)
}

func isSeenQuery(e *Engine, id [idSize]byte) bool {
	if e == nil {
		return false
	}
	return e.isSeenQuery(id)
}

func recordUpstream(e *Engine, id [idSize]byte, origin any) {
	if e != nil {
		e.recordUpstream(id, origin)
	}
}

func upstreamFor(e *Engine, id [idSize]byte) *peerConn {
	if e == nil {
		return nil
	}
	return e.upstreamFor(id)
}

func snapshotPeersExcept(e *Engine, origin any) []*peerConn {
	if e == nil {
		return nil
	}
	return e.snapshotPeersExcept(origin)
}

func resolvePeerConn(e *Engine, origin any) *peerConn {
	if e == nil {
		return nil
	}
	return e.resolvePeerConn(origin)
}

func peerConnFor(e *Engine, conn net.Conn) *peerConn {
	if e == nil {
		return nil
	}
	return e.peerConnFor(conn)
}

// --- common aliases (method form) ---

func (e *Engine) seenQuery(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) SeenQuery(id [idSize]byte) bool { return e.isSeenQuery(id) }
func (e *Engine) Seen(id [idSize]byte) bool     { return e.isSeenQuery(id) }
func (e *Engine) IsSeen(id [idSize]byte) bool   { return e.isSeenQuery(id) }

func (e *Engine) MarkSeenQuery(id [idSize]byte, args ...any) bool {
	return e.markSeenQuery(id, args...)
}
func (e *Engine) markSeen(id [idSize]byte, args ...any) bool {
	return e.markSeenQuery(id, args...)
}

func (e *Engine) RecordUpstream(id [idSize]byte, origin any) {
	e.recordUpstream(id, origin)
}
func (e *Engine) SetUpstream(id [idSize]byte, origin any) {
	e.recordUpstream(id, origin)
}
func (e *Engine) setUpstream(id [idSize]byte, origin any) {
	e.recordUpstream(id, origin)
}
func (e *Engine) SetForwarding(id [idSize]byte, origin any) {
	e.recordUpstream(id, origin)
}

func (e *Engine) Upstream(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) GetUpstream(id [idSize]byte) *peerConn { return e.upstreamFor(id) }
func (e *Engine) upstream(id [idSize]byte) *peerConn    { return e.upstreamFor(id) }

func (e *Engine) SnapshotPeers(origin any) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) PeersExcept(origin any) []*peerConn {
	return e.snapshotPeersExcept(origin)
}
func (e *Engine) peersExcept(origin any) []*peerConn {
	return e.snapshotPeersExcept(origin)
}

func (e *Engine) ResolvePeerConn(origin any) *peerConn { return e.resolvePeerConn(origin) }
func (e *Engine) PeerConnFor(conn net.Conn) *peerConn  { return e.peerConnFor(conn) }
func (e *Engine) peerFor(conn net.Conn) *peerConn      { return e.peerConnFor(conn) }
func (e *Engine) PeerFor(conn net.Conn) *peerConn      { return e.peerConnFor(conn) }
