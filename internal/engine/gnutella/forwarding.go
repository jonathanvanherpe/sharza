// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Query forwarding and horizon routing helpers for the Gnutella engine.
//
// A QUERY received from one peer is answered locally (as before) and then
// propagated to every other peer, with TTL decremented and Hops incremented,
// so a search reaches beyond the direct link. Duplicate QUERYs (same
// descriptor ID arriving on a second path) are suppressed, and QUERYHITs
// are routed back along the reverse path the query took.

import (
	"net"
	"time"
)

// defaultSeenQueryTTL is how long a descriptor ID stays in the
// duplicate-suppression cache. It is long enough to cover a query's
// propagation and reply window and short enough that a retried search
// with a fresh descriptor ID is never affected (IDs are unique per
// query).
const defaultSeenQueryTTL = 2 * time.Minute

// markSeenQuery records id as seen, suppressing any later copy of the
// same query. An optional expiry may be supplied as a time.Duration,
// time.Time, or a number of seconds (int/byte); otherwise the default
// horizon is used.
func (e *Engine) markSeenQuery(id [idSize]byte, opts ...any) {
	dur := defaultSeenQueryTTL
	var until time.Time
	haveUntil := false
	for _, o := range opts {
		switch v := o.(type) {
		case time.Duration:
			dur = v
		case time.Time:
			until = v
			haveUntil = true
		case int:
			dur = time.Duration(v) * time.Second
		case int64:
			dur = time.Duration(v) * time.Second
		case byte:
			dur = time.Duration(v) * time.Second
		}
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if haveUntil {
		e.seenQueries[id] = until
	} else {
		e.seenQueries[id] = time.Now().Add(dur)
	}
}

// isSeenQuery reports whether id has been seen and has not yet expired.
// Expired entries are removed lazily.
func (e *Engine) isSeenQuery(id [idSize]byte) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	until, ok := e.seenQueries[id]
	if !ok {
		return false
	}
	if time.Now().After(until) {
		delete(e.seenQueries, id)
		return false
	}
	return true
}

// recordUpstream stores the peer a query arrived from, so a QUERYHIT
// echoing the same descriptor ID can be routed back along that path.
// An optional expiry argument is accepted for symmetry with
// markSeenQuery and ignored: reverse-path state lives until overwritten.
func (e *Engine) recordUpstream(id [idSize]byte, upstream *peerConn, opts ...any) {
	_ = opts
	e.mu.Lock()
	defer e.mu.Unlock()
	e.forwarding[id] = upstream
}

// upstreamFor returns the peer a query arrived from, or nil if none was
// recorded (for example, for a query this engine originated itself).
func (e *Engine) upstreamFor(id [idSize]byte) *peerConn {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.forwarding[id]
}

// snapshotPeersExcept returns the current peer list, excluding the peer
// identified by origin. origin may be a *peerConn, a *peer, a net.Conn,
// a net.Addr, or an address string; a nil origin returns every peer.
func (e *Engine) snapshotPeersExcept(origin any) []*peerConn {
	e.mu.Lock()
	defer e.mu.Unlock()

	var excludePC *peerConn
	var excludeConn net.Conn
	var excludeAddr string

	switch v := origin.(type) {
	case nil:
	case *peerConn:
		excludePC = v
	case *peer:
		excludeConn = v.conn
	case net.Conn:
		excludeConn = v
	case net.Addr:
		excludeAddr = v.String()
	case string:
		excludeAddr = v
	}

	out := make([]*peerConn, 0, len(e.peers))
	for pc := range e.peers {
		if excludePC != nil && pc == excludePC {
			continue
		}
		if excludeConn != nil && pc.conn == excludeConn {
			continue
		}
		if excludeAddr != "" {
			if pc.addr != nil && pc.addr.String() == excludeAddr {
				continue
			}
			if pc.conn != nil && pc.conn.RemoteAddr() != nil && pc.conn.RemoteAddr().String() == excludeAddr {
				continue
			}
		}
		out = append(out, pc)
	}
	return out
}
