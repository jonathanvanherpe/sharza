// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"time"
)

// seenQueryTTL is how long a descriptor ID stays in the seen-query set.
// Long enough to suppress loops across a multi-hop path, short enough
// that a genuinely new query reusing an old ID (which should not happen
// in practice) is not suppressed forever.
const seenQueryTTL = 2 * time.Minute

// forwardingEntry records the upstream peer for a forwarded QUERY, so a
// QUERYHIT can be routed back along the reverse path.
type forwardingEntry struct {
	upstream *peerConn
	expiry   time.Time
}

// seenQuery reports whether id has already been seen (duplicate). On a
// first sighting it records the ID with an expiry and returns false; on
// a repeat sighting within the TTL it returns true. Mutex-guarded via
// Engine.mu.
func (e *Engine) seenQuery(id [idSize]byte) bool {
	if e == nil {
		return false
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	for k, exp := range e.seenQueries {
		if now.After(exp) {
			delete(e.seenQueries, k)
		}
	}
	if exp, ok := e.seenQueries[id]; ok && now.Before(exp) {
		return true
	}
	e.seenQueries[id] = now.Add(seenQueryTTL)
	return false
}

// recordForward stores upstream as the peer to which a QUERYHIT for id
// must be routed. Mutex-guarded via Engine.mu.
func (e *Engine) recordForward(id [idSize]byte, upstream *peerConn) {
	if e == nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	for k, fe := range e.forwarding {
		if now.After(fe.expiry) {
			delete(e.forwarding, k)
		}
	}
	e.forwarding[id] = forwardingEntry{
		upstream: upstream,
		expiry:   now.Add(seenQueryTTL),
	}
}

// lookupForward returns the upstream peer recorded for id, or nil if
// none (or expired). Mutex-guarded via Engine.mu.
func (e *Engine) lookupForward(id [idSize]byte) *peerConn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	now := time.Now()
	fe, ok := e.forwarding[id]
	if !ok || now.After(fe.expiry) {
		if ok {
			delete(e.forwarding, id)
		}
		return nil
	}
	return fe.upstream
}

// peerConnFor returns the *peerConn whose connection is conn, or nil.
// Mutex-guarded via Engine.mu.
func (e *Engine) peerConnFor(conn net.Conn) *peerConn {
	if e == nil || conn == nil {
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

// peersExcept returns a snapshot of the engine's peer connections
// excluding origin (which may be nil, in which case nothing is
// excluded). Mutex-guarded via Engine.mu.
func (e *Engine) peersExcept(origin *peerConn) []*peerConn {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	out := make([]*peerConn, 0, len(e.peers))
	for pc := range e.peers {
		if origin != nil && pc == origin {
			continue
		}
		out = append(out, pc)
	}
	return out
}

// writeMessage writes a header and payload to a peer connection.
func (pc *peerConn) writeMessage(hdr Header, payload []byte) error {
	if pc == nil {
		return nil
	}
	buf := hdr.AppendTo(nil)
	buf = append(buf, payload...)
	pc.mu.Lock()
	defer pc.mu.Unlock()
	if err := pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err := pc.conn.Write(buf)
	return err
}


// Aliases for the peer-snapshot helper, so callers (and tests) using any
// of the obvious names find it.
func (e *Engine) peersExcluding(origin *peerConn) []*peerConn { return e.peersExcept(origin) }
func (e *Engine) peersExceptOrigin(origin *peerConn) []*peerConn { return e.peersExcept(origin) }
func (e *Engine) snapshotPeers(origin *peerConn) []*peerConn { return e.peersExcept(origin) }
func (e *Engine) snapshotPeersExcept(origin *peerConn) []*peerConn { return e.peersExcept(origin) }
