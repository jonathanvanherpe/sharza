// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// routeTable is the reverse-path route table: a QUERY descriptor ID maps
// to the peer connection it arrived on, so a QUERYHIT can be sent back
// along the reverse path to the originating peer.
type routeTable struct {
	mu     sync.Mutex
	routes map[[idSize]byte]*peerConn
}

func newRouteTable() *routeTable {
	return &routeTable{routes: make(map[[idSize]byte]*peerConn)}
}

// record stores origin as the reverse-path peer for id.
func (rt *routeTable) record(id [idSize]byte, origin *peerConn) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	rt.routes[id] = origin
}

// lookup returns the origin peer for id, if any.
func (rt *routeTable) lookup(id [idSize]byte) (*peerConn, bool) {
	if rt == nil {
		return nil, false
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	pc, ok := rt.routes[id]
	return pc, ok
}

// clearOrigin removes every route whose origin is the given peer.
func (rt *routeTable) clearOrigin(origin *peerConn) {
	if rt == nil {
		return
	}
	rt.mu.Lock()
	defer rt.mu.Unlock()
	for id, pc := range rt.routes {
		if pc == origin {
			delete(rt.routes, id)
		}
	}
}

// seenSet deduplicates QUERYs by descriptor ID.
type seenSet struct {
	mu  sync.Mutex
	ids map[[idSize]byte]struct{}
}

func newSeenSet() *seenSet {
	return &seenSet{ids: make(map[[idSize]byte]struct{})}
}

// add records id and reports whether it was new (true) or already seen
// (false).
func (s *seenSet) add(id [idSize]byte) bool {
	if s == nil {
		return true
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.ids[id]; ok {
		return false
	}
	s.ids[id] = struct{}{}
	return true
}

// contains reports whether id has already been seen.
func (s *seenSet) contains(id [idSize]byte) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.ids[id]
	return ok
}

// seen is an alias for contains.
func (s *seenSet) seen(id [idSize]byte) bool {
	return s.contains(id)
}

// Engine helpers.

// recordQueryRoute records origin as the reverse-path origin for id.
func (e *Engine) recordQueryRoute(id [idSize]byte, origin *peerConn) {
	if e == nil {
		return
	}
	if e.routeTable != nil {
		e.routeTable.record(id, origin)
	}
	// Also support aliased state on Options, if set.
}

// forwardQuery relays a QUERY to every live peer except origin, with TTL
// decremented and Hops incremented. It drops the query when the TTL
// cannot survive another hop.
func (e *Engine) forwardQuery(origin *peerConn, hdr Header, payload []byte) {
	if e == nil {
		return
	}
	if hdr.TTL == 0 {
		return
	}
	newTTL := hdr.TTL - 1
	if newTTL == 0 {
		return
	}
	newHdr := hdr
	newHdr.TTL = newTTL
	newHdr.Hops = hdr.Hops + 1
	newHdr.Length = uint32(len(payload))

	e.mu.Lock()
	peers := make([]*peerConn, 0, len(e.peers))
	for pc := range e.peers {
		if pc != origin {
			peers = append(peers, pc)
		}
	}
	e.mu.Unlock()

	buf := newHdr.AppendTo(nil)
	buf = append(buf, payload...)
	for _, pc := range peers {
		pc.mu.Lock()
		_ = pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		_, _ = pc.conn.Write(buf)
		pc.mu.Unlock()
	}
}

// routeQueryHit sends a QUERYHIT back along the reverse path for id, if
// an origin peer is recorded. It decrements TTL and increments Hops.
func (e *Engine) routeQueryHit(id [idSize]byte, hdr Header, payload []byte) {
	if e == nil {
		return
	}
	var rt *routeTable
	if e.routeTable != nil {
		rt = e.routeTable
	}
	if rt == nil {
		return
	}
	pc, ok := rt.lookup(id)
	if !ok || pc == nil {
		return
	}
	if hdr.TTL == 0 {
		return
	}
	newTTL := hdr.TTL - 1
	if newTTL == 0 {
		return
	}
	newHdr := hdr
	newHdr.TTL = newTTL
	newHdr.Hops = hdr.Hops + 1
	newHdr.Length = uint32(len(payload))

	buf := newHdr.AppendTo(nil)
	buf = append(buf, payload...)
	pc.mu.Lock()
	defer pc.mu.Unlock()
	_ = pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = pc.conn.Write(buf)
}

