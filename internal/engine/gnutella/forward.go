// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Query forwarding for Gnutella 0.6: multi-hop QUERY propagation with
// TTL/Hops accounting and duplicate suppression, plus reverse-path
// routing of QUERYHITs back to the originating peer.
//
// The registry is unexported and lives on the Engine. It is consulted by
// peer.handleQuery and peer.handleQueryHit; callers never touch it
// directly, but the helpers below are exported-by-package (lower-case) so
// tests in this package can drive them.

import "sync"

// forwardRegistry tracks which descriptor IDs have been seen (duplicate
// suppression) and the reverse path a QUERY took, so a QUERYHIT can be
// routed back to the peer that originally asked.
type forwardRegistry struct {
	mu      sync.Mutex
	seen    map[[idSize]byte]struct{}
	reverse map[[idSize]byte]*peer
}

func newForwardRegistry() *forwardRegistry {
	return &forwardRegistry{
		seen:    make(map[[idSize]byte]struct{}),
		reverse: make(map[[idSize]byte]*peer),
	}
}

// isSeen reports whether id has already been processed.
func (f *forwardRegistry) isSeen(id [idSize]byte) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.seen[id]
	return ok
}

// markSeen records id as processed.
func (f *forwardRegistry) markSeen(id [idSize]byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.seen[id] = struct{}{}
}

// recordReverse stores the peer a QUERY with id arrived from.
func (f *forwardRegistry) recordReverse(id [idSize]byte, p *peer) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.reverse[id] = p
}

// reversePeer returns the peer a QUERY with id arrived from, if any.
func (f *forwardRegistry) reversePeer(id [idSize]byte) *peer {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reverse[id]
}

// ForwardQuery fans a QUERY out to every live peer except origin, with
// TTL decremented and Hops incremented. It is a no-op when TTL < 2.
func (e *Engine) ForwardQuery(origin *peer, hdr Header, payload []byte) {
	if hdr.TTL < 2 {
		return
	}
	newHdr := Header{
		ID:     hdr.ID,
		Type:   MsgQuery,
		TTL:    hdr.TTL - 1,
		Hops:   hdr.Hops + 1,
		Length: uint32(len(payload)),
	}
	buf := newHdr.AppendTo(nil)
	buf = append(buf, payload...)

	e.mu.Lock()
	peers := make([]*peer, 0, len(e.peers))
	for q := range e.peers {
		if q == origin {
			continue
		}
		peers = append(peers, q)
	}
	e.mu.Unlock()

	for _, q := range peers {
		_ = q.write(buf)
	}
}

// ForwardQuery is the *peer form: origin is p itself is not used as
// origin; instead p is the receiving peer and origin is passed by the
// caller via the engine helper. This method forwards to all peers except
// p, treating p as the origin of the incoming QUERY.
func (p *peer) ForwardQuery(hdr Header, payload []byte) {
	if p.eng == nil {
		return
	}
	p.eng.ForwardQuery(p, hdr, payload)
}

// RouteQueryHit forwards a QUERYHIT along the reverse path recorded for
// its descriptor ID, with TTL-1/Hops+1, dropping at TTL 0.
func (e *Engine) RouteQueryHit(hdr Header, payload []byte) {
	if hdr.TTL == 0 {
		return
	}
	newTTL := hdr.TTL - 1
	if newTTL == 0 {
		return
	}
	rp := e.forwards.reversePeer(hdr.ID)
	if rp == nil {
		return
	}
	newHdr := Header{
		ID:     hdr.ID,
		Type:   MsgQueryHit,
		TTL:    newTTL,
		Hops:   hdr.Hops + 1,
		Length: uint32(len(payload)),
	}
	buf := newHdr.AppendTo(nil)
	buf = append(buf, payload...)
	_ = rp.write(buf)
}

// RouteQueryHit is the *peer form.
func (p *peer) RouteQueryHit(hdr Header, payload []byte) {
	if p.eng == nil {
		return
	}
	p.eng.RouteQueryHit(hdr, payload)
}
