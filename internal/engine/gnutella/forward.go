// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// forwardingRegistry is the unexported forwarding state for multi-hop
// QUERY/QUERYHIT routing. It keeps a descriptor-ID seen-set for duplicate
// suppression and a reverse-path map from a descriptor ID to the peer a
// QUERY arrived from, so a QUERYHIT can be sent back along the link the
// original QUERY came in on.
type forwardingRegistry struct {
	mu      sync.Mutex
	engine  *Engine
	seen    map[[idSize]byte]struct{}
	reverse map[[idSize]byte]*peer
}

func newForwardingRegistry(engine *Engine) *forwardingRegistry {
	return &forwardingRegistry{
		engine:  engine,
		seen:    make(map[[idSize]byte]struct{}),
		reverse: make(map[[idSize]byte]*peer),
	}
}

// MarkSeen records id in the seen-set. It reports true when the id was
// not present before (a new query) and false when it is a duplicate.
func (f *forwardingRegistry) MarkSeen(id [idSize]byte) bool {
	if f == nil {
		return true
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, dup := f.seen[id]; dup {
		return false
	}
	f.seen[id] = struct{}{}
	return true
}

// Seen reports whether id is already in the seen-set.
func (f *forwardingRegistry) Seen(id [idSize]byte) bool {
	if f == nil {
		return false
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.seen[id]
	return ok
}

// RecordReverse stores the peer a QUERY with descriptor id arrived from,
// so QUERYHITs answering it can be routed back. An existing entry is
// kept, so the first arrival wins.
func (f *forwardingRegistry) RecordReverse(id [idSize]byte, origin *peer) {
	if f == nil || origin == nil {
		return
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.reverse[id]; !ok {
		f.reverse[id] = origin
	}
}

// ReversePeer returns the peer a QUERY with descriptor id arrived from,
// if any.
func (f *forwardingRegistry) ReversePeer(id [idSize]byte) *peer {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.reverse[id]
}

// ForwardQuery forwards a QUERY (payload) received from origin to every
// live peer except origin. It suppresses duplicates via the seen-set,
// records the reverse path, decrements TTL and increments Hops, and
// drops the message when TTL reaches zero. The header is not mutated;
// a copy with updated counters is sent.
func (f *forwardingRegistry) ForwardQuery(origin *peer, hdr Header, payload []byte) {
	if f == nil {
		return
	}
	// Duplicate suppression: a descriptor ID already seen is not
	// forwarded again.
	if !f.MarkSeen(hdr.ID) {
		return
	}
	f.RecordReverse(hdr.ID, origin)

	// Decrement TTL, increment Hops.
	if hdr.TTL == 0 {
		return
	}
	hdr.TTL--
	hdr.Hops++
	if hdr.TTL == 0 {
		return // expired: do not forward
	}

	eng := f.engine
	if eng == nil {
		return
	}
	eng.mu.Lock()
	peers := make([]*peerConn, 0, len(eng.peers))
	for pc := range eng.peers {
		peers = append(peers, pc)
	}
	eng.mu.Unlock()

	var wg sync.WaitGroup
	for _, pc := range peers {
		if origin != nil && pc.conn == origin.conn {
			continue
		}
		wg.Add(1)
		go func(pc *peerConn) {
			defer wg.Done()
			pc.mu.Lock()
			defer pc.mu.Unlock()
			_ = pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			h := hdr
			buf := h.AppendTo(nil)
			buf = append(buf, payload...)
			_, _ = pc.conn.Write(buf)
		}(pc)
	}
	wg.Wait()
}

// RouteQueryHit routes a QUERYHIT back along the reverse path of its
// descriptor ID. It returns true when a route was found and the message
// was forwarded. TTL is decremented and Hops incremented; the message is
// dropped when TTL reaches zero.
func (f *forwardingRegistry) RouteQueryHit(receiver *peer, hdr Header, payload []byte) bool {
	if f == nil {
		return false
	}
	origin := f.ReversePeer(hdr.ID)
	if origin == nil || origin == receiver {
		return false
	}
	if hdr.TTL == 0 {
		return false
	}
	hdr.TTL--
	hdr.Hops++
	if hdr.TTL == 0 {
		return false
	}
	return origin.writeMessage(hdr, payload) == nil
}

// Engine-level convenience wrappers.
func (e *Engine) ForwardQuery(origin *peer, hdr Header, payload []byte) {
	if e == nil {
		return
	}
	if e.forwarding == nil {
		return
	}
	e.forwarding.ForwardQuery(origin, hdr, payload)
}

func (e *Engine) RouteQueryHit(receiver *peer, hdr Header, payload []byte) bool {
	if e == nil || e.forwarding == nil {
		return false
	}
	return e.forwarding.RouteQueryHit(receiver, hdr, payload)
}

// Package-level helpers.
func ForwardQuery(origin *peer, hdr Header, payload []byte) {
	if origin != nil && origin.opts.forwarding != nil {
		origin.opts.forwarding.ForwardQuery(origin, hdr, payload)
		return
	}
	// Fall back to engine on Options if present.
	if origin != nil && origin.opts.engine != nil {
		origin.opts.engine.ForwardQuery(origin, hdr, payload)
	}
}

func RouteQueryHit(receiver *peer, hdr Header, payload []byte) bool {
	if receiver != nil && receiver.opts.forwarding != nil {
		return receiver.opts.forwarding.RouteQueryHit(receiver, hdr, payload)
	}
	if receiver != nil && receiver.opts.engine != nil {
		return receiver.opts.engine.RouteQueryHit(receiver, hdr, payload)
	}
	return false
}

// Peer-level convenience methods.
func (p *peer) ForwardQuery(hdr Header, payload []byte) {
	ForwardQuery(p, hdr, payload)
}

func (p *peer) RouteQueryHit(hdr Header, payload []byte) bool {
	return RouteQueryHit(p, hdr, payload)
}
