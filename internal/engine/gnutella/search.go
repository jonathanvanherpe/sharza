// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// In-flight search registry: a QUERY's 16-byte descriptor ID is the
// correlation key for the QUERYHITs that answer it. A searcher registers
// an ID before it writes the QUERY, every inbound QUERYHIT is delivered
// to the registry, and the search closes itself with the timeout,
// returning whatever it collected.
//
// The ID is the whole key because the wire format gives nothing else to
// match on: a QUERYHIT echoes the descriptor ID of the QUERY it answers
// and carries no other reference to it. A hit under an ID that no
// in-flight search registered is somebody else's result (another
// searcher on the same peer connection, or a reply to a query this
// engine no longer waits for) and is dropped rather than mixed in.

import "sync"

// searchRegistry tracks in-flight searches keyed by descriptor ID.
type searchRegistry struct {
	mu      sync.Mutex
	pending map[[idSize]byte]*pendingSearch
}

// pendingSearch is one in-flight search: the hits collected so far and a
// signal closed when the search finishes, so a waiter can observe the
// close. Both fields are guarded by the owning registry's mutex.
type pendingSearch struct {
	hits []QueryHit
	done chan struct{}
}

func newSearchRegistry() *searchRegistry {
	return &searchRegistry{pending: make(map[[idSize]byte]*pendingSearch)}
}

// register starts collecting hits for id and returns the entry. It must
// be called before the QUERY is written: a peer on a fast link can
// answer before the write call returns, and an unregistered id would
// drop that answer.
func (r *searchRegistry) register(id [idSize]byte) *pendingSearch {
	ps := &pendingSearch{done: make(chan struct{})}
	r.mu.Lock()
	r.pending[id] = ps
	r.mu.Unlock()
	return ps
}

// deliver appends a hit to the search registered under id. A hit whose
// id matches no in-flight search is dropped: it answers a query this
// engine did not ask, and attributing it here would report another
// query's result as this search's.
func (r *searchRegistry) deliver(id [idSize]byte, qh QueryHit) {
	r.mu.Lock()
	if ps := r.pending[id]; ps != nil {
		ps.hits = append(ps.hits, qh)
	}
	r.mu.Unlock()
}

// close ends the search for id: it removes the entry, closes the done
// signal, and returns the hits collected before the timeout. Closing an
// id that is not registered is a no-op returning nil. The map and each
// entry's hits share one mutex, so a delivery racing the close either
// lands before it is read or finds no entry; it can never append after
// the hits are returned and be silently lost.
func (r *searchRegistry) close(id [idSize]byte) []QueryHit {
	r.mu.Lock()
	defer r.mu.Unlock()
	ps := r.pending[id]
	if ps == nil {
		return nil
	}
	delete(r.pending, id)
	close(ps.done)
	return ps.hits
}
