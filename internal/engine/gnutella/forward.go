// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// forwardExpiry is how long a forwarding-table entry (and a duplicate-GUID
// suppression entry) stays live. A QUERY's TTL is at most 7 and each hop
// takes milliseconds, so a couple of minutes is comfortably longer than
// any real search horizon while still letting the table forget stale IDs.
const forwardExpiry = 2 * time.Minute

// forwardingTable correlates a forwarded QUERY's descriptor ID with the
// peer that sent it, so the matching QUERYHIT can be routed back along
// the reverse path. It also suppresses duplicate GUIDs, which is what
// keeps a QUERY from looping forever in a mesh.
type forwardingTable struct {
	mu      sync.Mutex
	entries map[[idSize]byte]*forwardEntry
	seen    map[[idSize]byte]time.Time
}

type forwardEntry struct {
	upstream *peerConn
	expiry   time.Time
}

func newForwardingTable() *forwardingTable {
	return &forwardingTable{
		entries: make(map[[idSize]byte]*forwardEntry),
		seen:    make(map[[idSize]byte]time.Time),
	}
}

// record marks id as seen and, if it is new, stores upstream as the
// reverse-path peer. It returns true when the caller should process the
// message, and false when id is a duplicate that must be dropped.
func (ft *forwardingTable) record(id [idSize]byte, upstream *peerConn) bool {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	now := time.Now()
	ft.evictLocked(now)
	if _, dup := ft.seen[id]; dup {
		return false
	}
	ft.seen[id] = now.Add(forwardExpiry)
	ft.entries[id] = &forwardEntry{upstream: upstream, expiry: now.Add(forwardExpiry)}
	return true
}

// lookup returns the reverse-path entry for id, if present and not
// expired.
func (ft *forwardingTable) lookup(id [idSize]byte) (*forwardEntry, bool) {
	ft.mu.Lock()
	defer ft.mu.Unlock()
	now := time.Now()
	ft.evictLocked(now)
	e, ok := ft.entries[id]
	if !ok || now.After(e.expiry) {
		return nil, false
	}
	return e, true
}

func (ft *forwardingTable) evictLocked(now time.Time) {
	for id, t := range ft.seen {
		if now.After(t) {
			delete(ft.seen, id)
			delete(ft.entries, id)
		}
	}
	for id, e := range ft.entries {
		if now.After(e.expiry) {
			delete(ft.entries, id)
		}
	}
}
