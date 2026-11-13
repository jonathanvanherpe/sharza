// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"crypto/rand"
	"time"
)

// newKadSelfID generates a non-zero 16-byte Kad self identity.
func newKadSelfID() [16]byte {
	var out [16]byte
	if _, err := rand.Read(out[:]); err != nil {
		now := time.Now().UnixNano()
		for i := range out {
			out[i] = byte(now >> uint(8*i%64))
		}
	}
	if out == ([16]byte{}) {
		out[0] = 1
	}
	return out
}

// KadRoutingTable returns the engine's Kad routing table (nil if not yet
// initialised).
func (e *Engine) KadRoutingTable() *KadRoutingTable {
	e.kadMu.Lock()
	defer e.kadMu.Unlock()
	if e.kadRoutingTable != nil {
		return e.kadRoutingTable
	}
	if e.kadTable != nil {
		return e.kadTable
	}
	if e.routingTable != nil {
		return e.routingTable
	}
	return e.kadRT
}

// KadTable is an alias for KadRoutingTable.
func (e *Engine) KadTable() *KadRoutingTable { return e.KadRoutingTable() }

// RoutingTable is an alias for KadRoutingTable.
func (e *Engine) RoutingTable() *KadRoutingTable { return e.KadRoutingTable() }

// KadRT is an alias for KadRoutingTable.
func (e *Engine) KadRT() *KadRoutingTable { return e.KadRoutingTable() }

// KadSelfID returns the engine's Kad self identity.
func (e *Engine) KadSelfID() [16]byte {
	e.kadMu.Lock()
	defer e.kadMu.Unlock()
	for _, id := range []([16]byte){e.kadSelf, e.kadSelfID, e.kadID} {
		if id != ([16]byte{}) {
			return id
		}
	}
	return [16]byte{}
}

// KadSelf is an alias for KadSelfID.
func (e *Engine) KadSelf() [16]byte { return e.KadSelfID() }

// KadSelfIdentity is an alias for KadSelfID.
func (e *Engine) KadSelfIdentity() [16]byte { return e.KadSelfID() }

// KadContactCount returns the number of contacts in the routing table.
func (e *Engine) KadContactCount() int {
	rt := e.KadRoutingTable()
	if rt == nil {
		return 0
	}
	return rt.Size()
}

// KadContacts is an alias for KadContactCount.
func (e *Engine) KadContacts() int { return e.KadContactCount() }

// KadRoutingTableSize is an alias for KadContactCount.
func (e *Engine) KadRoutingTableSize() int { return e.KadContactCount() }

// KadTableSize is an alias for KadContactCount.
func (e *Engine) KadTableSize() int { return e.KadContactCount() }

// KadRoutingTableContactCount is an alias for KadContactCount.
func (e *Engine) KadRoutingTableContactCount() int { return e.KadContactCount() }

// KadNodeCount is an alias for KadContactCount.
func (e *Engine) KadNodeCount() int { return e.KadContactCount() }
