// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
	"time"
)

func TestRouteTableDuplicateAndOrigin(t *testing.T) {
	rt := newRouteTable()
	id := testID(0x11)

	if rt.isDuplicate(id) {
		t.Fatal("fresh id reported duplicate")
	}

	p := &peer{}
	rt.remember(id, p)
	if !rt.isDuplicate(id) {
		t.Fatal("remembered id not duplicate")
	}
	if got := rt.origin(id); got != p {
		t.Fatalf("origin = %v, want %p", got, p)
	}

	// nil origin (local search) round-trips as nil.
	id2 := testID(0x22)
	rt.remember(id2, nil)
	if !rt.isDuplicate(id2) {
		t.Fatal("nil-origin id not duplicate")
	}
	if rt.origin(id2) != nil {
		t.Fatal("nil origin not preserved")
	}
}

func TestRouteTableRememberDoesNotOverwriteOrigin(t *testing.T) {
	rt := newRouteTable()
	id := testID(0x33)
	p1 := &peer{}
	p2 := &peer{}
	rt.remember(id, p1)
	rt.remember(id, p2)
	if got := rt.origin(id); got != p1 {
		t.Fatalf("origin overwritten: got %p want %p", got, p1)
	}
}

func TestRouteTableExpiry(t *testing.T) {
	rt := newRouteTable()
	id := testID(0x44)
	rt.remember(id, &peer{})
	// Force expiry by backdating.
	rt.mu.Lock()
	e := rt.entries[id]
	e.seenAt = time.Now().Add(-routeExpiry - time.Second)
	rt.entries[id] = e
	rt.mu.Unlock()

	if rt.isDuplicate(id) {
		t.Fatal("expired id still duplicate")
	}
	if rt.origin(id) != nil {
		t.Fatal("expired origin not cleared")
	}
}