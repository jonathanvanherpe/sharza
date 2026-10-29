// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"testing"
	"time"
)

func TestForwardQueryAndHitRouting(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
		Catalogue:         []FileEntry{},
	})
	// Two scripted peers dial in.
	rA, connA := dialEngine(t, eng.Addr().String())
	rB, connB := dialEngine(t, eng.Addr().String())

	id := testID(0x42)

	// A sends a QUERY with TTL 3.
	q := Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0}
	payload := EncodeQuery(Query{MinSpeed: 0, Search: "foo"})
	q.Length = uint32(len(payload))
	sendMsg(t, connA, q, payload)

	// B should receive the forwarded QUERY with TTL 2, Hops 1.
	hdr, gotPayload := readMsg(t, rB)
	if hdr.Type != MsgQuery {
		t.Fatalf("B got type %s, want query", typeName(hdr.Type))
	}
	if hdr.ID != id {
		t.Fatalf("B got id %x, want %x", hdr.ID, id)
	}
	if hdr.TTL != 2 {
		t.Fatalf("B got TTL %d, want 2", hdr.TTL)
	}
	if hdr.Hops != 1 {
		t.Fatalf("B got Hops %d, want 1", hdr.Hops)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("B payload mismatch")
	}

	// B replies with a QUERYHIT.
	qh := QueryHit{HitCount: 1, Port: 1234, IP: [4]byte{127, 0, 0, 1}, Speed: 1, Hits: []FileHit{{FileIndex: 7, FileSize: 9, FileName: "f"}}}
	hitPayload := EncodeQueryHit(qh)
	rh := Header{ID: id, Type: MsgQueryHit, TTL: 2, Hops: 0, Length: uint32(len(hitPayload))}
	sendMsg(t, connB, rh, hitPayload)

	// A first receives the local QUERYHIT, then the routed one.
	localHdr, _ := readMsg(t, rA)
	if localHdr.Type != MsgQueryHit {
		t.Fatalf("A got type %s, want queryhit", typeName(localHdr.Type))
	}
	hdr2, _ := readMsg(t, rA)
	if hdr2.Type != MsgQueryHit {
		t.Fatalf("A got type %s, want queryhit", typeName(hdr2.Type))
	}
	if hdr2.ID != id {
		t.Fatalf("A got id %x, want %x", hdr2.ID, id)
	}
	if hdr2.TTL != 1 {
		t.Fatalf("A got TTL %d, want 1", hdr2.TTL)
	}
}

func TestForwardDuplicateSuppressed(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
		Catalogue:         []FileEntry{},
	})
	rA, connA := dialEngine(t, eng.Addr().String())
	rB, connB := dialEngine(t, eng.Addr().String())
	_ = rA

	id := testID(0x43)
	payload := EncodeQuery(Query{MinSpeed: 0, Search: "bar"})
	q := Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(payload))}

	// First query forwarded to B.
	sendMsg(t, connA, q, payload)
	hdr, _ := readMsg(t, rB)
	if hdr.Type != MsgQuery {
		t.Fatalf("first: B got %s", typeName(hdr.Type))
	}

	// Duplicate query should not be forwarded; B's read should time out.
	sendMsg(t, connA, q, payload)
	connB.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err := readMsgErr(rB)
	if err == nil {
		t.Fatalf("duplicate query was forwarded to B")
	}
}

func TestForwardTTL1NotForwarded(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
		Catalogue:         []FileEntry{{Index: 1, Size: 2, Name: "x"}},
	})
	rA, connA := dialEngine(t, eng.Addr().String())
	rB, connB := dialEngine(t, eng.Addr().String())
	_ = rB

	id := testID(0x44)
	payload := EncodeQuery(Query{MinSpeed: 0, Search: "baz"})
	q := Header{ID: id, Type: MsgQuery, TTL: 1, Hops: 0, Length: uint32(len(payload))}
	sendMsg(t, connA, q, payload)

	// A should get a local QUERYHIT (TTL clamped to 1).
	hdr, _ := readMsg(t, rA)
	if hdr.Type != MsgQueryHit {
		t.Fatalf("A got %s, want queryhit", typeName(hdr.Type))
	}

	// B should receive nothing; read times out.
	connB.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
	_, _, err := readMsgErr(rB)
	if err == nil {
		t.Fatalf("TTL 1 query was forwarded to B")
	}
}
