// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
	"time"
)

// TestForwardQueryThreeEngine is the headline evidence: engine A searches
// through engine B and receives a hit originated by engine C. The QUERY
// traverses A->B->C and the QUERYHIT returns C->B->A, surfacing from
// Engine.Search.
func TestForwardQueryThreeEngine(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "test.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engB, 1)
	waitForPeers(t, engA, 1)
	time.Sleep(200 * time.Millisecond)

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want the hit originated by C routed back through B")
	}
	found := false
	for _, r := range results {
		for _, h := range r.Hits {
			if h.FileName == "test.mp3" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no result carried test.mp3: %+v", results)
	}
}

// TestQueryTTLZeroIsDropped proves a QUERY arriving with TTL 0 is not
// processed (no QUERYHIT comes back). Removing the TTL-0 guard in
// readLoop makes this test go red.
func TestQueryTTLZeroIsDropped(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "test.mp3"},
		},
	})
	r, conn := dialEngine(t, eng.Addr().String())
	defer conn.Close()

	sendMsg(t, conn, Header{ID: testID(0x11), Type: MsgQuery, TTL: 0, Hops: 0,
		Length: uint32(len(EncodeQuery(Query{Search: "test"})))}, EncodeQuery(Query{Search: "test"}))

	// Give the engine time to (wrongly) answer.
	if err := conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if hdr, _, err := readMsgErr(r); err == nil {
		t.Fatalf("a message arrived after a TTL-0 query: type %s", typeName(hdr.Type))
	}
}

// TestQueryOriginExclusionNoEcho proves a forwarded query is not sent
// back to the peer it came from. Removing the origin exclusion in
// forwardQuery makes this test go red.
func TestQueryOriginExclusionNoEcho(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "test.mp3"},
		},
	})
	r, conn := dialEngine(t, eng.Addr().String())
	defer conn.Close()

	q := EncodeQuery(Query{Search: "test"})
	sendMsg(t, conn, Header{ID: testID(0x22), Type: MsgQuery, TTL: 7, Hops: 0, Length: uint32(len(q))}, q)

	// First message should be the local QUERYHIT (or possibly none), never
	// an echoed QUERY.
	gotQuery := false
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		hdr, _, err := readMsgErr(r)
		if err != nil {
			break
		}
		if hdr.Type == MsgQuery {
			gotQuery = true
			break
		}
	}
	if gotQuery {
		t.Fatal("engine echoed the QUERY back to its sender")
	}
}

// TestQueryDedupOnReseenDescriptorID proves a query whose descriptor ID
// has already been seen is dropped and not answered twice. Removing the
// seen-set guard makes this test go red.
func TestQueryDedupOnReseenDescriptorID(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "test.mp3"},
		},
	})
	r, conn := dialEngine(t, eng.Addr().String())
	defer conn.Close()

	id := testID(0x33)
	q := EncodeQuery(Query{Search: "test"})
	h := Header{ID: id, Type: MsgQuery, TTL: 7, Hops: 0, Length: uint32(len(q))}

	sendMsg(t, conn, h, q)
	// first must be answered
	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgQueryHit {
		t.Fatalf("first reply type = %s, want queryhit", typeName(hdr.Type))
	}

	sendMsg(t, conn, h, q)
	// second must not be answered
	if err := conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if hdr2, _, err := readMsgErr(r); err == nil {
		t.Fatalf("duplicate query was answered: type %s", typeName(hdr2.Type))
	}
}

var _ = net.Addr(nil)
