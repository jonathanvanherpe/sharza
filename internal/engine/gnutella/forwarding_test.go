// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestMarkSeenQuerySuppressesDuplicate(t *testing.T) {
	eng := New()
	id := testID(0x11)
	if eng.isSeenQuery(id) {
		t.Fatal("unseen id reported seen")
	}
	eng.markSeenQuery(id)
	if !eng.isSeenQuery(id) {
		t.Fatal("marked id reported unseen")
	}
	// second mark is idempotent and stays seen
	eng.markSeenQuery(id)
	if !eng.isSeenQuery(id) {
		t.Fatal("re-marked id reported unseen")
	}
}

func TestSeenQueryExpiry(t *testing.T) {
	eng := New()
	id := testID(0x22)
	eng.markSeenQuery(id, 50*time.Millisecond)
	if !eng.isSeenQuery(id) {
		t.Fatal("marked id reported unseen")
	}
	time.Sleep(120 * time.Millisecond)
	if eng.isSeenQuery(id) {
		t.Fatal("expired id still reported seen")
	}
}

func TestRecordUpstreamAndUpstreamFor(t *testing.T) {
	eng := New()
	id := testID(0x33)
	if eng.upstreamFor(id) != nil {
		t.Fatal("expected nil upstream before recording")
	}
	pc := &peerConn{}
	eng.recordUpstream(id, pc)
	if got := eng.upstreamFor(id); got != pc {
		t.Fatalf("upstream = %v, want %v", got, pc)
	}
}

func TestSnapshotPeersExcept(t *testing.T) {
	eng := New()
	pc1 := &peerConn{}
	pc2 := &peerConn{}
	pc3 := &peerConn{}
	eng.mu.Lock()
	eng.peers[pc1] = struct{}{}
	eng.peers[pc2] = struct{}{}
	eng.peers[pc3] = struct{}{}
	eng.mu.Unlock()

	got := eng.snapshotPeersExcept(pc2)
	if len(got) != 2 {
		t.Fatalf("len = %d, want 2", len(got))
	}
	for _, pc := range got {
		if pc == pc2 {
			t.Fatal("excluded peer present in snapshot")
		}
	}
	// nil origin returns all
	if got := eng.snapshotPeersExcept(nil); len(got) != 3 {
		t.Fatalf("nil origin len = %d, want 3", len(got))
	}
}

// TestSecondHopReachabilityAndReversePath proves that a QUERY issued by
// engine A reaches engine C through B, and that C's QUERYHIT is routed
// back to A along the reverse path.
func TestSecondHopReachabilityAndReversePath(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "found.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()
	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	var (
		mu   sync.Mutex
		seen int
	)
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Peers:             []string{engB.Addr().String()},
		OnQueryHit: func(_ net.Addr, _ [idSize]byte, _ QueryHit) {
			mu.Lock()
			seen++
			mu.Unlock()
		},
	})
	defer cancelA()
	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("found")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want the forwarded QUERYHIT from C")
	}
	found := false
	for _, r := range results {
		for _, h := range r.Hits {
			if h.FileName == "found.mp3" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("no result carried found.mp3: %+v", results)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Error("OnQueryHit was not called for the reverse-routed hit")
	}
}

// TestDuplicateSuppressionOnForwarding ensures a query arriving twice on
// different paths is not answered twice.
func TestDuplicateSuppressionOnForwarding(t *testing.T) {
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 10, Name: "dup.mp3"},
		},
	})
	defer cancelB()

	// Two scripted peers both send the same QUERY (same descriptor ID).
	r1, conn1 := dialEngine(t, engB.Addr().String())
	defer conn1.Close()
	r2, conn2 := dialEngine(t, engB.Addr().String())
	defer conn2.Close()
	waitForPeers(t, engB, 2)

	id := testID(0x77)
	q := Query{MinSpeed: 0, Search: "dup"}
	payload := EncodeQuery(q)
	qhdr := Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(payload))}

	sendMsg(t, conn1, qhdr, payload)
	// first answer
	h1, _ := readMsg(t, r1)
	if h1.Type != MsgQueryHit {
		t.Fatalf("first peer: type = %s, want queryhit", typeName(h1.Type))
	}

	// Drain the forwarded copy of the first query that the engine sends
	// to the second peer, if it has arrived.
	time.Sleep(200 * time.Millisecond)
	if err := conn2.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if hdr, _, err := readMsgErr(r2); err == nil && hdr.Type == MsgQuery {
		// consumed forwarded query
	}

	// second copy, same descriptor ID: suppressed, no queryhit.
	sendMsg(t, conn2, qhdr, payload)
	if err := conn2.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if hdr, _, err := readMsgErr(r2); err == nil {
		if hdr.Type == MsgQueryHit {
			t.Fatal("duplicate query was answered, want suppression")
		}
	}
}
