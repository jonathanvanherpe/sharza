// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
	"time"
)

func waitForPeersN(t *testing.T, eng *Engine, want int) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for {
		eng.mu.Lock()
		n := len(eng.peers)
		eng.mu.Unlock()
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("engine has %d peers, want at least %d", n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestForwardingThreeEngineChain: A -> B -> C, C has the file, A's search
// gets the hit back.
func TestForwardingThreeEngineChain(t *testing.T) {
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

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeersN(t, engB, 1)
	waitForPeersN(t, engA, 1)
	time.Sleep(200 * time.Millisecond)

	results, err := engA.Search("found")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileName == "found.mp3" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("Search did not return found.mp3; got %+v", results)
	}
}

// TestDuplicateSuppressionAnsweredOnce: a looped query (same descriptor
// ID sent twice) is answered only once.
func TestDuplicateSuppressionAnsweredOnce(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 100, Name: "loop.mp3"},
		},
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeersN(t, eng, 1)
	// waitForPeers counts inbound? Engine peers includes inbound peerConn, yes.

	id := testID(0x42)
	q := EncodeQuery(Query{MinSpeed: 0, Search: "loop"})
	// First query.
	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(q))}, q)
	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgQueryHit {
		t.Fatalf("first reply type = %s, want queryhit", typeName(hdr.Type))
	}
	// Second query with same ID should be dropped: no reply.
	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(q))}, q)
	if err := conn.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMsgErr(r); err == nil {
		t.Fatal("duplicate query was answered a second time")
	}
}
