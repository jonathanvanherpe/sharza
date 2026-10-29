// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
	"time"
)

// TestForwardingThreeEngineChain: a query from A traverses B to reach C
// two hops away, and C's QUERYHIT returns to A's Search.
func TestForwardingThreeEngineChain(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 7, Size: 777, Name: "found.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Peers:            []string{engC.Addr().String()},
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Peers:            []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	waitForPeers(t, engB, 2)
	time.Sleep(200 * time.Millisecond)

	results, err := engA.Search("found")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits; query did not traverse two hops")
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
		t.Errorf("found.mp3 not in results: %+v", results)
	}
	_ = net.IP{}
}

// TestForwardingDuplicateSuppression: a repeated query with the same
// descriptor ID is answered only once.
func TestForwardingDuplicateSuppression(t *testing.T) {
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 100, Name: "loop.mp3"},
		},
	})
	defer cancelA()

	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)

	id := testID(0x42)
	q := Query{MinSpeed: 0, Search: "loop"}
	payload := EncodeQuery(q)
	hdr := Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(payload))}

	sendMsg(t, conn, hdr, payload)
	h1, _ := readMsg(t, r)
	if h1.Type != MsgQueryHit {
		t.Fatalf("first reply type = %s, want queryhit", typeName(h1.Type))
	}

	sendMsg(t, conn, hdr, payload)
	if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMsgErr(r); err == nil {
		t.Fatal("duplicate query was answered again")
	}
	_ = cancelA
}
