// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
	"time"
)

// TestQueryForwardingReachesIndirectPeer is the three-peer chain (A-B-C):
// a query originating at A is forwarded by B and answered by C, and the
// QUERYHIT travels back through B to A.
func TestQueryForwardingReachesIndirectPeer(t *testing.T) {
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

	waitForPeers(t, engA, 1)
	waitForPeers(t, engB, 2)
	waitForPeers(t, engC, 1)
	time.Sleep(200 * time.Millisecond)

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT forwarded from C")
	}
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileName == "test.mp3" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no hit named test.mp3 in %+v", results)
	}
}

// TestQueryForwardingDropsDuplicate verifies that a second QUERY carrying
// the same descriptor ID is not forwarded (C is reached only once).
func TestQueryForwardingDropsDuplicate(t *testing.T) {
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
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()

	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	r, conn := dialEngine(t, engB.Addr().String())
	defer conn.Close()

	id := testID(0x42)
	q := Query{MinSpeed: 0, Search: "test"}
	payload := EncodeQuery(q)

	// Send the same descriptor ID twice.
	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 7, Hops: 0, Length: uint32(len(payload))}, payload)
	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 7, Hops: 0, Length: uint32(len(payload))}, payload)

	// Count how many QUERYHITs carrying test.mp3 come back.
	count := 0
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			break
		}
		hdr, pl, err := readMsgErr(r)
		if err != nil {
			break
		}
		if hdr.Type == MsgQueryHit {
			qh, err := DecodeQueryHit(pl)
			if err == nil {
				for _, h := range qh.Hits {
					if h.FileName == "test.mp3" {
						count++
					}
				}
			}
		}
	}
	if count != 1 {
		t.Fatalf("received %d forwarded hits, want 1 (duplicate dropped)", count)
	}
}

// TestQueryForwardingNoForwardWhenTTLAtMostOne verifies that a QUERY with
// TTL 1 is answered locally but never reaches the indirect peer.
func TestQueryForwardingNoForwardWhenTTLAtMostOne(t *testing.T) {
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
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()

	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	r, conn := dialEngine(t, engB.Addr().String())
	defer conn.Close()

	id := testID(0x77)
	q := Query{MinSpeed: 0, Search: "test"}
	payload := EncodeQuery(q)

	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 1, Hops: 0, Length: uint32(len(payload))}, payload)

	// B answers locally (empty catalogue -> empty hit). C must not be reached,
	// so no hit carrying test.mp3 may arrive.
	gotTest := false
	deadline := time.Now().Add(1 * time.Second)
	for time.Now().Before(deadline) {
		if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
			break
		}
		hdr, pl, err := readMsgErr(r)
		if err != nil {
			break
		}
		if hdr.Type == MsgQueryHit {
			qh, err := DecodeQueryHit(pl)
			if err == nil {
				for _, h := range qh.Hits {
					if h.FileName == "test.mp3" {
						gotTest = true
					}
				}
			}
		}
	}
	if gotTest {
		t.Fatal("indirect peer was reached despite TTL 1")
	}
}
