// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
	"time"
)

// TestForwardQueryReachesPeerAndReturnsHit: a 3-node chain A->B->C. A
// searches; the QUERY propagates to C via B, and C's QUERYHIT returns to
// A via the reverse path.
func TestForwardQueryReachesPeerAndReturnsHit(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 7, Size: 100, Name: "forward.mp3"},
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
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	waitForPeers(t, engB, 2)
	waitForPeers(t, engC, 1)
	time.Sleep(200 * time.Millisecond)

	results, err := engA.Search("forward")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits; QUERY did not reach C or hit did not return")
	}
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileName == "forward.mp3" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("hits = %+v, want forward.mp3", results)
	}
}

// TestForwardDuplicateQuerySuppressed: a QUERY with an ID already seen is
// dropped with no reply and no forward.
func TestForwardDuplicateQuerySuppressed(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 1, Name: "dup.mp3"},
		},
	})

	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	payload := EncodeQuery(Query{Search: "dup"})
	id := testID(0x42)
	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(payload))}, payload)

	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgQueryHit {
		t.Fatalf("first reply type = %s, want queryhit", typeName(hdr.Type))
	}

	// Duplicate: same descriptor ID.
	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(payload))}, payload)

	if err := conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMsgErr(r); err == nil {
		t.Fatal("duplicate query produced a reply; expected drop")
	}
}

// TestForwardTTLExpiryDropsReverseHit: a QUERY arriving with TTL 2 is
// forwarded with TTL 1; the peer that answers replies with TTL 0 (clamped
// to 1), and the reverse-path forward drops it, so the origin receives no
// hit from that peer.
func TestForwardTTLExpiryDropsReverseHit(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 2, Size: 2, Name: "ttl.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()

	r, conn := dialEngine(t, engB.Addr().String())
	waitForPeers(t, engB, 2)
	time.Sleep(200 * time.Millisecond)

	qpayload := EncodeQuery(Query{Search: "ttl"})
	id := testID(0x77)
	sendMsg(t, conn, Header{ID: id, Type: MsgQuery, TTL: 2, Hops: 0, Length: uint32(len(qpayload))}, qpayload)

	// B's own (empty) reply.
	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQueryHit {
		t.Fatalf("first reply type = %s, want queryhit", typeName(hdr.Type))
	}
	qh, _ := DecodeQueryHit(payload)
	if len(qh.Hits) != 0 {
		t.Errorf("expected empty local hit, got %d", len(qh.Hits))
	}

	// No forwarded hit from C should arrive.
	if err := conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if hdr2, payload2, err := readMsgErr(r); err == nil {
		if hdr2.Type == MsgQueryHit {
			qh2, _ := DecodeQueryHit(payload2)
			if len(qh2.Hits) > 0 {
				t.Fatalf("TTL-expired reverse hit reached origin: %d hits", len(qh2.Hits))
			}
		}
		_ = hdr2
	} else {
		// timeout: expected
	}
}

