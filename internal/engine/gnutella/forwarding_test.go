// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestQueryPropagatesTwoHops proves a QUERY reaches a peer two hops
// away and the origin receives the leaf's QUERYHIT.
func TestQueryPropagatesTwoHops(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "leaf.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		Listen:            "127.0.0.1:0",
		Peers:             []string{engC.Addr().String()},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
	})
	defer cancelB()
	waitForPeers(t, engB, 1)

	engA, cancelA := startEngine(t, Options{
		Listen:            "127.0.0.1:0",
		Peers:             []string{engB.Addr().String()},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
	})
	defer cancelA()
	waitForPeers(t, engA, 1)
	time.Sleep(200 * time.Millisecond)

	results, err := engA.Search("leaf")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileName == "leaf.mp3" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("origin did not receive leaf's QUERYHIT: %+v", results)
	}
}

// TestDuplicateQuerySuppressed proves a duplicate QUERY is dropped.
func TestDuplicateQuerySuppressed(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 1, Name: "x.mp3"},
		},
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	id := testID(0x77)
	q := Query{MinSpeed: 0, Search: "x"}
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
		t.Fatal("duplicate query produced a reply")
	}
}

// TestQueryTTL1StopsForwarding proves a QUERY with TTL 1 is not forwarded.
func TestQueryTTL1StopsForwarding(t *testing.T) {
	// Scripted peer C that records any QUERY it receives.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	received := make(chan struct{}, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
			return
		}
		r := bufio.NewReader(conn)
		hs, err := ReadHandshake(r)
		if err != nil || !hs.Request {
			return
		}
		if _, err := conn.Write(OKReply()); err != nil {
			return
		}
		confirm, err := ReadHandshake(r)
		if err != nil || !confirm.IsOK() {
			return
		}
		for {
			hdr, payload, err := readMsgErr(r)
			if err != nil {
				return
			}
			if hdr.Type == MsgQuery {
				if _, err := DecodeQuery(payload); err == nil {
					select {
					case received <- struct{}{}:
					default:
					}
				}
			}
		}
	}()

	engB, cancelB := startEngine(t, Options{
		Listen:            "127.0.0.1:0",
		Peers:             []string{ln.Addr().String()},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	defer cancelB()
	waitForPeers(t, engB, 1)
	time.Sleep(200 * time.Millisecond)

	// Send a TTL 1 QUERY to B via a scripted client.
	r, conn := dialEngine(t, engB.Addr().String())
	waitForPeers(t, engB, 1)
	id := testID(0x99)
	q := Query{MinSpeed: 0, Search: "leaf"}
	payload := EncodeQuery(q)
	hdr := Header{ID: id, Type: MsgQuery, TTL: 1, Hops: 0, Length: uint32(len(payload))}
	sendMsg(t, conn, hdr, payload)
	// B answers locally.
	h, _ := readMsg(t, r)
	if h.Type != MsgQueryHit {
		t.Fatalf("reply type = %s, want queryhit", typeName(h.Type))
	}

	// C should not receive a forwarded QUERY.
	select {
	case <-received:
		t.Fatal("QUERY with TTL 1 was forwarded")
	case <-time.After(500 * time.Millisecond):
	}
}