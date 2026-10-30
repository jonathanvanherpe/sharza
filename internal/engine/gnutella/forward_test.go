// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bufio"
	"net"
	"testing"
	"time"
)

// TestForwardThreeNodeTopology verifies that a QUERY from engine A reaches
// engine C through B, and the resulting QUERYHIT returns to A.
func TestForwardThreeNodeTopology(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 7, Size: 777, Name: "remote.mp3"},
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

	results, err := engA.Search("remote")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits; query did not reach C")
	}
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileName == "remote.mp3" {
				found = true
				if qh.Port != uint16(engC.Addr().(*net.TCPAddr).Port) {
					t.Errorf("hit port = %d, want %d (C)", qh.Port, engC.Addr().(*net.TCPAddr).Port)
				}
				if qh.IP != [4]byte{127, 0, 0, 1} {
					t.Errorf("hit ip = %v, want 127.0.0.1", qh.IP)
				}
			}
		}
	}
	if !found {
		t.Fatalf("remote.mp3 not found in results: %+v", results)
	}
}

// TestForwardDuplicateSuppression checks that a duplicate QUERY is not
// forwarded twice to a downstream peer.
func TestForwardDuplicateSuppression(t *testing.T) {
	// Downstream scripted peer C connected to engine B.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{ln.Addr().String()},
	})
	defer cancelB()

	var downstream net.Conn
	select {
	case downstream = <-accepted:
	case <-time.After(testDeadline):
		t.Fatal("engine B did not dial downstream C")
	}
	defer downstream.Close()
	if err := downstream.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}
	// Complete handshake as a Gnutella peer on downstream side.
	rDown := handshakeAsPeer(t, downstream)

	// Wait for B to register downstream peer.
	waitForPeers(t, engB, 1)
	time.Sleep(100 * time.Millisecond)

	// Scripted client A connects to B and sends the same QUERY twice.
	rA, connA := dialEngine(t, engB.Addr().String())
	defer connA.Close()
	time.Sleep(100 * time.Millisecond)

	id := testID(0x42)
	q := Query{MinSpeed: 0, Search: "dup"}
	payload := EncodeQuery(q)

	// First QUERY.
	sendMsg(t, connA, Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(payload))}, payload)
	// Second duplicate QUERY with same ID.
	sendMsg(t, connA, Header{ID: id, Type: MsgQuery, TTL: 3, Hops: 0, Length: uint32(len(payload))}, payload)

	// Count how many QUERY messages downstream C receives within a window.
	count := 0
	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		if err := downstream.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
			t.Fatal(err)
		}
		hdr, _, err := readMsgErr(rDown)
		if err != nil {
			break
		}
		if hdr.Type == MsgQuery {
			count++
		}
	}
	if count != 1 {
		t.Errorf("downstream received %d forwarded QUERYs, want 1 (duplicate suppressed)", count)
	}
	_ = rA
}

// TestForwardTTLExpiry checks that a QUERY with TTL 1 is not forwarded.
func TestForwardTTLExpiry(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{ln.Addr().String()},
	})
	defer cancelB()

	var downstream net.Conn
	select {
	case downstream = <-accepted:
	case <-time.After(testDeadline):
		t.Fatal("engine B did not dial downstream C")
	}
	defer downstream.Close()
	if err := downstream.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}
	rDown := handshakeAsPeer(t, downstream)

	waitForPeers(t, engB, 1)
	time.Sleep(100 * time.Millisecond)

	rA, connA := dialEngine(t, engB.Addr().String())
	defer connA.Close()
	time.Sleep(100 * time.Millisecond)

	id := testID(0x77)
	q := Query{MinSpeed: 0, Search: "ttl"}
	payload := EncodeQuery(q)
	sendMsg(t, connA, Header{ID: id, Type: MsgQuery, TTL: 1, Hops: 0, Length: uint32(len(payload))}, payload)

	// Downstream should receive nothing within the window.
	if err := downstream.SetReadDeadline(time.Now().Add(400 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readMsgErr(rDown); err == nil {
		t.Fatal("downstream received a forwarded QUERY, want TTL expiry drop")
	}
	_ = rA
}

// handshakeAsPeer completes the server-side handshake from a scripted peer's
// perspective where the engine dialed us: we are the accepting side, reading
// the engine's CONNECT and replying 200. Returns a reader positioned at
// binary messages.
func handshakeAsPeer(t *testing.T, conn net.Conn) *bufio.Reader {
	t.Helper()
	r := bufio.NewReader(conn)
	hs, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("read connect: %v", err)
	}
	if !hs.Request {
		t.Fatalf("expected connect request, got %s", hs.Status())
	}
	if _, err := conn.Write([]byte("GNUTELLA/0.6 200 OK\r\n\r\n")); err != nil {
		t.Fatalf("write 200: %v", err)
	}
	// engine sends confirmation
	cf, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("read confirmation: %v", err)
	}
	if !cf.IsOK() {
		t.Fatalf("confirmation = %s, want 200", cf.Status())
	}
	return r
}
