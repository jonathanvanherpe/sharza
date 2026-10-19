// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Search tests assert on Search's return value, not only the OnQueryHit
// callback: the engine-level evidence for the "completes a search" leg of
// P1 is that the hits a QUERYHIT answers come back from the call that sent
// the QUERY. The matching-ID test is the two-engine scripted pair over
// real TCP (engine B answers engine A); the other two use a scripted 0.6
// client so a QUERYHIT with a wrong ID, and a peer that stays silent, can
// be arranged deterministically.

import (
	"net"
	"sync"
	"testing"
	"time"
)

// waitForPeers waits until the engine holds at least want live peer
// connections. Search writes only to registered peers, so a test must not
// search through a peer the dial loop has not registered yet.
func waitForPeers(t *testing.T, eng *Engine, want int) {
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

// TestSearchReturnsQueryHitWithMatchingDescriptorID is the two-engine
// pair: engine B shares a catalogue, engine A dials it and searches, and
// the QUERYHIT answering that QUERY comes back from Search itself.
func TestSearchReturnsQueryHitWithMatchingDescriptorID(t *testing.T) {
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "test.mp3"},
		},
	})
	defer cancelB()

	var (
		mu   sync.Mutex
		seen int
	)
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
		OnQueryHit: func(_ net.Addr, _ [idSize]byte, _ QueryHit) {
			mu.Lock()
			seen++
			mu.Unlock()
		},
	})
	defer cancelA()

	// The dial loop connects asynchronously; searching before the
	// handshake finished would write QUERY bytes into the handshake.
	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT echoing its descriptor ID")
	}
	qh := results[0]
	if qh.HitCount < 1 || len(qh.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", qh)
	}
	if qh.Hits[0].FileName != "test.mp3" {
		t.Errorf("filename = %q, want %q", qh.Hits[0].FileName, "test.mp3")
	}
	if qh.Port != uint16(engB.Addr().(*net.TCPAddr).Port) {
		t.Errorf("port = %d, want %d", qh.Port, engB.Addr().(*net.TCPAddr).Port)
	}
	if qh.IP != [4]byte{127, 0, 0, 1} {
		t.Errorf("ip = %v, want 127.0.0.1", qh.IP)
	}
	// The QUERYHIT that answered over the wire must carry a servent
	// ID: the mandatory 16-byte GUID between Speed and the hits,
	// generated once per engine run and tagged like a descriptor ID.
	if qh.ServentID == ([idSize]byte{}) {
		t.Error("servent id is all zeros, want engine B's per-run servent GUID")
	}
	if qh.ServentID[8] != guidNetworkID || qh.ServentID[15] != guidReserved {
		t.Errorf("servent id %x is not GUID-tagged (byte 8 want 0x%02x, byte 15 want 0x%02x)",
			qh.ServentID, guidNetworkID, guidReserved)
	}

	// The callback is a separate surface and must still see the same hit.
	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Error("OnQueryHit was not called for the matching QUERYHIT")
	}
}

// TestSearchIgnoresQueryHitWithNonMatchingDescriptorID proves the
// descriptor ID is the correlation key: a peer answers with a QUERYHIT
// under an ID the QUERY never used, and that hit must not appear in
// Search's results. It is still received and still reaches OnQueryHit;
// only the registry refuses to attribute it to this search.
func TestSearchIgnoresQueryHitWithNonMatchingDescriptorID(t *testing.T) {
	var (
		mu     sync.Mutex
		seen   int
		seenID [idSize]byte
	)
	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		OnQueryHit: func(_ net.Addr, id [idSize]byte, _ QueryHit) {
			mu.Lock()
			seen++
			seenID = id
			mu.Unlock()
		},
	})
	// A scripted 0.6 client links to the engine and answers the QUERY
	// that comes back at it.
	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Search("test")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	bogus := testID(0x5A)
	if hdr.ID == bogus {
		t.Fatal("test setup: random descriptor ID collided with the bogus one")
	}
	qh := QueryHit{
		HitCount:  1,
		Port:      1234,
		IP:        [4]byte{127, 0, 0, 1},
		ServentID: testID(0x5A),
		Hits:      []FileHit{{FileIndex: 9, FileSize: 9, FileName: "wrong.mp3"}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: bogus, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) != 0 {
		t.Errorf("Search returned %d hits under a non-matching descriptor ID, want 0", len(res.hits))
	}

	// The hit was still received; the callback must see it with the ID it
	// actually carried.
	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Fatal("OnQueryHit was not called for the QUERYHIT")
	}
	if seenID != bogus {
		t.Errorf("callback id = %x, want the QUERYHIT's own id %x", seenID, bogus)
	}
}

// TestSearchTimeoutReturnsPartialHits pins the timeout path: of two live
// peers, one answers and one stays silent. Search must run out its window
// and return exactly the hit it collected, with no error. The answer is
// delayed so it lands inside the window, not before Search starts waiting:
// a Search that returned as soon as its writes finished would miss it.
func TestSearchTimeoutReturnsPartialHits(t *testing.T) {
	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     600 * time.Millisecond,
	})

	// The answering peer reads the QUERY and replies after a delay.
	ansR, ansConn := dialEngine(t, engA.Addr().String())
	// The silent peer completes the handshake and then never answers; its
	// QUERY just sits in the socket buffer.
	_, silentConn := dialEngine(t, engA.Addr().String())
	defer silentConn.Close()

	waitForPeers(t, engA, 2)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Search("partial")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, ansR)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	// Answer mid-window: only the timeout wait can collect this hit.
	time.Sleep(250 * time.Millisecond)
	qh := QueryHit{
		HitCount:  1,
		Port:      1234,
		IP:        [4]byte{127, 0, 0, 1},
		ServentID: testID(0x77),
		Hits:      []FileHit{{FileIndex: 7, FileSize: 100, FileName: "partial.mp3"}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, ansConn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) != 1 {
		t.Fatalf("Search returned %d hits, want the 1 from the peer that answered (the other stayed silent)",
			len(res.hits))
	}
	if got := res.hits[0].Hits[0].FileName; got != "partial.mp3" {
		t.Errorf("filename = %q, want %q", got, "partial.mp3")
	}
}
