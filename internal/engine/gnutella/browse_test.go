// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Browse tests assert on Browse's return value, not only the OnQueryHit
// callback: the engine-level evidence for "one engine can list another
// node's shares" is that the hits a BH QUERY draws back come out of the
// call that sent the QUERY. The two-engine pair proves the end-to-end
// path; the scripted-peer tests make the wire shape (BH extension, empty
// criteria) and the descriptor-ID correlation observable and mutation-
// testable.

import (
	"net"
	"sync"
	"testing"
	"time"
)

// TestBrowseReturnsCatalogueFromTwoEnginePair is the end-to-end evidence:
// engine B shares a catalogue, engine A dials it and browses, and A's
// Browse call returns exactly B's files.
func TestBrowseReturnsCatalogueFromTwoEnginePair(t *testing.T) {
	catalogue := []FileEntry{
		{Index: 1, Size: 12345, Name: "first.mp3"},
		{Index: 2, Size: 987654321, Name: "second.iso"},
	}
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue:         catalogue,
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

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Browse()
	if err != nil {
		t.Fatalf("Browse failed: %v", err)
	}
	if len(results) != 1 {
		t.Fatalf("Browse returned %d QueryHits, want the 1 answering its BH QUERY", len(results))
	}
	qh := results[0]
	if qh.Port != uint16(engB.Addr().(*net.TCPAddr).Port) {
		t.Errorf("port = %d, want %d", qh.Port, engB.Addr().(*net.TCPAddr).Port)
	}
	if qh.IP != [4]byte{127, 0, 0, 1} {
		t.Errorf("ip = %v, want 127.0.0.1", qh.IP)
	}
	if len(qh.Hits) != len(catalogue) {
		t.Fatalf("hit count = %d, want %d", len(qh.Hits), len(catalogue))
	}
	for i, want := range catalogue {
		got := qh.Hits[i]
		if got.FileIndex != want.Index || got.FileSize != want.Size || got.FileName != want.Name {
			t.Errorf("hit %d = %+v, want index=%d size=%d name=%q",
				i, got, want.Index, want.Size, want.Name)
		}
	}

	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Error("OnQueryHit was not called for the browse QUERYHIT")
	}
}

// TestBrowseSendsBHQueryAndCollectsHits reads the outbound QUERY on a
// scripted 0.6 peer and asserts the browse wire shape before answering:
// empty criteria followed by a GGEP block carrying the BH marker. This is
// the test that goes red if the BH extension is dropped from Browse.
func TestBrowseSendsBHQueryAndCollectsHits(t *testing.T) {
	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})
	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Browse()
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if hdr.TTL != browseTTL {
		t.Errorf("browse QUERY TTL = %d, want %d", hdr.TTL, browseTTL)
	}
	q, err := DecodeQuery(payload)
	if err != nil {
		t.Fatalf("query payload: %v", err)
	}
	if q.Search != "" {
		t.Errorf("browse QUERY criteria = %q, want empty", q.Search)
	}
	exts, err := DecodeGGEP(q.Extensions)
	if err != nil {
		t.Fatalf("browse QUERY extensions: %v", err)
	}
	if len(exts) != 1 || exts[0].ID != browseExtension {
		t.Fatalf("browse QUERY extensions = %+v, want the %q marker", exts, browseExtension)
	}

	qh := QueryHit{
		HitCount: 2,
		Port:     1234,
		IP:       [4]byte{127, 0, 0, 1},
		Hits: []FileHit{
			{FileIndex: 1, FileSize: 100, FileName: "one.bin"},
			{FileIndex: 2, FileSize: 200, FileName: "two.bin"},
		},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Browse failed: %v", res.err)
	}
	if len(res.hits) != 1 || len(res.hits[0].Hits) != 2 {
		t.Fatalf("Browse returned %+v, want one hit with two files", res.hits)
	}
	if res.hits[0].Hits[0].FileName != "one.bin" || res.hits[0].Hits[1].FileName != "two.bin" {
		t.Errorf("files = %+v, want one.bin and two.bin", res.hits[0].Hits)
	}
}

// TestBrowseIgnoresQueryHitWithNonMatchingDescriptorID proves the
// descriptor-ID correlation holds for Browse too: a QUERYHIT under an ID
// the browse QUERY never used must not be attributed to it.
func TestBrowseIgnoresQueryHitWithNonMatchingDescriptorID(t *testing.T) {
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
	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Browse()
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
		HitCount: 1,
		Port:     1234,
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 9, FileSize: 9, FileName: "wrong.mp3"}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: bogus, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Browse failed: %v", res.err)
	}
	if len(res.hits) != 0 {
		t.Errorf("Browse returned %d hits under a non-matching descriptor ID, want 0", len(res.hits))
	}

	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Fatal("OnQueryHit was not called for the QUERYHIT")
	}
	if seenID != bogus {
		t.Errorf("callback id = %x, want the QUERYHIT's own id %x", seenID, bogus)
	}
}

// TestBrowseTimeoutReturnsPartialHits pins the timeout path for Browse: of
// two live peers, one answers and one stays silent, and Browse returns the
// hit it collected with no error.
func TestBrowseTimeoutReturnsPartialHits(t *testing.T) {
	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     600 * time.Millisecond,
	})

	ansR, ansConn := dialEngine(t, engA.Addr().String())
	_, silentConn := dialEngine(t, engA.Addr().String())
	defer silentConn.Close()

	waitForPeers(t, engA, 2)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Browse()
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
		HitCount: 1,
		Port:     1234,
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 7, FileSize: 100, FileName: "partial.mp3"}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, ansConn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Browse failed: %v", res.err)
	}
	if len(res.hits) != 1 {
		t.Fatalf("Browse returned %d hits, want the 1 from the peer that answered", len(res.hits))
	}
	if got := res.hits[0].Hits[0].FileName; got != "partial.mp3" {
		t.Errorf("filename = %q, want %q", got, "partial.mp3")
	}
}
