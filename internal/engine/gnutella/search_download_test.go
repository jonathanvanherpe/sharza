// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the smallest end-to-end artifact for
// the "completes a search and a download" half of the P1 exit gate: one
// engine, a scripted peer answering its QUERY with a QUERYHIT that names
// an httptest servent, and a Fetch that writes the served bytes to disk.
// No production code is exercised beyond the already-landed Search and
// Downloader primitives.

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1234
	)
	content := testContent(size)

	// httptest servent: speaks real HTTP over a real TCP port, which is
	// exactly what a live Gnutella servent does for /gnutella/<index>.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	var (
		mu         sync.Mutex
		callbackID [idSize]byte
		callbackN  int
	)
	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		OnQueryHit: func(_ net.Addr, id [idSize]byte, _ QueryHit) {
			mu.Lock()
			defer mu.Unlock()
			callbackN++
			callbackID = id
		},
	})
	defer cancel()

	// Scripted peer dials the engine and completes the 0.6 handshake.
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	type searchResult struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan searchResult, 1)
	go func() {
		hits, err := eng.Search("needle")
		resCh <- searchResult{hits, err}
	}()

	// The engine's QUERY arrives; capture its descriptor ID so the reply
	// echoes it (that echo is what makes the registry attribute the hit).
	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}
	queryID := hdr.ID

	// Answer with a QUERYHIT whose IP/Port name the httptest servent.
	qh, _ := hitFor(t, srv, index, size, "song.mp3")
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: queryID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT echoing its descriptor ID")
	}
	gotQH := res.hits[0]
	if gotQH.HitCount < 1 || len(gotQH.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", gotQH)
	}
	if gotQH.Hits[0].FileName != "song.mp3" {
		t.Errorf("filename = %q, want %q", gotQH.Hits[0].FileName, "song.mp3")
	}

	// The callback is a separate surface and must see the same hit under
	// the descriptor ID the QUERY used.
	mu.Lock()
	seen := callbackN
	seenID := callbackID
	mu.Unlock()
	if seen == 0 {
		t.Error("OnQueryHit was not called for the matching QUERYHIT")
	}
	if seenID != queryID {
		t.Errorf("callback id = %x, want the QUERY's descriptor id %x", seenID, queryID)
	}

	// Now compose: the hit Search returned names the servent, so
	// Engine.Downloader(...).Fetch must write the full served bytes.
	gotHit := gotQH.Hits[0]
	d := eng.Downloader(gotQH, gotHit)
	dir := t.TempDir()
	fetchRes, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fetchRes.Bytes != int64(size) {
		t.Errorf("Fetch Bytes = %d, want %d", fetchRes.Bytes, size)
	}
	onDisk, err := os.ReadFile(fetchRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}