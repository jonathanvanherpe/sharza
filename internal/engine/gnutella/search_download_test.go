// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the smallest end-to-end proof that
// Engine.Search and Downloader.Fetch (via Engine.Downloader) compose into
// one completed transfer: a QUERY goes out over a real Gnutella 0.6 link,
// the peer answers with a QUERYHIT naming a file served over HTTP, Search
// returns that hit, and Fetch moves the named bytes onto disk. No job
// store, no scheduler, no RPC surface: just the two primitives joined by
// the hit they share.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	// The file the search result will point at. A real TCP listener
	// (httptest) serves it, so the download half exercises the same
	// net/http path a live servent would take.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/7" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	// A QueryHit naming srv as its source, built the same way the
	// download tests build one.
	qhSrc, _ := hitFor(t, srv, index, size, "song.mp3")

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
		Logf:             t.Logf,
	})
	defer cancelA()

	// A scripted peer links to the engine and will answer its QUERY.
	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Search("song")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	// Echo the QUERY's descriptor ID so the hit is attributed to this
	// search, but carry srv's address as the file source.
	qh := qhSrc
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT echoing its descriptor ID")
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", gotQH)
	}

	// The hand-off: the hit Search returned becomes the transfer.
	d := engA.Downloader(gotQH, gotQH.Hits[0])
	dir := t.TempDir()
	dlRes, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if dlRes.Bytes != size || dlRes.Resumed() {
		t.Errorf("result = %+v, want %d bytes, not resumed", dlRes, size)
	}

	wantPath := filepath.Join(dir, "song.mp3")
	if dlRes.Path != wantPath {
		t.Errorf("result path = %q, want %q", dlRes.Path, wantPath)
	}
	onDisk, err := os.ReadFile(dlRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}
