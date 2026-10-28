// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes proves the P1 exit-gate leg that the two
// primitives compose into one completed transfer: Engine.Search returns a
// QUERYHIT whose descriptor ID matches the QUERY, and that hit turned into a
// transfer by Engine.Downloader completes via Fetch, leaving the served bytes
// on disk at the declared size. It runs over real TCP: one engine, one
// scripted 0.6 peer, one httptest servent.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1000
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("X-Gnutella-Content-Length", fmt.Sprintf("%d", size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})
	// A scripted 0.6 peer links to the engine and answers its QUERY.
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	// The QUERYHIT names the servent, so the download goes there.
	qhTemplate, _ := hitFor(t, srv, index, uint32(size), "song.mp3")

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("song")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	qh := qhTemplate
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	if len(res.hits[0].Hits) == 0 {
		t.Fatal("returned hit has no file hits")
	}

	returnedQH := res.hits[0]
	returnedHit := res.hits[0].Hits[0]

	dir := t.TempDir()
	d := eng.Downloader(returnedQH, returnedHit)
	dlRes, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	onDisk, err := os.ReadFile(dlRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file on disk is %d bytes, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
}