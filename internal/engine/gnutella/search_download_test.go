// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestSearchThenDownloadCompletes is the end-to-end gate for the
// Gnutella 0.6 "completes a search and a download" criterion: one real
// TCP link carries a QUERY and its answering QUERYHIT, and the hit's
// advertised servent (an httptest.Server) is then fetched over HTTP,
// with the bytes landing on disk. It composes Engine.Search and
// Engine.Downloader(...).Fetch without any production-code change.
func TestSearchThenDownloadCompletes(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
	})
	defer cancel()

	// A scripted peer connects to engine A and will answer its QUERY.
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("test")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	// Reply with a QUERYHIT whose IP/port are the httptest listener's,
	// not the scripted peer's own, so the download goes to the servent.
	qh, _ := hitFor(t, srv, index, uint32(size), "song.mp3")
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatal("Search returned a hit with no file hits")
	}
	hit := gotQH.Hits[0]

	dir := t.TempDir()
	dres, err := eng.Downloader(gotQH, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if dres.Complete {
		t.Errorf("Fetch Complete = true, want false")
	}
	if dres.Bytes != int64(size) {
		t.Errorf("Fetch Bytes = %d, want %d", dres.Bytes, size)
	}
	if dres.Offset != 0 {
		t.Errorf("Fetch Offset = %d, want 0", dres.Offset)
	}

	onDisk, err := os.ReadFile(dres.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	if gotPath != fmt.Sprintf("/gnutella/%d", index) {
		t.Errorf("request path = %q, want /gnutella/%d", gotPath, index)
	}
}
