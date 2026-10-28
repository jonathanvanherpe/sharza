// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadCompose is the smallest end-to-end proof that
// P1's two halves compose: one engine searches a scripted peer and
// downloads the file the search named, over real TCP and real HTTP.
//
// Engine A has no configured peers of its own; a scripted 0.6 peer
// dials it, answers its QUERY with a QUERYHIT whose IP and port point
// at an httptest server, and the test then drives that hit through
// Engine.Downloader(...).Fetch into a temp directory. The file on disk
// must equal the bytes the server served.

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSearchAndDownloadCompose(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	qh0, _ := hitFor(t, srv, index, size, "song.mp3")

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     500 * time.Millisecond,
	})
	defer cancelA()

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

	hp := EncodeQueryHit(qh0)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := res.hits[0]
	if len(qh.Hits) == 0 {
		t.Fatal("search hit has no file hits")
	}
	hit := qh.Hits[0]

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	dres, err := engA.Downloader(qh, hit).Fetch(ctx, dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if dres.Bytes != int64(size) {
		t.Errorf("Bytes = %d, want %d", dres.Bytes, size)
	}
	data, err := os.ReadFile(dres.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(data, content) {
		t.Errorf("file on disk does not match served content")
	}
	if filepath.Dir(dres.Path) != dir {
		t.Errorf("result path %q not inside %q", dres.Path, dir)
	}
}