// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd is the smallest verifiable unit of the
// P1 exit gate "completes a search and a download": one end-to-end
// integration test over real TCP proving that a QUERY's echoed QUERYHIT
// drives Engine.Search to return a hit, and that the same hit then drives
// Downloader.Fetch (reached via Engine.Downloader) to a completed
// transfer whose on-disk bytes equal the served content.

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

func TestSearchAndDownloadEndToEnd(t *testing.T) {
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

	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Logf:              t.Logf,
	})

	// A scripted 0.6 peer dials A and registers.
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

	// Reply with a QUERYHIT echoing the descriptor ID, whose IP/Port point
	// at the httptest server.
	qh, _ := hitFor(t, srv, index, size, "song.mp3")
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) != 1 {
		t.Fatalf("Search returned %d hits, want 1", len(res.hits))
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatal("returned hit has no file hits")
	}

	// Drive the download from the hit Search returned.
	dir := t.TempDir()
	dlRes, err := engA.Downloader(gotQH, gotQH.Hits[0]).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if dlRes.Bytes != int64(size) || dlRes.Offset != 0 {
		t.Errorf("result = %+v, want %d bytes at offset 0", dlRes, size)
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