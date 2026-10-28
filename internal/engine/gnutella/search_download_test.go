// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the end-to-end evidence for the P1
// exit gate: one Engine.Search and one Downloader.Fetch (via
// Engine.Downloader) compose into a single completed transfer over real
// TCP. No production code is involved beyond the existing primitives.
//
// An httptest servent serves a known file; a scripted peer dials the
// engine, receives its QUERY, and answers with a QUERYHIT pointing at the
// servent; Search returns that hit; Downloader.Fetch moves the bytes into a
// temp dir; the test checks the byte count, the on-disk size, the
// byte-for-byte content, and that the result path stays inside the temp dir.

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

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	// The servent: serves the known file at /gnutella/<index>.
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

	// A QUERYHIT that points the download at the servent above.
	qh, _ := hitFor(t, srv, index, size, "song.mp3")

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     200 * time.Millisecond,
	})
	// Scripted peer dials the engine and will answer its QUERY.
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

	// Reply with a QUERYHIT pointing at the servent, echoing the QUERY's
	// descriptor ID so Search attributes it to this search.
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
		t.Fatal("QUERYHIT carries no file hits")
	}
	gotQH := res.hits[0]
	gotHit := gotQH.Hits[0]

	// Compose: turn the returned hit into a transfer and fetch it.
	dir := t.TempDir()
	fetchRes, err := eng.Downloader(gotQH, gotHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if fetchRes.Bytes != int64(size) {
		t.Errorf("byte count = %d, want %d", fetchRes.Bytes, size)
	}
	info, err := os.Stat(fetchRes.Path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if info.Size() != int64(size) {
		t.Errorf("on-disk size = %d, want %d", info.Size(), size)
	}
	onDisk, err := os.ReadFile(fetchRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	if filepath.Dir(fetchRes.Path) != dir {
		t.Errorf("result path %q is not inside temp dir %q", fetchRes.Path, dir)
	}
}
