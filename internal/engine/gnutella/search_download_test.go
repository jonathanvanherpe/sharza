// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end integration test for the P1 exit gate: one Engine over
// real TCP composes Search with a download reached through
// Engine.Downloader into a single completed transfer. No production
// code is exercised beyond the existing primitives.

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
		index = 42
		size  = 1234
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/42" {
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
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     200 * time.Millisecond,
		Logf:              t.Logf,
	})
	defer cancel()

	r, conn := dialEngine(t, eng.Addr().String())
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		t.Fatal(err)
	}
	waitForPeers(t, eng, 1)

	type searchResult struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan searchResult, 1)
	go func() {
		hits, err := eng.Search("compose")
		resCh <- searchResult{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	qh, _ := hitFor(t, srv, index, uint32(size), "composed.bin")
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
		t.Fatal("Search hit has no file hits")
	}
	gotQH := res.hits[0]
	gotHit := res.hits[0].Hits[0]

	dir := t.TempDir()
	d := eng.Downloader(gotQH, gotHit)
	fetchRes, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if fetchRes.Bytes != int64(size) {
		t.Errorf("Fetch bytes = %d, want %d", fetchRes.Bytes, size)
	}
	if uint32(fetchRes.Bytes) != gotHit.FileSize {
		t.Errorf("Fetch bytes = %d, declared size = %d", fetchRes.Bytes, gotHit.FileSize)
	}
	if fetchRes.Offset != 0 {
		t.Errorf("Fetch offset = %d, want 0", fetchRes.Offset)
	}

	wantPath := filepath.Join(dir, "composed.bin")
	if fetchRes.Path != wantPath {
		t.Errorf("result path = %q, want %q", fetchRes.Path, wantPath)
	}
	onDisk, err := os.ReadFile(fetchRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file on disk size = %d, want declared size %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	// Ensure no stray files / sanity.
	if _, err := os.Stat(filepath.Join(dir, "composed.bin")); err != nil {
		t.Fatalf("stat: %v", err)
	}
}