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

// TestSearchAndDownloadComposes proves the two primitives compose into one
// completed transfer: Engine.Search collects a QUERYHIT that names an
// httptest servent, Engine.Downloader turns that hit into a transfer, and
// Fetch writes the served bytes to disk with the declared size.
func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1024
	)
	content := testContent(size)

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})

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

	qhServ, hitServ := hitFor(t, srv, index, size, "song.mp3")

	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)
	time.Sleep(150 * time.Millisecond)

	// Scripted peer answers the engine's QUERY with a QUERYHIT naming the
	// httptest servent above.
	go func() {
		hdr, payload := readMsg(t, r)
		if hdr.Type != MsgQuery {
			t.Errorf("peer: first message type = %s, want query", typeName(hdr.Type))
			return
		}
		if _, err := DecodeQuery(payload); err != nil {
			t.Errorf("peer: query payload: %v", err)
			return
		}
		hp := EncodeQueryHit(qhServ)
		sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)
	}()

	results, err := eng.Search("test")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatal("Search hit has no file hits")
	}
	hit := qh.Hits[0]
	// Sanity: the hit should name the servent's file.
	if hit.FileIndex != hitServ.FileIndex || hit.FileSize != hitServ.FileSize {
		t.Fatalf("hit = %+v, want index=%d size=%d", hit, hitServ.FileIndex, hitServ.FileSize)
	}

	dir := t.TempDir()
	d := eng.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if res.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file on disk = %d bytes, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
}

