// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the smallest end-to-end artifact for
// the "completes a search and a download" leg of P1: one engine sends a
// QUERY over real TCP, a scripted peer answers with a QUERYHIT whose
// IP/Port name an httptest servent, and the engine turns that hit into a
// completed Fetch whose bytes match the served file.

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
		size  = 1234
	)
	content := testContent(size)

	// Servent serving the known file at /gnutella/<index>, reusing the
	// download test's servent shape.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+strconv.Itoa(index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
		_, _ = w.Write([]byte{0xFF})
	}))
	defer srv.Close()

	qhServent, hitServent := hitFor(t, srv, index, size, "song.mp3")

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    200 * time.Millisecond,
	})
	// Scripted peer connects to the searcher engine.
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)
	time.Sleep(150 * time.Millisecond)

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

	// Reply with a QUERYHIT pointing at the servent.
	qh := qhServent
	qh.HitCount = 1
	qh.Hits = []FileHit{hitServent}
	qh.Speed = 1000
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
		t.Fatal("first hit has no file hits")
	}

	hit := res.hits[0].Hits[0]
	dlQH := res.hits[0]
	d := eng.Downloader(dlQH, hit)

	dir := t.TempDir()
	fr, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fr.Bytes != int64(size) {
		t.Errorf("Fetch bytes = %d, want %d", fr.Bytes, size)
	}

	onDisk, err := os.ReadFile(fr.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file size on disk = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}

	// sanity: path inside dir
	if filepath.Dir(fr.Path) != dir {
		t.Errorf("result path %q not inside %q", fr.Path, dir)
	}
}
