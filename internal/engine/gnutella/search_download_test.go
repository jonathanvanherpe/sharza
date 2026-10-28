// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSearchAndDownloadComposes is the smallest end-to-end artifact for the
// "completes a search and a download" half of the P1 exit gate: one engine,
// one scripted peer that answers its QUERY, and an httptest servent that
// serves the file the QUERYHIT names. It proves Engine.Search and
// Engine.Downloader(...).Fetch compose into a single completed transfer
// over real TCP.
func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	// The servent the QUERYHIT will name as the download source.
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

	qhServent, hitServent := hitFor(t, srv, index, size, "song.mp3")

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
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

	// Answer the QUERY with a QUERYHIT whose IP/Port name the servent.
	// The descriptor ID is echoed from the QUERY, which is what lets
	// Search collect it.
	qh := qhServent
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	qhHit := res.hits[0]
	if qhHit.HitCount < 1 || len(qhHit.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", qhHit)
	}
	if qhHit.Hits[0].FileName != hitServent.FileName {
		t.Errorf("filename = %q, want %q", qhHit.Hits[0].FileName, hitServent.FileName)
	}
	if qhHit.Port != uint16(srv.Listener.Addr().(*net.TCPAddr).Port) {
		t.Errorf("port = %d, want %d", qhHit.Port, srv.Listener.Addr().(*net.TCPAddr).Port)
	}
	if qhHit.IP != [4]byte{127, 0, 0, 1} {
		t.Errorf("ip = %v, want 127.0.0.1", qhHit.IP)
	}

	// Compose: download the hit Search returned, via Engine.Downloader.
	dir := t.TempDir()
	d := engA.Downloader(qhHit, qhHit.Hits[0])
	fetchRes, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fetchRes.Bytes != size {
		t.Errorf("Fetch Bytes = %d, want %d", fetchRes.Bytes, size)
	}
	if fetchRes.Offset != 0 {
		t.Errorf("Fetch Offset = %d, want 0", fetchRes.Offset)
	}
	onDisk, err := os.ReadFile(fetchRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)", len(onDisk), len(content))
	}
	if filepath.Dir(fetchRes.Path) != dir {
		t.Errorf("wrote outside dir: %s", fetchRes.Path)
	}
}