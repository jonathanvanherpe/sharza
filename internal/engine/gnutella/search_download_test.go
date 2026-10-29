// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the smallest end-to-end proof of P1's
// "completes a search and a download" leg: one engine searches over a real
// TCP peer, the peer answers with a QUERYHIT pointing at an httptest
// servent, and Engine.Downloader(...).Fetch writes the served bytes to disk.
// No production code is exercised beyond the existing Search and Fetch.

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

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1234
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

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:     200 * time.Millisecond,
	})

	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)
	time.Sleep(150 * time.Millisecond)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("test")
		resCh <- result{hits, err}
	}()

	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}

	qhServ, _ := hitFor(t, srv, index, uint32(size), "song.mp3")
	hp := EncodeQueryHit(qhServ)
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
		t.Fatal("QUERYHIT has no file hits")
	}
	gotHit := qh.Hits[0]

	dir := t.TempDir()
	fetchRes, err := eng.Downloader(qh, gotHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, "song.mp3")
	if fetchRes.Path != wantPath {
		t.Errorf("result path = %q, want %q", fetchRes.Path, wantPath)
	}
	if fetchRes.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", fetchRes.Bytes, size)
	}

	onDisk, err := os.ReadFile(fetchRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	// sanity: servent address carried through
	if net.IP(qh.IP[:]).String() == "0.0.0.0" {
		t.Error("QUERYHIT lost its source address")
	}
}