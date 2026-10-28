// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the end-to-end slice of P1's
// "completes a search and a download" gate: one engine, one scripted
// peer, one httptest servent. The engine sends a QUERY, the peer answers
// with a QUERYHIT that names the servent, Search returns that hit, and
// Engine.Downloader(...).Fetch writes the full served bytes to disk with
// matching content. No production code is exercised beyond the two
// primitives already landed.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"
)

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1024
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

	qhServ, _ := hitFor(t, srv, index, size, "song.mp3")

	var (
		cbMu   sync.Mutex
		cbID   [idSize]byte
		cbSeen int
	)
	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		OnQueryHit: func(_ net.Addr, id [idSize]byte, _ QueryHit) {
			cbMu.Lock()
			defer cbMu.Unlock()
			cbSeen++
			cbID = id
		},
	})
	defer cancel()

	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	type searchResult struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan searchResult, 1)
	go func() {
		hits, err := eng.Search("test")
		resCh <- searchResult{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}
	queryID := hdr.ID

	hp := EncodeQueryHit(qhServ)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT naming the servent")
	}
	searchHit := res.hits[0]
	if len(searchHit.Hits) == 0 {
		t.Fatal("returned hit has no file hits")
	}
	searchFileHit := searchHit.Hits[0]
	if searchFileHit.FileName != "song.mp3" {
		t.Errorf("filename = %q, want %q", searchFileHit.FileName, "song.mp3")
	}

	cbMu.Lock()
	seen := cbSeen
	seenID := cbID
	cbMu.Unlock()
	if seen == 0 {
		t.Fatal("OnQueryHit was not called for the QUERYHIT")
	}
	if seenID != queryID {
		t.Errorf("callback descriptor id = %x, want the QUERY's id %x", seenID, queryID)
	}

	// Composition: the hit Search returned feeds the downloader.
	dir := t.TempDir()
	fetchRes, err := eng.Downloader(searchHit, searchFileHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fetchRes.Bytes != int64(size) {
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
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}