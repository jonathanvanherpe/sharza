// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the P1 exit-gate slice: one
// end-to-end transfer proving that Engine.Search and Downloader.Fetch
// (via Engine.Downloader) compose into a single completed download over
// real TCP and real HTTP. No production code is touched; the primitives
// are exercised as they already exist.

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

	// Real HTTP source standing in for a Gnutella servent.
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

	// Engine B shares a catalogue entry; engine A dials it.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "test.bin"},
		},
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	// Scripted peer connected to A; it will answer A's QUERY with a
	// QUERYHIT naming the httptest server above.
	r, conn := dialEngine(t, engA.Addr().String())

	waitForPeers(t, engA, 2)
	time.Sleep(150 * time.Millisecond)

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

	qhSrv, hitSrv := hitFor(t, srv, index, uint32(size), "test.bin")
	hp := EncodeQueryHit(qhSrv)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits, want at least one naming the served file")
	}

	// Find a hit that names the served file (httptest source).
	var foundQH QueryHit
	var foundHit FileHit
	found := false
	for _, qh := range res.hits {
		for _, h := range qh.Hits {
			if qh.IP == qhSrv.IP && qh.Port == qhSrv.Port && h.FileIndex == hitSrv.FileIndex {
				foundQH = qh
				foundHit = h
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatal("no search hit names the served file")
	}
	// Sanity: at least one hit names the served file by name too.
	named := false
	for _, qh := range res.hits {
		for _, h := range qh.Hits {
			if h.FileName == "test.bin" {
				named = true
			}
		}
	}
	if !named {
		t.Error("no hit names the served file by filename")
	}

	dir := t.TempDir()
	dRes, err := engA.Downloader(foundQH, foundHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if dRes.Bytes != int64(size) {
		t.Errorf("Bytes = %d, want %d", dRes.Bytes, size)
	}
	onDisk, err := os.ReadFile(dRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("on-disk size = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
	if filepath.Dir(dRes.Path) != dir {
		t.Errorf("file written outside dir: %s", dRes.Path)
	}
}