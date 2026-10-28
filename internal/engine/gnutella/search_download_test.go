// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the smallest end-to-end proof that the
// two P1 primitives compose into one completed transfer: Engine.Search
// collects a QUERYHIT that names a file, and Engine.Downloader(qh, hit).Fetch
// moves and size-checks that file over real TCP and real HTTP. No
// production code is touched; the test only exercises existing seams.

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
		name  = "test.bin"
	)
	content := testContent(size)

	// Real HTTP servent: the file Engine.Downloader will fetch.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+strconv.Itoa(index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	// Engine B carries a catalogue entry for the same file metadata.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: name},
		},
	})
	defer cancelB()

	// Engine A dials B and searches with a 1s window.
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	// Scripted peer dials A; it will echo A's QUERY descriptor ID in a
	// QUERYHIT that names the httptest servent instead of itself.
	r, conn := dialEngine(t, engA.Addr().String())
	defer conn.Close()

	waitForPeers(t, engA, 2)
	time.Sleep(150 * time.Millisecond)

	// QUERYHIT naming the httptest server, built the same way the
	// download tests build one.
	qhServer, _ := hitFor(t, srv, uint32(index), uint32(size), name)

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
		t.Fatalf("scripted peer: first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("scripted peer: query payload: %v", err)
	}

	hp := EncodeQueryHit(qhServer)
	sendMsg(t, conn, Header{
		ID:     hdr.ID,
		Type:   MsgQueryHit,
		TTL:    6,
		Hops:   0,
		Length: uint32(len(hp)),
	}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}

	// Find the hit that names the served file (the scripted peer's).
	var foundQH QueryHit
	var foundHit FileHit
	found := false
	for _, qh := range res.hits {
		for _, h := range qh.Hits {
			if h.FileName == name && int(h.FileSize) == size && qh.Port == qhServer.Port {
				foundQH = qh
				foundHit = h
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("Search returned %d hit(s) but none named the served file", len(res.hits))
	}

	dir := t.TempDir()
	dres, err := engA.Downloader(foundQH, foundHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if dres.Bytes != int64(size) {
		t.Errorf("Bytes = %d, want %d", dres.Bytes, size)
	}

	// On-disk file exists, has size bytes, equals served content.
	info, err := os.Stat(dres.Path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if info.Size() != int64(size) {
		t.Errorf("on-disk size = %d, want %d", info.Size(), size)
	}
	onDisk, err := os.ReadFile(dres.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("on-disk content (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}