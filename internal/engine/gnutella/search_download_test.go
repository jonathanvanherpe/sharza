// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd proves the "completes a search and a
// download" leg of P1's exit gate: a QUERYHIT returned by Engine.Search
// drives Engine.Downloader(...).Fetch to bytes on disk that match the
// source. Two engines talk over real TCP; engine B advertises a file
// through its catalogue and an httptest servent (real TCP, real HTTP)
// serves the bytes at /gnutella/<index>. Engine A dials B, searches,
// retargets the hit's source address/port at the servent, and fetches.

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
		if r.URL.Path != "/gnutella/"+strconv.Itoa(index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: "test.mp3"},
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

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]
	if hit.FileName != "test.mp3" {
		t.Errorf("filename = %q, want %q", hit.FileName, "test.mp3")
	}

	// Retarget the hit's source address/port at the servent.
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)

	dir := t.TempDir()
	res, err := engA.Downloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if res.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}

	wantPath := filepath.Join(dir, "test.mp3")
	if res.Path != wantPath {
		t.Errorf("result path = %q, want %q", res.Path, wantPath)
	}

	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if info.Size() != int64(hit.FileSize) {
		t.Errorf("on-disk size = %d, want %d", info.Size(), hit.FileSize)
	}

	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}