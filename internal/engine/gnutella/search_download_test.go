// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end composition test: one engine searches a connected,
// catalogue-bearing peer over real TCP, collects that peer's QUERYHIT,
// and fetches the named file over HTTP from a servent standing in for
// that peer. This is the smallest verifiable unit of P1's exit-gate
// criterion "completes a search and a download": it proves that
// Engine.Search and Downloader.Fetch compose into one completed transfer.

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

func TestSearchThenDownload(t *testing.T) {
	const (
		index = 7
		size  = 1234
		name  = "test.mp3"
	)
	content := testContent(size)

	// HTTP servent standing in for the peer that can serve the file.
	// It speaks real HTTP over a real TCP listener, matching the
	// pattern in download_test.go.
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

	// Catalogue-bearing peer.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: name},
		},
	})
	defer cancelB()

	// Searching leaf.
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
		Peers:            []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 || len(results[0].Hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	hit := qh.Hits[0]
	if hit.FileName != name {
		t.Fatalf("filename = %q, want %q", hit.FileName, name)
	}
	if hit.FileSize != uint32(size) {
		t.Fatalf("size = %d, want %d", hit.FileSize, size)
	}
	if hit.FileIndex != index {
		t.Fatalf("index = %d, want %d", hit.FileIndex, index)
	}

	// The QUERYHIT advertises the peer's Gnutella address; the file
	// bytes come from the HTTP servent above, so point the hit's
	// source at it. The file index/size/name still come from Search.
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("servent listener address is %T", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("servent address %s is not IPv4", ta)
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
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file size on disk = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Error("file bytes on disk do not match served content")
	}
	if filepath.Dir(res.Path) != dir {
		t.Errorf("wrote outside destination dir: %s", res.Path)
	}
}
