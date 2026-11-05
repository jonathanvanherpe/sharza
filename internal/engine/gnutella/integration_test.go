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

// TestSearchAndDownloadEndToEnd proves the P1 exit-gate slice: a search
// result collected over real TCP drives a completed file transfer. A
// source engine shares a file (index 42) through its Catalogue; a
// searcher dials it, issues a QUERY for "shared", collects the QUERYHIT,
// and then fetches the file through Engine.Downloader against an
// httptest servent that stands in for the owning peer and serves the
// same bytes at /gnutella/<index>. The result's byte count, on-disk
// size and bytes are checked against the source.
func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 42
		size  = 4096
	)
	content := testContent(size)

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: "shared.bin"},
		},
	})
	defer cancelB()

	// httptest servent standing in for the owning peer: serves the same
	// bytes the source engine advertises, at /gnutella/<index>.
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

	var downloadLogged int
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
		Logf: func(format string, args ...any) {
			if format == "downloaded %s from %s: %d bytes at offset %d" {
				downloadLogged++
			}
		},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("shared")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatal("QUERYHIT carries no file hits")
	}
	hit := qh.Hits[0]
	if hit.FileIndex != index {
		t.Fatalf("file index = %d, want %d", hit.FileIndex, index)
	}

	// The owning peer for the download is the httptest servent, so the
	// hit's source address is redirected to it (the engine-generated
	// hit points at the source engine, which does not serve HTTP).
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
	d := engA.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if res.Bytes != int64(size) {
		t.Errorf("result byte count = %d, want %d", res.Bytes, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("on-disk size = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("on-disk bytes (%d) differ from source (%d)", len(onDisk), len(content))
	}
	if filepath.Dir(res.Path) != dir {
		t.Errorf("file landed in %q, want %q", filepath.Dir(res.Path), dir)
	}
	if downloadLogged == 0 {
		t.Error("engine log sink was not wired through Engine.Downloader")
	}
}