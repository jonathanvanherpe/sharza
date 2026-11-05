// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd proves the "completes a search and a
// download" leg of P1's exit gate over real TCP: a source engine
// advertises a file through its Catalogue, a searcher finds it with
// Engine.Search, the resulting QUERYHIT drives a transfer through
// Engine.Downloader(...).Fetch, and the bytes on disk match what the
// source advertised.
//
// The QUERYHIT's advertised address points at the source engine, which
// does not serve HTTP here; the download is redirected to a stand-in
// servent that serves the advertised bytes, exactly as a caller would
// when rewriting a hit's IP/port to a real source. No production code
// changes are needed for this test.

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
	const size = 12345

	// Source file the catalogue entry describes. Its bytes are what the
	// stand-in servent will serve and what the on-disk result must match.
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "shared.bin")
	content := testContent(size)
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}
	fi, err := os.Stat(srcPath)
	if err != nil {
		t.Fatalf("stat source file: %v", err)
	}

	// Source engine: shares the temp file through its Catalogue.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: uint32(fi.Size()), Name: "shared.bin"},
		},
	})
	defer cancelB()

	// Stand-in HTTP servent serving the advertised bytes at
	// /gnutella/<file index>.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/1" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(len(content)))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	// Searcher dials the source engine.
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
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
		t.Fatal("QUERYHIT has no file hits")
	}
	hit := qh.Hits[0]

	// Rewrite the hit's IP/port to the stand-in servent.
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("servent addr is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("servent addr %s is not IPv4", ta)
	}
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)

	// Transfer.
	dir := t.TempDir()
	d := engA.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if res.Bytes != int64(len(content)) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, len(content))
	}

	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("on-disk bytes (%d) do not match source (%d)", len(onDisk), len(content))
	}
	fi2, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if fi2.Size() != int64(len(content)) {
		t.Errorf("on-disk size = %d, want %d", fi2.Size(), len(content))
	}
}
