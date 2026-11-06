// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd is the P1 exit-gate slice: one transfer
// that composes Engine.Search and Engine.Downloader/Fetch over real TCP.
// A source engine shares a temp file through its Catalogue; a searcher
// dials it, runs a QUERY, collects the QUERYHIT, and fetches the named
// file over HTTP from a servent standing in for that peer. The bytes and
// size on disk must match the source.

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

func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const fileIndex = 42
	content := testContent(1234)

	// Source engine shares the temp file through its Catalogue.
	srcDir := t.TempDir()
	srcPath := filepath.Join(srcDir, "shared.bin")
	if err := os.WriteFile(srcPath, content, 0o644); err != nil {
		t.Fatalf("write source file: %v", err)
	}
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: fileIndex, Size: uint32(len(content)), Name: "shared.bin"},
		},
	})
	defer cancelB()

	// An HTTP servent standing in for the peer that owns the file: it
	// serves the same bytes the Catalogue advertises, at the path the
	// download client requests.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", fileIndex) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(len(content)))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	// Searcher dials the source.
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
		t.Fatalf("hit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]
	if hit.FileName != "shared.bin" {
		t.Fatalf("filename = %q, want %q", hit.FileName, "shared.bin")
	}

	// The QUERYHIT advertises the Gnutella control address; the servent
	// standing in for that peer serves HTTP on its own port, so point
	// the download at it (same host, servent port).
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("servent address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("servent address %s is not IPv4", ta)
	}
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)

	destDir := t.TempDir()
	res, err := engA.Downloader(qh, hit).Fetch(context.Background(), destDir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != int64(len(content)) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, len(content))
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("downloaded file (%d bytes) does not match source (%d bytes)",
			len(onDisk), len(content))
	}
	if fi, err := os.Stat(res.Path); err != nil || fi.Size() != int64(len(content)) {
		t.Errorf("on-disk size = %d, want %d", fi.Size(), len(content))
	}
}
