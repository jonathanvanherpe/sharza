// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchThenDownload is the end-to-end integration slice of P1's
// exit gate: one engine searches another over real TCP, then fetches the
// advertised file from a scripted servent over real HTTP, proving that
// Engine.Search and Downloader.Fetch (via Engine.Downloader) compose into
// a single completed transfer.

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

func TestSearchThenDownload(t *testing.T) {
	const (
		index = 7
		size  = 1234
		name  = "test.bin"
	)
	content := testContent(size)

	// Engine B shares a one-file catalogue.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: name},
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
	if len(results) == 0 || len(results[0].Hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	hit := qh.Hits[0]

	// Stand in the advertised servent with an httptest server serving
	// deterministic bytes; rewrite the hit's IP/port to that server.
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

	wantPath := filepath.Join(dir, name)
	if res.Path != wantPath {
		t.Errorf("result path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}
	if res.Offset != 0 {
		t.Errorf("result offset = %d, want 0", res.Offset)
	}
	if res.Resumed() {
		t.Errorf("result reported resumed, want not resumed")
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
