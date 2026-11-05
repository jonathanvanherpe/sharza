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
	"sync"
	"testing"
	"time"
)

// TestSearchAndDownloadEndToEnd proves that Engine.Search and
// Downloader.Fetch (reached through Engine.Downloader) compose into a
// single completed transfer over real TCP: a search returns a hit echoing
// a descriptor ID, and the fetch writes the full 4096 bytes to disk with
// byte-for-byte equality against the source.
func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const size = 4096
	content := testContent(size)

	// Source engine: answers QUERYs from its catalogue.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 42, Size: size, Name: "shared.bin"},
		},
	})
	defer cancelB()

	// httptest servent: serves the same bytes the catalogue advertises,
	// at the Gnutella download path. The engine-generated hit points at
	// the source engine, which does not serve HTTP, so the test redirects
	// the hit's IP/Port to this listener.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/42" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	// Capturing log sink wired into the searching engine, so the
	// download log line can be counted.
	var (
		logMu    sync.Mutex
		logLines []string
	)
	logf := func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logLines = append(logLines, fmt.Sprintf(format, args...))
		t.Logf(format, args...)
	}

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
		Logf:              logf,
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("shared")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}

	var qh QueryHit
	var hit FileHit
	found := false
	for _, r := range results {
		for _, h := range r.Hits {
			if h.FileIndex == 42 {
				qh = r
				hit = h
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatal("no QueryHit with a file hit whose FileIndex == 42")
	}

	// Redirect the hit's IP/Port to the httptest listener.
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
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	res, err := engA.Downloader(qh, hit).Fetch(ctx, dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}
	if res.Bytes != size {
		t.Errorf("res.Bytes = %d, want %d", res.Bytes, size)
	}

	data, err := os.ReadFile(filepath.Join(dir, "shared.bin"))
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if len(data) != size {
		t.Errorf("on-disk size = %d, want %d", len(data), size)
	}
	if !bytes.Equal(data, content) {
		t.Error("on-disk bytes do not match testContent")
	}

	// Count the download log line produced through Engine.Downloader.
	src := net.JoinHostPort(net.IP(qh.IP[:]).String(), strconv.Itoa(int(qh.Port)))
	expected := fmt.Sprintf("downloaded %s from %s: %d bytes at offset %d", "shared.bin", src, size, 0)
	logMu.Lock()
	defer logMu.Unlock()
	count := 0
	for _, line := range logLines {
		if line == expected {
			count++
		}
	}
	if count == 0 {
		t.Errorf("no %q log line captured from Engine.Downloader; got %v", expected, logLines)
	}
}
