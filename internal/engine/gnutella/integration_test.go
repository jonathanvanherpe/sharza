// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd proves the two halves of P1 compose into
// one completed transfer: engine B shares a file, engine A searches for
// it and receives a QUERYHIT naming it, then fetches the bytes through
// the Gnutella 1 download path. The download source is redirected onto
// an httptest servent so the transfer is deterministic and never touches
// the network.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 42
		size  = 4096
	)
	content := testContent(size)

	// httptest servent serving the shared bytes at /gnutella/42.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/42" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", size))
		w.Header().Set("X-Gnutella-Content-Length", fmt.Sprintf("%d", size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}

	// Engine B: shares the catalogue entry.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: "shared.bin"},
		},
	})
	defer cancelB()

	// Capture log lines through engine A's log sink (which Engine.Downloader
	// wires through).
	var (
		logMu    sync.Mutex
		logLines []string
	)
	logSink := func(format string, args ...any) {
		logMu.Lock()
		defer logMu.Unlock()
		logLines = append(logLines, fmt.Sprintf(format, args...))
	}

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
		Logf:              logSink,
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

	// Pick the hit whose FileIndex is 42.
	var (
		chosenQH  QueryHit
		chosenHit FileHit
		found     bool
	)
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileIndex == index {
				chosenQH = qh
				chosenHit = h
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("no hit with FileIndex %d in %d result(s)", index, len(results))
	}

	// Redirect that hit's IP/Port to the httptest listener.
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}
	copy(chosenQH.IP[:], ip)
	chosenQH.Port = uint16(ta.Port)

	dir := t.TempDir()
	ctx := context.Background()
	res, err := engA.Downloader(chosenQH, chosenHit).Fetch(ctx, dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if res.Bytes != size {
		t.Errorf("res.Bytes = %d, want %d", res.Bytes, size)
	}

	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("on-disk size = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
	// Path should be inside dir.
	if filepath.Dir(res.Path) != dir {
		t.Errorf("path %q not inside %q", res.Path, dir)
	}

	// Assert the downloaded log line was captured through the sink.
	logMu.Lock()
	defer logMu.Unlock()
	var sawDownloaded bool
	for _, line := range logLines {
		if strings.Contains(line, "downloaded") && strings.Contains(line, "from") {
			sawDownloaded = true
			break
		}
	}
	if !sawDownloaded {
		t.Errorf("did not capture a 'downloaded ... from ...' log line; got %v", logLines)
	}
}
