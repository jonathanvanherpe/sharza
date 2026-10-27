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

// TestSearchThenDownload is the smallest end-to-end proof that the two
// P1 primitives compose over real TCP: engine A searches engine B, the
// QUERYHIT that Search returns drives a successful HTTP fetch, and the
// bytes on disk match the served content. No network is reached; the
// download source is repointed at a local httptest servent.
func TestSearchThenDownload(t *testing.T) {
	const (
		index = 7
		size  = 1234
		name  = "test.mp3"
	)
	content := testContent(size)

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
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatal("hit has no file hits")
	}
	hit := qh.Hits[0]
	if hit.FileIndex != index {
		t.Errorf("file index = %d, want %d", hit.FileIndex, index)
	}
	if hit.FileSize != size {
		t.Errorf("file size = %d, want %d", hit.FileSize, size)
	}
	if hit.FileName != name {
		t.Errorf("file name = %q, want %q", hit.FileName, name)
	}

	// Repoint the hit's source at a local httptest servent serving
	// /gnutella/7, standing in for the peer that would serve the file.
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
	if res.Bytes != size {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}
	if res.Offset != 0 || res.Resumed() {
		t.Errorf("result = %+v, want %d bytes at offset 0, not resumed", res, size)
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