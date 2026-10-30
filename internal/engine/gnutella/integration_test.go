// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

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

// TestSearchAndDownloadEndToEnd proves that Engine.Search and
// Engine.Downloader(...).Fetch compose into one completed transfer over
// real TCP: engine B advertises a file, engine A searches for it, takes
// the returned QueryHit, retargets its source address at an httptest
// servent that serves the bytes, and downloads them.
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
			{Index: index, Size: uint32(size), Name: "song.mp3"},
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

	results, err := engA.Search("song")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatal("QueryHit has no file hits")
	}
	hit := qh.Hits[0]

	// Retarget the QueryHit's source address at the servent.
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

	dir := t.TempDir()
	res, err := engA.Downloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Path == "" {
		t.Fatal("Fetch returned empty path")
	}

	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if int64(len(onDisk)) != int64(hit.FileSize) {
		t.Errorf("on-disk size = %d, want %d", len(onDisk), hit.FileSize)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	// Also ensure file exists at expected path.
	if _, err := os.Stat(filepath.Join(dir, "song.mp3")); err != nil {
		t.Errorf("expected file missing: %v", err)
	}
}
