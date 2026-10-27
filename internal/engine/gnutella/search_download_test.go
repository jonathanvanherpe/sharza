// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchThenDownload proves Engine.Search and Downloader.Fetch compose
// into one completed transfer over real TCP: engine B answers a QUERY
// from its catalogue, engine A searches it, then fetches the advertised
// file from an HTTP servent.

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSearchThenDownload(t *testing.T) {
	const (
		index = 7
		size  = 1234
		name  = "test.mp3"
	)

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
		t.Fatalf("hit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]
	if hit.FileIndex != index || hit.FileSize != size || hit.FileName != name {
		t.Fatalf("first file hit = %+v, want index %d size %d name %q", hit, index, size, name)
	}

	content := testContent(size)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/7" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", "1234")
		w.Header().Set("X-Gnutella-Content-Length", "1234")
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

	if res.Path != filepath.Join(dir, name) {
		t.Errorf("result path = %q, want %q", res.Path, filepath.Join(dir, name))
	}
	if res.Bytes != size {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}
	if res.Resumed() {
		t.Errorf("result unexpectedly resumed (offset %d)", res.Offset)
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
