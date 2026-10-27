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

// TestSearchDownload is the end-to-end integration test over real TCP:
// engine A searches, engine B answers from its catalogue, and A drives
// the hit through Engine.Downloader into a completed file transfer. B's
// QUERYHIT advertises a separate httptest servent port via the
// advertisePort seam, so the transfer exercises the real download path
// rather than the engine's own listener.
func TestSearchDownload(t *testing.T) {
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

	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("servent listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "test.bin"},
		},
		advertisePort: uint16(ta.Port),
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:            []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("test")
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
	if qh.Port != uint16(ta.Port) {
		t.Errorf("QUERYHIT port = %d, want servent port %d", qh.Port, ta.Port)
	}

	d := engA.Downloader(qh, hit)
	dir := t.TempDir()
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != int64(size) {
		t.Errorf("DownloadResult.Bytes = %d, want %d", res.Bytes, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	if filepath.Dir(res.Path) != dir {
		t.Errorf("result path %q is not inside %q", res.Path, dir)
	}
}
