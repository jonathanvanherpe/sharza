// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end integration test: one Engine.Search over real TCP feeds one
// Engine.Downloader.Fetch, proving the two primitives compose into a single
// completed transfer. No production code is exercised beyond what the
// existing unit tests already cover; this only wires them together.

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
	const (
		index = 7
		size  = 1234
	)
	content := testContent(size)

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

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: "shared.bin"},
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

	results, err := engA.Search("shared")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 || len(results[0].Hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	hit := qh.Hits[0]
	if hit.FileSize != size {
		t.Fatalf("hit size = %d, want %d", hit.FileSize, size)
	}

	// Retarget the source address at the httptest servent.
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("servent addr is %T", srv.Listener.Addr())
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
	if res.Bytes != int64(size) {
		t.Errorf("Bytes = %d, want %d", res.Bytes, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if int64(len(onDisk)) != int64(size) {
		t.Errorf("on-disk size = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Error("on-disk bytes do not match source")
	}
	// ensure path inside dir
	if filepath.Dir(res.Path) != dir {
		t.Errorf("path %s not in %s", res.Path, dir)
	}
}
