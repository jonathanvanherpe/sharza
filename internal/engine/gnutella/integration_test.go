// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Integration test: one end-to-end transfer over real TCP proving that
// Engine.Search and Downloader.Fetch (reached via Engine.Downloader)
// compose into a single completed download. Engine B shares a catalogue
// entry and an httptest servent serves the bytes; engine A dials B,
// searches, retargets the hit at the servent, and fetches.

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
		size  = 1200
	)
	content := testContent(size)

	// httptest servent serving the file at /gnutella/<index>.
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
		t.Fatalf("servent listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("servent listener address %s is not IPv4", ta)
	}

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "endtoend.bin"},
		},
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
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
		t.Fatal("QueryHit has no file hits")
	}
	hit := qh.Hits[0]
	if hit.FileSize != uint32(size) {
		t.Fatalf("hit.FileSize = %d, want %d", hit.FileSize, size)
	}

	// Retarget the hit's IP/port at the servent.
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)

	destDir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()

	res, err := engA.Downloader(qh, hit).Fetch(ctx, destDir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}

	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file on disk = %d bytes, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
	if int(hit.FileSize) != len(onDisk) {
		t.Errorf("on-disk size %d != hit.FileSize %d", len(onDisk), hit.FileSize)
	}

	// Sanity: destination is inside destDir.
	if filepath.Dir(res.Path) != destDir {
		t.Errorf("result path %q not inside %q", res.Path, destDir)
	}
}