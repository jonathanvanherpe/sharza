// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd is the P1 exit-gate artifact: one
// integration test over real TCP proving Engine.Search and
// Downloader.Fetch compose into a single completed transfer. Engine A
// catalogues test.bin (plus a zero-size decoy) and advertises an
// httptest servent port; engine B dials A, searches "test", takes the
// first usable hit, fetches it into a temp dir, and asserts path, byte
// count and byte-for-byte content equality.

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
	const size = 4096
	content := testContent(size)

	// The servent: a real HTTP listener speaking the Gnutella 1
	// download convention, serving test.bin at its file index.
	index := uint32(1)
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

	serventPort := srv.Listener.Addr().(*net.TCPAddr).Port

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "test.bin"},
			{Index: 2, Size: 0, Name: "decoy.bin"},
		},
		advertisePort: uint16(serventPort),
	})
	defer cancelA()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engA.Addr().String()},
	})
	defer cancelB()

	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engB.Search("test")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}

	// Take the first usable hit (skip the zero-size decoy).
	var chosenQH QueryHit
	var chosenHit FileHit
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileSize == 0 {
				continue
			}
			chosenQH = qh
			chosenHit = h
			found = true
			break
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatal("no usable hit found")
	}

	dir := t.TempDir()
	d := engB.Downloader(chosenQH, chosenHit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, "test.bin")
	if res.Path != wantPath {
		t.Errorf("path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != int64(size) {
		t.Errorf("bytes = %d, want %d", res.Bytes, size)
	}

	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read fetched file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("fetched bytes differ from servent payload")
	}
}
