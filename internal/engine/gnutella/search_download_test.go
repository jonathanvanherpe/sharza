// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end test: one engine searches a peer, collects its QUERYHIT, and
// fetches the named file over HTTP from an httptest servent standing in
// for that peer. Proves the search and download primitives compose into
// one completed transfer.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// errNoUsableHit is returned when a search yields no hit that can be
// downloaded: zero port, unspecified address, or no non-empty file.
var errNoUsableHit = errors.New("gnutella: no usable hit")

// usableHit returns the first FileHit in qh that can be downloaded:
// non-zero port, non-unspecified IP, and at least one file with a
// non-zero size. It reports false when qh cannot be used.
func usableHit(qh QueryHit) (FileHit, bool) {
	if qh.Port == 0 {
		return FileHit{}, false
	}
	if net.IP(qh.IP[:]).IsUnspecified() {
		return FileHit{}, false
	}
	for _, h := range qh.Hits {
		if h.FileSize > 0 {
			return h, true
		}
	}
	return FileHit{}, false
}

// firstUsableHit scans search results in order and returns the first
// usable (QueryHit, FileHit) pair.
func firstUsableHit(results []QueryHit) (QueryHit, FileHit, bool) {
	for _, qh := range results {
		if hit, ok := usableHit(qh); ok {
			return qh, hit, true
		}
	}
	return QueryHit{}, FileHit{}, false
}

func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const index = 42
	payload := testContent(2048)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		w.Header().Set("X-Gnutella-Content-Length", fmt.Sprintf("%d", len(payload)))
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T", srv.Listener.Addr())
	}
	serventPort := uint16(ta.Port)

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(len(payload)), Name: "test.bin"},
			{Index: index + 1, Size: 0, Name: "empty.bin"},
		},
		advertisePort: serventPort,
	})
	defer cancelA()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
		Peers:            []string{engA.Addr().String()},
	})
	defer cancelB()

	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engB.Search("test")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	qh, hit, ok := firstUsableHit(results)
	if !ok {
		t.Fatal(errNoUsableHit)
	}

	dir := t.TempDir()
	res, err := engB.Downloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, "test.bin")
	if res.Path != wantPath {
		t.Errorf("path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != int64(len(payload)) {
		t.Errorf("bytes = %d, want %d", res.Bytes, len(payload))
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != len(payload) {
		t.Fatalf("on-disk size = %d, want %d", len(onDisk), len(payload))
	}
	for i := range payload {
		if onDisk[i] != payload[i] {
			t.Fatalf("byte %d differs", i)
		}
	}
}

func TestSearchAndDownloadSkipsUnusableHits(t *testing.T) {
	// Hits that cannot be downloaded must be skipped without touching disk.
	dir := t.TempDir()
	cases := []struct {
		name string
		qh   QueryHit
	}{
		{"zero port", QueryHit{Port: 0, IP: [4]byte{127, 0, 0, 1}, Hits: []FileHit{{FileIndex: 1, FileSize: 10, FileName: "a.bin"}}}},
		{"unspecified ip", QueryHit{Port: 1234, IP: [4]byte{0, 0, 0, 0}, Hits: []FileHit{{FileIndex: 1, FileSize: 10, FileName: "a.bin"}}}},
		{"empty file", QueryHit{Port: 1234, IP: [4]byte{127, 0, 0, 1}, Hits: []FileHit{{FileIndex: 1, FileSize: 0, FileName: "a.bin"}}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, ok := usableHit(tc.qh); ok {
				t.Fatalf("usableHit reported usable for %s", tc.name)
			}
			// Ensure nothing was written.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Errorf("disk touched: %d entries", len(entries))
			}
		})
	}

	// No usable hit at all yields the sentinel.
	bad := []QueryHit{
		{Port: 0, IP: [4]byte{127, 0, 0, 1}, Hits: []FileHit{{FileSize: 5}}},
	}
	if _, _, ok := firstUsableHit(bad); ok {
		t.Fatal("firstUsableHit found a hit in an all-bad set")
	}
	if errNoUsableHit == nil {
		t.Fatal("sentinel unset")
	}
}

func TestSearchAndDownloadNoUsableHitEndToEnd(t *testing.T) {
	// Engine A shares an empty catalogue, so its QUERYHIT carries no
	// non-empty file and the search yields no usable hit.
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue:        nil,
	})
	defer cancelA()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    500 * time.Millisecond,
		Peers:            []string{engA.Addr().String()},
	})
	defer cancelB()

	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engB.Search("anything")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if _, _, ok := firstUsableHit(results); ok {
		t.Fatal("expected no usable hit")
	}
	// Sentinel is the documented outcome.
	if errNoUsableHit.Error() == "" {
		t.Fatal("empty sentinel")
	}
}

func TestSearchAndDownloadContextCancellation(t *testing.T) {
	const index = 7
	payload := testContent(1 << 20)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Delay so cancellation wins.
		time.Sleep(5 * time.Second)
		w.Header().Set("Content-Length", fmt.Sprintf("%d", len(payload)))
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)

	ta := srv.Listener.Addr().(*net.TCPAddr)
	serventPort := uint16(ta.Port)

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(len(payload)), Name: "big.bin"},
		},
		advertisePort: serventPort,
	})
	defer cancelA()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
		Peers:            []string{engA.Addr().String()},
	})
	defer cancelB()

	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engB.Search("big")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	qh, hit, ok := firstUsableHit(results)
	if !ok {
		t.Fatal(errNoUsableHit)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel before Fetch

	dir := t.TempDir()
	_, err = engB.Downloader(qh, hit).Fetch(ctx, dir)
	if err == nil {
		t.Fatal("Fetch succeeded despite cancelled context")
	}
}
