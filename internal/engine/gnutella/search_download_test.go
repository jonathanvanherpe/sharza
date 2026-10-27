// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchThenDownload is the smallest end-to-end proof that the two
// primitives already on main compose: a QUERY issued by Engine.Search
// and a Downloader.Fetch driven by its QUERYHIT complete one transfer
// over real TCP (loopback), with a real handshake, QUERY/QUERYHIT
// correlation, and an HTTP GET.

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

func TestSearchThenDownload(t *testing.T) {
	content := testContent(1234)

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 7, Size: 1234, Name: "test.mp3"},
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

	var (
		qh   QueryHit
		hit  FileHit
		ok   bool
	)
	for _, r := range results {
		for _, h := range r.Hits {
			if h.FileIndex == 7 && h.FileSize == 1234 && h.FileName == "test.mp3" {
				qh = r
				hit = h
				ok = true
				break
			}
		}
		if ok {
			break
		}
	}
	if !ok {
		t.Fatalf("no matching hit in %#v", results)
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/7" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(1234))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(1234))
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
	ctx := context.Background()
	res, err := engA.Downloader(qh, hit).Fetch(ctx, dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != 1234 {
		t.Errorf("Bytes = %d, want 1234", res.Bytes)
	}
	wantPath := filepath.Join(dir, "test.mp3")
	if res.Path != wantPath {
		t.Errorf("Path = %q, want %q", res.Path, wantPath)
	}
	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("file bytes do not match served content")
	}
}