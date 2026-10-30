// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end integration test: one Engine.Search over real TCP followed by
// one Downloader.Fetch, proving the two compose into a completed transfer.

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
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
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: "test.bin"},
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

	// Retarget the hit's source at the serving httptest.Server.
	qh.IP = [4]byte{}
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)

	dir := t.TempDir()
	dl := engA.Downloader(qh, hit)
	res, err := dl.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Fatalf("destination bytes do not equal source")
	}
	if int64(len(got)) != int64(hit.FileSize) {
		t.Fatalf("destination size %d, want %d (hit.FileSize)", len(got), hit.FileSize)
	}
}
