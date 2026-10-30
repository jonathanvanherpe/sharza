// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd proves that a QUERYHIT returned by
// Engine.Search can drive Engine.Downloader(...).Fetch to bytes on disk
// that match the source, over real TCP between two engines. Engine B
// advertises the file through its catalogue; the bytes are served from
// an httptest server, and the hit's source address/port are retargeted
// at that server before the download.

import (
	"bytes"
	"context"
	"fmt"
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
		index = 1
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
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "test.bin"},
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
		t.Fatalf("hit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]

	// Retarget the hit's source address/port at the servent.
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
	d := engA.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(got, content) {
		t.Errorf("downloaded bytes do not match source")
	}
	fi, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("stat downloaded file: %v", err)
	}
	if fi.Size() != int64(hit.FileSize) {
		t.Errorf("on-disk size = %d, want %d", fi.Size(), hit.FileSize)
	}
}
