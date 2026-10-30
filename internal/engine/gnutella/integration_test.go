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
// real TCP: engine B advertises a file in its catalogue, engine A
// searches, takes the first QueryHit/FileHit, retargets the source at a
// servent, fetches, and the destination bytes match the source with the
// advertised size.
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
			{Index: index, Size: size, Name: "song.mp3"},
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
		t.Fatalf("QueryHit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]

	// Retarget the hit's source address at the servent.
	ta := srv.Listener.Addr().(*net.TCPAddr)
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("servent address %s is not IPv4", ta)
	}
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)

	dir := t.TempDir()
	d := engA.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != int64(hit.FileSize) {
		t.Errorf("Fetch bytes = %d, want %d", res.Bytes, hit.FileSize)
	}

	dest := filepath.Join(dir, "song.mp3")
	got, err := os.ReadFile(dest)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if len(got) != int(hit.FileSize) {
		t.Errorf("destination size = %d, want %d", len(got), hit.FileSize)
	}
	if !bytes.Equal(got, content) {
		t.Error("destination bytes do not equal source")
	}
}