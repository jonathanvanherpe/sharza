// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end composition test for P1's exit-gate criterion "completes a
// search and a download": one engine searches a connected peer over real
// TCP, takes the QUERYHIT that answers its QUERY, and fetches the named
// file over HTTP. It proves the two primitives already on main (Engine.Search
// and Downloader.Fetch) compose into one completed transfer. No production
// code changes; this slice is the test only.

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

func TestSearchThenDownloadCompletesTransfer(t *testing.T) {
	const (
		index = 42
		size  = 2048
		name  = "composition.bin"
	)
	content := testContent(size)

	// The file bytes are served by an httptest servent over real TCP,
	// matching the download tests' pattern. Sharza's engine is a
	// Gnutella client on this path and does not serve files itself, so
	// the bytes come from this stand-in servent; the QueryHit returned by
	// Search is pointed at it below.
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

	// Serving peer: an engine with a Catalogue entry describing the file.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: name},
		},
	})
	defer cancelB()

	// Searching leaf: dials the serving peer.
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     300 * time.Millisecond,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("composition")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want the serving peer's QUERYHIT")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatalf("QUERYHIT %+v has no file hits", qh)
	}
	hit := qh.Hits[0]
	if hit.FileIndex != index {
		t.Errorf("FileIndex = %d, want %d", hit.FileIndex, index)
	}
	if hit.FileSize != size {
		t.Errorf("FileSize = %d, want %d", hit.FileSize, size)
	}
	if hit.FileName != name {
		t.Errorf("FileName = %q, want %q", hit.FileName, name)
	}

	// Point the QueryHit's source at the httptest servent that actually
	// serves the bytes. The FileHit (index/size/name) came from Search.
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

	wantPath := filepath.Join(dir, name)
	if res.Path != wantPath {
		t.Errorf("result path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != size {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file on disk is %d bytes, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
}
