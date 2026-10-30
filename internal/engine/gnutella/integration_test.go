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
// Downloader.Fetch (reached through Engine.Downloader) compose into one
// completed transfer over real TCP: engine B advertises a file, engine A
// searches it, takes the returned QueryHit, downloads it, and the bytes on
// disk match the source.
func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 7
		size  = 1024
	)
	content := testContent(size)

	// The servent file: a temp file of known bytes that engine B's
	// catalogue entry names.
	serventDir := t.TempDir()
	serventPath := filepath.Join(serventDir, "shared.bin")
	if err := os.WriteFile(serventPath, content, 0o644); err != nil {
		t.Fatalf("write servent file: %v", err)
	}

	// A real TCP HTTP servent that serves the file at the Gnutella
	// download path. Its address is what the transfer ultimately targets.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+strconv.Itoa(index) {
			http.NotFound(w, r)
			return
		}
		data, err := os.ReadFile(serventPath)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(data)))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(len(data)))
		_, _ = w.Write(data)
	}))
	defer srv.Close()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "shared.bin"},
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

	results, err := engA.Search("shared")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT echoing its descriptor ID")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatalf("query hit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]

	// The search hit advertises engine B's Gnutella (handshake) port,
	// which does not serve HTTP. Retarget the source at the servent above
	// so Fetch exercises the real download path; in a live swarm the hit
	// already carries the servent's download port.
	ta := srv.Listener.Addr().(*net.TCPAddr)
	qh.IP = [4]byte{127, 0, 0, 1}
	qh.Port = uint16(ta.Port)

	d := engA.Downloader(qh, hit)
	if d == nil {
		t.Fatal("Engine.Downloader returned nil")
	}

	destDir := t.TempDir()
	res, err := d.Fetch(context.Background(), destDir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes == 0 {
		t.Fatal("Fetch wrote no bytes")
	}

	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Fatalf("destination bytes (%d) do not match source bytes (%d)", len(onDisk), len(content))
	}
	if int64(len(onDisk)) != int64(hit.FileSize) {
		t.Fatalf("destination size %d does not equal hit size %d", len(onDisk), hit.FileSize)
	}
}