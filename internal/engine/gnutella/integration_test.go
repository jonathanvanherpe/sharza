// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadEndToEnd is the smallest verifiable slice of
// P1's "completes a search and a download" exit gate: engine B shares a
// catalogue entry, engine A dials it, searches, and fetches the file
// that the QUERYHIT names. The download source is retargeted at an
// httptest servent serving the file, because Gnutella 1 servents answer
// the transfer over HTTP while the engine speaks the Gnutella control
// protocol; the byte path is nonetheless a real TCP transfer exercised
// end to end.

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 7
		size  = 12345
		name  = "test.bin"
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+strconv.Itoa(int(index)) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	srvAddr := srv.Listener.Addr().(*net.TCPAddr)
	srvIP := srvAddr.IP.To4()
	if srvIP == nil {
		t.Fatalf("servent address %s is not IPv4", srvAddr)
	}

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: name},
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

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatal("QUERYHIT has no file hits")
	}
	hit := qh.Hits[0]
	if hit.FileIndex != index {
		t.Fatalf("file index = %d, want %d", hit.FileIndex, index)
	}
	if hit.FileSize != uint32(size) {
		t.Fatalf("file size = %d, want %d", hit.FileSize, size)
	}

	// Retarget the hit's source at the servent that actually serves
	// the bytes; the control-protocol peer does not speak HTTP.
	qh.IP = [4]byte{srvIP[0], srvIP[1], srvIP[2], srvIP[3]}
	qh.Port = uint16(srvAddr.Port)

	destDir := t.TempDir()
	res, err := engA.Downloader(qh, hit).Fetch(context.Background(), destDir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Path == "" {
		t.Fatal("Fetch returned no path")
	}

	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if len(got) != size {
		t.Fatalf("destination size = %d, want %d", len(got), size)
	}
	if int(hit.FileSize) != size {
		t.Fatalf("hit.FileSize = %d, want %d", hit.FileSize, size)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("destination bytes do not match served content")
	}
	if _, err := os.Stat(filepath.Join(destDir, name)); err != nil {
		t.Fatalf("expected file %s on disk: %v", name, err)
	}
}

