// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end composition test: one engine searches a connected peer
// that bears a catalogue, takes the resulting QUERYHIT/FileHit, and
// fetches the named file over HTTP from a servent standing in for that
// peer. It proves that Engine.Search and Downloader.Fetch compose into
// a single completed transfer over real TCP.

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
		index = 7
		size  = 1234
		name  = "song.mp3"
	)
	content := testContent(size)

	// Servent standing in for the peer: serves the file bytes over HTTP
	// at the Gnutella download path, with the headers a real servent sends.
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

	// Peer bearing the catalogue.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: name},
		},
	})
	defer cancelB()

	// Searching leaf.
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
		t.Fatal("Search returned no hits, want the peer's QUERYHIT")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatalf("QUERYHIT %+v has no file hits", qh)
	}
	hit := qh.Hits[0]
	if hit.FileName != name {
		t.Errorf("filename = %q, want %q", hit.FileName, name)
	}
	if hit.FileSize != size {
		t.Errorf("filesize = %d, want %d", hit.FileSize, size)
	}

	// The servent stands in for the peer's file service: point the
	// QUERYHIT's source address at it so the download GET lands there.
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("servent addr is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("servent addr %s is not IPv4", ta)
	}
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)

	dir := t.TempDir()
	d := engA.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, name)
	if res.Path != wantPath {
		t.Errorf("result path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != int64(size) || res.Offset != 0 {
		t.Errorf("result = %+v, want %d bytes at offset 0", res, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	if _, err := os.Stat(res.Path); err != nil {
		t.Fatalf("stat result: %v", err)
	}
}