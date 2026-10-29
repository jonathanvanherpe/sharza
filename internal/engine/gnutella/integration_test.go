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

// TestSearchAndDownloadEndToEnd is the engine-level evidence for the
// "completes a search and a download" leg of P1's exit gate: a QUERYHIT
// returned by Engine.Search is handed to Engine.Downloader and the
// advertised bytes actually land on disk.
//
// Two gnutella engines over real TCP (engine B shares a catalogue, engine A
// dials it and searches), plus an httptest servent mirroring download_test.go
// that serves /gnutella/<index> with the declared size. Engine B's QUERYHIT
// advertises its own control port; the transfer servent is pointed at by
// redirecting the hit's source, the same redirection a real servent avoids
// because its single port demuxes both gnutella and HTTP.
func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 7
		size  = 1234
		name  = "song.mp3"
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
		t.Fatalf("listener addr is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: uint32(index), Size: uint32(size), Name: name},
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
		t.Fatal("Search returned no hits, want the QUERYHIT echoing its descriptor ID")
	}
	qh := results[0]
	if qh.HitCount < 1 || len(qh.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]

	// Redirect the hit's source to the HTTP transfer servent. Engine B's
	// QUERYHIT advertises its gnutella control port; the bytes are served
	// by the httptest servent above.
	qh.IP = [4]byte{ip[0], ip[1], ip[2], ip[3]}
	qh.Port = uint16(ta.Port)

	dir := t.TempDir()
	d := engA.Downloader(qh, hit)
	if d == nil {
		t.Fatal("Engine.Downloader returned nil")
	}
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, name)
	if res.Path != wantPath {
		t.Errorf("result path = %q, want %q", res.Path, wantPath)
	}

	fi, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("destination file missing: %v", err)
	}
	if fi.Size() != int64(size) {
		t.Errorf("destination size = %d, want %d", fi.Size(), size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("destination bytes (%d) do not match served payload (%d)", len(onDisk), len(content))
	}
}