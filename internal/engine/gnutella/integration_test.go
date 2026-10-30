// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

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

// TestSearchAndDownloadEndToEnd proves the P1 exit-gate composition: a
// search over real TCP collects a QUERYHIT, and the Downloader built from
// that hit fetches the file's bytes from the advertised source. No single
// primitive is exercised in isolation; the test fails if Search does not
// collect the hit, if Downloader does not target the advertised source, or
// if the bytes on disk do not match the servent's bytes.
func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 42
		size  = 2048
		name  = "shared.bin"
	)
	content := testContent(size)

	// The servent's HTTP side: a real httptest listener serving the
	// file at /gnutella/<index> with matching declared lengths.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)

	// Engine B shares the catalogue and advertises the HTTP listener as
	// its download source.
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener addr type %T", srv.Listener.Addr())
	}
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: name},
		},
		DownloadAddr: srv.Listener.Addr().String(),
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
		Peers:           []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search(name)
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
	if hit.FileIndex != index || hit.FileSize != uint32(size) {
		t.Fatalf("hit = %+v, want index %d size %d", hit, index, size)
	}
	// The advertised source must be the HTTP listener.
	if qh.Port != uint16(ta.Port) {
		t.Errorf("qh.Port = %d, want %d", qh.Port, ta.Port)
	}
	if qh.IP != [4]byte{127, 0, 0, 1} {
		t.Errorf("qh.IP = %v, want 127.0.0.1", qh.IP)
	}

	dir := t.TempDir()
	d := engA.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != int64(size) {
		t.Errorf("Bytes = %d, want %d", res.Bytes, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)", len(onDisk), len(content))
	}
	if fi, err := os.Stat(res.Path); err != nil || fi.Size() != int64(size) {
		t.Errorf("destination size = %v, want %d", fi.Size(), size)
	}
}
