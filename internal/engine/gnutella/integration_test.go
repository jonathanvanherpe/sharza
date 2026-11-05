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
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSearchAndDownloadEndToEnd is the smallest verifiable unit of P1's
// exit gate: one engine advertises a file, another dials it, searches,
// and turns the returned QUERYHIT into a completed download. The
// download's source address is rewritten from the answering peer to a
// stand-in httptest servent, which serves the advertised bytes at the
// Gnutella /gnutella/<index> path; the transfer is then checked
// byte-for-byte against the source.
func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 42
		size  = 2048
	)
	content := testContent(size)

	// Engine B advertises the file through its catalogue.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "shared.bin"},
		},
	})
	defer cancelB()

	// Stand-in servent: serves the advertised bytes at /gnutella/<index>.
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

	// Engine A dials B and searches.
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("shared")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	if len(qh.Hits) == 0 {
		t.Fatal("QUERYHIT carries no file hits")
	}
	hit := qh.Hits[0]
	if hit.FileIndex != index {
		t.Fatalf("file index = %d, want %d", hit.FileIndex, index)
	}
	if int(hit.FileSize) != size {
		t.Fatalf("file size = %d, want %d", hit.FileSize, size)
	}

	// Rewrite the QUERYHIT's source address to the stand-in servent,
	// so the download is fetched over real TCP from it.
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
	if res.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size)
	}

	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("downloaded file (%d bytes) does not match source (%d bytes)",
			len(onDisk), len(content))
	}
	// Sanity: the path landed inside the destination directory.
	if filepath.Dir(res.Path) != dir {
		t.Errorf("result path %q is not inside %q", res.Path, dir)
	}
}