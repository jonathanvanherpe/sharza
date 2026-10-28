// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSearchAndDownloadComposes proves that Engine.Search and
// Downloader.Fetch (reached through Engine.Downloader) compose into one
// completed download: a QUERY goes out over a real TCP link, the
// answering QUERYHIT names a real HTTP servent, and Fetch pulls the file
// from that servent byte-for-byte.
func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 42
		size  = 2048
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

	qh0, hit0 := hitFor(t, srv, index, size, "compose.bin")

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     200 * time.Millisecond,
	})
	defer cancelA()

	// A scripted 0.6 peer links into the engine over real TCP and answers
	// the QUERY that Search sends.
	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Search("compose")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	// Answer with a QUERYHIT whose source address is the HTTP servent, so
	// the hit Search returns can drive a real download.
	qh := QueryHit{
		HitCount: 1,
		Port:     qh0.Port,
		IP:       qh0.IP,
		Speed:    0,
		Hits:     []FileHit{hit0},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatal("QUERYHIT has no file hits")
	}
	gotHit := gotQH.Hits[0]

	dir := t.TempDir()
	d := engA.Downloader(gotQH, gotHit)
	dr, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, "compose.bin")
	if dr.Path != wantPath {
		t.Errorf("result path = %q, want %q", dr.Path, wantPath)
	}
	if dr.Bytes != size {
		t.Errorf("result bytes = %d, want %d", dr.Bytes, size)
	}

	onDisk, err := os.ReadFile(dr.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	fi, err := os.Stat(dr.Path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if fi.Size() != size {
		t.Errorf("on-disk size = %d, want %d", fi.Size(), size)
	}
}