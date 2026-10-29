// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// TestSearchAndDownloadComposes proves the P1 exit-gate leg: a search
// performed over a live peer connection and a download driven from one
// of its hits compose into a single completed transfer. The peer is a
// scripted 0.6 client that answers the engine's QUERY with a QUERYHIT
// naming an httptest servent; Engine.Search returns that hit, and
// Engine.Downloader(...).Fetch writes the served bytes to disk.
func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	// The servent that will actually serve the file.
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

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     300 * time.Millisecond,
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("compose")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	qh, _ := hitFor(t, srv, index, size, "compose.bin")
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 || len(res.hits[0].Hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	gotQH := res.hits[0]
	gotHit := gotQH.Hits[0]

	dir := t.TempDir()
	d := eng.Downloader(gotQH, gotHit)
	fres, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, "compose.bin")
	if fres.Path != wantPath {
		t.Errorf("result path = %q, want %q", fres.Path, wantPath)
	}
	if fres.Bytes != size {
		t.Errorf("result bytes = %d, want %d", fres.Bytes, size)
	}

	onDisk, err := os.ReadFile(fres.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("file size on disk = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}
