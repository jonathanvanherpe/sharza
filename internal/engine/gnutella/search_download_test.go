// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes proves the P1 exit-gate slice: one
// Engine.Search over real TCP and one Engine.Downloader.Fetch compose into
// a single completed transfer. A scripted 0.6 peer answers the QUERY with
// a QUERYHIT naming an httptest-served file; Search collects that hit by
// descriptor ID, and Fetch moves the bytes into the caller's directory.

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

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	// The file's real source: an httptest server speaking HTTP over TCP,
	// exactly like a servent answering GET /gnutella/<index>.
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

	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    500 * time.Millisecond,
		Logf:             t.Logf,
	})
	defer cancel()

	// A scripted 0.6 peer links in and will answer the QUERY.
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("needle")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	// Build a QUERYHIT naming the httptest server as the servent, using a
	// hostile file name so the Fetch path must sanitise it.
	hostileName := "../../etc/passwd"
	qhSrv, hitSrv := hitFor(t, srv, index, uint32(size), hostileName)

	qh := QueryHit{
		HitCount: 1,
		Port:     qhSrv.Port,
		IP:       qhSrv.IP,
		Speed:    0,
		Hits:     []FileHit{hitSrv},
	}

	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	// Also send a QUERYHIT under an unregistered descriptor ID: a search
	// that correlates by ID must not attribute it to this query.
	bogus := testID(0x5A)
	if bogus == hdr.ID {
		bogus = testID(0x5B)
	}
	bogusHP := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: bogus, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(bogusHP))}, bogusHP)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) != 1 {
		t.Fatalf("Search returned %d hits, want exactly the 1 whose descriptor ID matched", len(res.hits))
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatal("matched QUERYHIT carries no file hits")
	}
	gotHit := gotQH.Hits[0]
	if gotHit.FileSize != uint32(size) {
		t.Fatalf("hit size = %d, want %d", gotHit.FileSize, size)
	}

	// Drive the engine's Downloader + Fetch.
	dir := t.TempDir()
	d := eng.Downloader(gotQH, gotHit)
	fetchRes, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if fetchRes.Bytes != int64(size) {
		t.Errorf("Fetch bytes = %d, want %d", fetchRes.Bytes, size)
	}
	if fetchRes.Offset != 0 {
		t.Errorf("Fetch offset = %d, want 0", fetchRes.Offset)
	}
	wantBase := "etcpasswd"
	if filepath.Base(fetchRes.Path) != wantBase {
		t.Errorf("sanitised name = %q, want %q", filepath.Base(fetchRes.Path), wantBase)
	}
	if filepath.Dir(fetchRes.Path) != dir {
		t.Errorf("wrote to %q, want directly inside %q", fetchRes.Path, dir)
	}

	onDisk, err := os.ReadFile(fetchRes.Path)
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
