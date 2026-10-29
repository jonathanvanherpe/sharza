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

// TestSearchAndDownloadComposes proves the P1 exit gate at its smallest
// verifiable unit: Engine.Search and Engine.Downloader/Fetch compose into
// one completed transfer over real TCP. A scripted 0.6 peer answers the
// QUERY with a QUERYHIT naming an httptest servent's real address; Search
// collects that hit by descriptor ID and discards a second hit carrying an
// unregistered ID; the collected hit then drives a download that writes
// the served bytes into a temp dir.
func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1234
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

	// A name that needs sanitising, so the composition proves the
	// downloader's sanitiser runs on a hit that came back from Search.
	hostileName := "../../etc/passwd"

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})
	defer cancelA()

	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

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

	// Matching hit: carries the descriptor ID of the QUERY and names the
	// httptest servent as its source.
	qh, _ := hitFor(t, srv, index, uint32(size), hostileName)
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	// Unregistered ID: must be ignored by Search and not appear in its
	// results, even though it is still delivered to the callback.
	bogusQH := QueryHit{
		HitCount: 1,
		Port:     1234,
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 9, FileSize: 9, FileName: "wrong.mp3"}},
	}
	bogusHp := EncodeQueryHit(bogusQH)
	bogus := testID(0x5A)
	if hdr.ID == bogus {
		t.Fatal("test setup: descriptor ID collided with the bogus one")
	}
	sendMsg(t, conn, Header{ID: bogus, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(bogusHp))}, bogusHp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) != 1 {
		t.Fatalf("Search returned %d hits, want 1 (the unregistered ID must be ignored)", len(res.hits))
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatal("collected hit has no file hits")
	}
	gotHit := gotQH.Hits[0]

	dir := t.TempDir()
	dres, err := engA.Downloader(gotQH, gotHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantName := sanitizeFileName(hostileName)
	wantPath := filepath.Join(dir, wantName)
	if dres.Path != wantPath {
		t.Errorf("result path = %q, want %q", dres.Path, wantPath)
	}
	if dres.Bytes != int64(size) {
		t.Errorf("byte count = %d, want %d", dres.Bytes, size)
	}
	if dres.Offset != 0 {
		t.Errorf("offset = %d, want 0", dres.Offset)
	}
	if filepath.Dir(dres.Path) != dir {
		t.Errorf("path not contained in dir: %s", dres.Path)
	}
	if base := filepath.Base(dres.Path); base != wantName {
		t.Errorf("sanitised file name = %q, want %q", base, wantName)
	}
	fi, err := os.Stat(dres.Path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if fi.Size() != int64(size) {
		t.Errorf("on-disk size = %d, want %d", fi.Size(), size)
	}
	onDisk, err := os.ReadFile(dres.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
}
