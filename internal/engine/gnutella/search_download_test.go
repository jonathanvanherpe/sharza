// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestSearchAndDownloadComposes proves the P1 exit-gate composition: a
// Search that is answered by a scripted peer returns a QueryHit, and
// fetching that hit through Engine.Downloader writes the served payload
// to disk with a matching size and byte count. The whole path runs over
// real TCP (engine <-> scripted peer, engine <-> httptest server).
func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
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

	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})
	defer cancel()

	// A scripted peer dials the engine and completes the handshake.
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("test")
		resCh <- result{hits: hits, err: err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	// Reply with a QUERYHIT echoing the query's descriptor ID and naming
	// the httptest server as the source.
	qh, _ := hitFor(t, srv, index, size, "song.mp3")
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatal("Search hit has no file hits")
	}
	gotHit := gotQH.Hits[0]
	if gotHit.FileSize != size {
		t.Errorf("hit size = %d, want %d", gotHit.FileSize, size)
	}

	dir := t.TempDir()
	dres, err := eng.Downloader(gotQH, gotHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch failed: %v", err)
	}

	if dres.Bytes != int64(size) {
		t.Errorf("result.Bytes = %d, want %d", dres.Bytes, size)
	}
	onDisk, err := os.ReadFile(dres.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("downloaded file (%d bytes) does not match served payload (%d bytes)",
			len(onDisk), len(content))
	}
	if int64(len(onDisk)) != int64(size) {
		t.Errorf("on-disk size = %d, want %d", len(onDisk), size)
	}
}