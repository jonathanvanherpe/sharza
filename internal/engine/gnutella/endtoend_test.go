// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadCompose is the smallest end-to-end proof of the
// P1 exit gate: one scripted 0.6 peer echoes a QUERYHIT that points at
// an httptest servent, Engine.Search returns that hit, and
// Engine.Downloader(qh, hit).Fetch writes the full file to a temp dir
// and its bytes match the served bytes. No production code is exercised
// beyond the two primitives and their handoff.

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

func TestSearchAndDownloadCompose(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/7" {
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
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
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

	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}

	qh := QueryHit{
		HitCount: 1,
		Port:     uint16(ta.Port),
		IP:       [4]byte{ip[0], ip[1], ip[2], ip[3]},
		Speed:    1000,
		Hits: []FileHit{{
			FileIndex: index,
			FileSize:  size,
			FileName:  "compose.bin",
		}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT echoing its descriptor ID")
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", gotQH)
	}
	hit := gotQH.Hits[0]

	dir := t.TempDir()
	fetchRes, err := eng.Downloader(gotQH, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	wantPath := filepath.Join(dir, "compose.bin")
	if fetchRes.Path != wantPath {
		t.Errorf("result path = %q, want %q", fetchRes.Path, wantPath)
	}
	if fetchRes.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", fetchRes.Bytes, size)
	}
	onDisk, err := os.ReadFile(fetchRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}