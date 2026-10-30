// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchThenDownloadCompletesTransfer is the smallest verifiable unit
// of P1's "completes a search and a download" exit gate: one end-to-end
// integration test over real TCP proving that Engine.Search and
// Downloader.Fetch (reached through Engine.Downloader) compose into a
// single completed transfer. No production code is exercised beyond
// what the two primitives already expose.

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

func TestSearchThenDownloadCompletesTransfer(t *testing.T) {
	const (
		index = 7
		size  = 1234
	)
	content := testContent(size)

	// (b) httptest servent serving a known body at /gnutella/<index>.
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

	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}

	// Real engine with a short search window.
	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
		Logf:             t.Logf,
	})
	defer cancel()

	// (a) scripted Gnutella peer dials into the engine and answers its
	// QUERY with a QueryHit pointing at the httptest servent above.
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

	// Answer mid-window so the collection wait is what gathers it.
	time.Sleep(100 * time.Millisecond)
	qh := QueryHit{
		HitCount: 1,
		Port:     uint16(ta.Port),
		IP:       [4]byte{ip[0], ip[1], ip[2], ip[3]},
		Speed:    1000,
		Hits: []FileHit{
			{FileIndex: index, FileSize: uint32(size), FileName: "found.bin"},
		},
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
	qh0 := res.hits[0]
	if len(qh0.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", qh0)
	}
	hit := qh0.Hits[0]

	// Compose into a download through Engine.Downloader.
	dir := t.TempDir()
	d := eng.Downloader(qh0, hit)
	fetchRes, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if fetchRes.Bytes != int64(size) {
		t.Errorf("Fetch bytes = %d, want %d", fetchRes.Bytes, size)
	}
	onDisk, err := os.ReadFile(fetchRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if len(onDisk) != size {
		t.Errorf("on-disk size = %d, want %d", len(onDisk), size)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)", len(onDisk), len(content))
	}
}
