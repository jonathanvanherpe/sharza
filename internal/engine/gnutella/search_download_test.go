// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

// TestSearchAndDownloadComposes is the end-to-end proof that Engine.Search
// and Downloader.Fetch (via Engine.Downloader) compose into one completed
// transfer over real TCP and real HTTP: a QUERY goes out, a QUERYHIT
// naming an HTTP-served file comes back, and that file is fetched and
// size-checked into the destination directory.
func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
		name  = "payload.bin"
	)
	content := testContent(size)

	// Real HTTP servent stand-in for the file named by the QUERYHIT.
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

	// Engine B is a real peer with a catalogue entry, so the direct link
	// between A and B exists and carries traffic.
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: name},
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

	// A scripted peer links to engine A and answers A's QUERY with a
	// QUERYHIT naming the HTTP-served file, echoing the QUERY's
	// descriptor ID. This is the existing scripted-peer seam.
	spR, spConn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 2)

	type searchResult struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan searchResult, 1)
	go func() {
		hits, err := engA.Search("test")
		resCh <- searchResult{hits, err}
	}()

	hdr, payload := readMsg(t, spR)
	if hdr.Type != MsgQuery {
		t.Fatalf("scripted peer first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	qh, _ := hitFor(t, srv, uint32(index), uint32(size), name)
	hp := EncodeQueryHit(qh)
	sendMsg(t, spConn, Header{
		ID:     hdr.ID,
		Type:   MsgQueryHit,
		TTL:    6,
		Hops:   0,
		Length: uint32(len(hp)),
	}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}

	// Find the hit naming the served file.
	srvAddr := srv.Listener.Addr().String()
	var chosenQH QueryHit
	var chosenHit FileHit
	found := false
	for _, q := range res.hits {
		for _, h := range q.Hits {
			if net.JoinHostPort(net.IP(q.IP[:]).String(), strconv.Itoa(int(q.Port))) == srvAddr {
				chosenQH = q
				chosenHit = h
				found = true
				break
			}
		}
		if found {
			break
		}
	}
	if !found {
		t.Fatalf("Search returned no hit naming the served file (got %+v)", res.hits)
	}
	if chosenHit.FileName != name {
		t.Errorf("served hit filename = %q, want %q", chosenHit.FileName, name)
	}

	dir := t.TempDir()
	dr, err := engA.Downloader(chosenQH, chosenHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if dr.Bytes != int64(size) {
		t.Errorf("Bytes = %d, want %d", dr.Bytes, size)
	}
	info, err := os.Stat(dr.Path)
	if err != nil {
		t.Fatalf("stat result: %v", err)
	}
	if info.Size() != int64(size) {
		t.Errorf("on-disk size = %d, want %d", info.Size(), size)
	}
	onDisk, err := os.ReadFile(dr.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
	_ = spConn
}
