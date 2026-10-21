// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Tests for SearchAndDownload, the composition of Search and Downloader.Fetch
// that the P1 "completes a search and a download" gate asks for.
//
// The file server is the one stand-in in the flow. The engine's listener
// does not serve file bytes, so A's QUERYHIT advertises the port of an
// httptest server that holds the catalogue payload (Options.advertisePort).
// Everything else is real: B dials A over loopback TCP, the QUERY and
// QUERYHIT cross the wire, Search collects the hit, and Fetch moves the
// bytes over real HTTP.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// catalogueName is the file A advertises and B is asked to download.
const catalogueName = "song.mp3"

// catalogueIndex is the file index A advertises for catalogueName.
const catalogueIndex = 1

// serveCatalogue stands in for A's file server: it answers
// /gnutella/<catalogueIndex> with payload and 404s everything else, so a
// request for the wrong file fails the download instead of matching it.
func serveCatalogue(t *testing.T, payload []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", catalogueIndex) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestSearchAndDownloadFetchesCatalogueBytes is the end-to-end flow: B
// searches through its one peer A, takes the hit A answers with, and
// downloads it. The returned file must hold exactly the catalogue payload.
func TestSearchAndDownloadFetchesCatalogueBytes(t *testing.T) {
	payload := testContent(4096 + 37)
	fileSrv := serveCatalogue(t, payload)
	filePort := fileSrv.Listener.Addr().(*net.TCPAddr).Port

	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: catalogueIndex, Size: uint32(len(payload)), Name: catalogueName},
		},
		advertisePort: uint16(filePort),
	})

	engB, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     500 * time.Millisecond,
		Peers:             []string{engA.Addr().String()},
	})
	waitForPeers(t, engB, 1)

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	job, err := engB.SearchAndDownload(ctx, "song", dir)
	if err != nil {
		t.Fatalf("SearchAndDownload: %v", err)
	}

	wantPath := filepath.Join(dir, catalogueName)
	if job.Path != wantPath {
		t.Errorf("Path = %q, want %q", job.Path, wantPath)
	}
	if job.Hit.FileName != catalogueName || job.Hit.FileIndex != catalogueIndex {
		t.Errorf("Hit = %+v, want index %d name %q", job.Hit, catalogueIndex, catalogueName)
	}
	if job.Bytes != int64(len(payload)) {
		t.Errorf("Bytes = %d, want %d", job.Bytes, len(payload))
	}
	if job.Offset != 0 {
		t.Errorf("Offset = %d, want 0 for a fresh download", job.Offset)
	}

	got, err := os.ReadFile(job.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("downloaded %d bytes, want the %d-byte catalogue payload (contents differ)",
			len(got), len(payload))
	}
}

// TestSearchAndDownloadNoUsableHit scripts the peer B searches through, so
// the QUERYHIT it sends can be arranged. It advertises Port 0, which no
// download can start from, and SearchAndDownload must say so rather than
// fetch anything.
func TestSearchAndDownloadNoUsableHit(t *testing.T) {
	engS, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     500 * time.Millisecond,
	})
	// The scripted 0.6 client dials the searcher, as in the Search tests.
	r, conn := dialEngine(t, engS.Addr().String())
	waitForPeers(t, engS, 1)

	dir := t.TempDir()
	type result struct {
		job *DownloadJob
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		job, err := engS.SearchAndDownload(context.Background(), "song", dir)
		resCh <- result{job, err}
	}()

	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	qh := QueryHit{
		HitCount: 1,
		Port:     0,
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: catalogueIndex, FileSize: 10, FileName: catalogueName}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if !errors.Is(res.err, ErrNoSuitableHit) {
		t.Fatalf("err = %v, want ErrNoSuitableHit", res.err)
	}
	if res.job != nil {
		t.Errorf("job = %+v, want nil when no hit is usable", res.job)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("dir holds %d entries after a refused search, want none", len(entries))
	}
}

// TestSelectHitSkipsUnusableHits pins the selection rule on its own: a hit
// with no port, an unspecified address, or no named file is skipped, and
// the first hit that qualifies wins, in the order given.
func TestSelectHitSkipsUnusableHits(t *testing.T) {
	usable := QueryHit{Port: 6346, IP: [4]byte{10, 0, 0, 2}, Hits: []FileHit{{FileIndex: 3, FileName: "b.mp3"}}}
	cases := []struct {
		name     string
		hits     []QueryHit
		wantOK   bool
		wantName string
	}{
		{name: "none", hits: nil, wantOK: false},
		{
			name: "port zero",
			hits: []QueryHit{{Port: 0, IP: [4]byte{10, 0, 0, 2}, Hits: []FileHit{{FileName: "a.mp3"}}}},
		},
		{
			name: "unspecified address",
			hits: []QueryHit{{Port: 6346, IP: [4]byte{0, 0, 0, 0}, Hits: []FileHit{{FileName: "a.mp3"}}}},
		},
		{
			name: "no named file",
			hits: []QueryHit{{Port: 6346, IP: [4]byte{10, 0, 0, 2}, Hits: []FileHit{{FileIndex: 1, FileName: ""}}}},
		},
		{
			name:     "first usable wins over later",
			hits:     []QueryHit{{Port: 0, IP: [4]byte{10, 0, 0, 2}}, usable, usable},
			wantOK:   true,
			wantName: "b.mp3",
		},
		{
			name:     "named file after an unnamed one",
			hits:     []QueryHit{{Port: 6346, IP: [4]byte{10, 0, 0, 2}, Hits: []FileHit{{FileName: ""}, {FileIndex: 4, FileName: "c.mp3"}}}},
			wantOK:   true,
			wantName: "c.mp3",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, hit, ok := selectHit(tc.hits)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && hit.FileName != tc.wantName {
				t.Errorf("selected %q, want %q", hit.FileName, tc.wantName)
			}
		})
	}
}

// TestPeerNotRegisteredUntilHandshakeCompletes pins the race that made the
// composed flow flaky. A dialed connection used to be registered as a peer
// before its handshake ran, so Search could write its QUERY into the
// handshake and the far side dropped the link. The scripted listener here
// reads the CONNECT and then holds its 200 reply: while that reply is
// pending the engine must not count the connection as a peer.
func TestPeerNotRegisteredUntilHandshakeCompletes(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	connectSeen := make(chan struct{})
	release := make(chan struct{})
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		r := bufio.NewReader(c)
		// Read the CONNECT request up to its blank line.
		for {
			line, err := r.ReadString('\n')
			if err != nil || line == "\r\n" {
				break
			}
		}
		close(connectSeen)
		<-release
		_, _ = c.Write([]byte("GNUTELLA/0.6 200 OK\r\n\r\n"))
		// Hold the link open until the test closes it.
		_, _ = io.Copy(io.Discard, r)
	}()

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{ln.Addr().String()},
	})

	select {
	case <-connectSeen:
	case <-time.After(testDeadline):
		t.Fatal("the engine never sent its CONNECT")
	}
	eng.mu.Lock()
	n := len(eng.peers)
	eng.mu.Unlock()
	if n != 0 {
		t.Fatalf("engine counts %d peer(s) while the handshake is still pending, want 0", n)
	}

	close(release)
	waitForPeers(t, eng, 1)
}
