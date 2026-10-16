// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Fetch tests: the end-to-end search -> download that Engine.Fetch
// composes, over real TCP.
//
// TestFetchSearchThenDownloadEndToEnd is the two-engine loop the P1 exit
// gate wants: engine B answers a QUERY from its Catalogue and serves the
// download from the same port its QUERYHIT advertises; engine A searches
// and downloads from it. No part of that exchange is scripted.
//
// The remaining tests arrange cases a second engine cannot: a zero-hit
// QUERYHIT for an empty catalogue (still engine B's behaviour, but a
// scripted peer lets the test pin the sentinel without a real search), a
// servent that serves a body the hit's size disagrees with, and a
// cancelled context. Those use a scripted Gnutella 0.6 servent (a plain
// TCP peer, as in peer_test.go) to answer the QUERY and a real
// httptest.NewServer as the HTTP servent the QUERYHIT points at. Both
// halves run over real TCP, so Engine.Fetch itself is what is under test
// in every case.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// fetchTimeout is the search window the Fetch tests use. It only has to
// be long enough for one loopback pair to answer; the tests wait on the
// scripted servent's handshake rather than on a sleep, so it does not
// matter if it is generous.
const fetchTimeout = 500 * time.Millisecond

// httpSource starts an httptest servent and returns the IPv4 address and
// port a QUERYHIT must advertise to point at it.
func httpSource(t *testing.T, h http.Handler) (net.IP, uint16) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("http listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("http listener %s is not IPv4", ta)
	}
	return ip, uint16(ta.Port)
}

// startScriptedServent listens on loopback and answers every QUERY a
// dialing engine sends with one QUERYHIT carrying hits, all pointing at
// the given HTTP source. The returned channel receives once the 0.6
// handshake for the first connection has completed, so a test can call
// Fetch without racing the handshake (the engine adds the peer to its
// map before the handshake, so waitForPeers alone would not be enough).
func startScriptedServent(t *testing.T, httpIP net.IP, httpPort uint16, hits []FileHit) (string, <-chan struct{}) {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scripted servent listen: %v", err)
	}
	t.Cleanup(func() { _ = l.Close() })
	ready := make(chan struct{}, 1)
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go scriptedServent(c, httpIP, httpPort, hits, ready)
		}
	}()
	return l.Addr().String(), ready
}

// scriptedServent speaks the server side of the 0.6 handshake and then
// answers the first QUERY with one QUERYHIT. It never fails the test: it
// runs on its own goroutine and simply returns when the connection ends.
func scriptedServent(conn net.Conn, httpIP net.IP, httpPort uint16, hits []FileHit, ready chan<- struct{}) {
	defer conn.Close()
	r := bufio.NewReader(conn)
	hs, err := ReadHandshake(r)
	if err != nil || !hs.Request {
		return
	}
	if _, err := conn.Write([]byte("GNUTELLA/0.6 200 OK\r\n\r\n")); err != nil {
		return
	}
	if _, err := ReadHandshake(r); err != nil {
		return
	}
	select {
	case ready <- struct{}{}:
	default:
	}
	for {
		hdr, err := DecodeHeader(r)
		if err != nil {
			return
		}
		payload := make([]byte, hdr.Length)
		if _, err := io.ReadFull(r, payload); err != nil {
			return
		}
		if hdr.Type != MsgQuery {
			continue
		}
		qh := QueryHit{
			HitCount: uint8(len(hits)),
			Port:     httpPort,
			Hits:     hits,
		}
		copy(qh.IP[:], httpIP.To4())
		hp := EncodeQueryHit(qh)
		resp := Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}
		buf := resp.AppendTo(nil)
		buf = append(buf, hp...)
		if _, err := conn.Write(buf); err != nil {
			return
		}
	}
}

// startFetchEngine boots an engine whose only peer is the scripted
// servent and waits until the handshake is done, so a Fetch in the test
// reaches the candidate loop rather than racing the connection setup.
func startFetchEngine(t *testing.T, addr string, ready <-chan struct{}) *Engine {
	t.Helper()
	// startEngine registers its own cancel cleanup, so the engine is shut
	// down when the test ends without anything extra here.
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     fetchTimeout,
		Peers:             []string{addr},
	})
	waitForPeers(t, eng, 1)
	select {
	case <-ready:
	case <-time.After(testDeadline):
		t.Fatal("scripted servent did not complete the 0.6 handshake")
	}
	return eng
}

// TestFetchSearchThenDownloadEndToEnd is the P1 exit-gate artifact: two
// real engines complete the loop. Engine B shares a file from its
// Catalogue and serves it on the same port its QUERYHIT advertises;
// engine A sends a real QUERY over a real 0.6 link, takes the QUERYHIT
// that answers it, and moves the named file over real HTTP. The bytes on
// disk are compared exactly, so a short, long or misaligned body cannot
// pass.
func TestFetchSearchThenDownloadEndToEnd(t *testing.T) {
	const (
		index = 5
		size  = 2048
	)
	content := testContent(size)

	// Engine B's shared file, named by index in its catalogue. The
	// download GET is served from Path on the Gnutella port.
	shared := filepath.Join(t.TempDir(), "archive.tar.gz")
	if err := os.WriteFile(shared, content, 0o644); err != nil {
		t.Fatalf("write shared file: %v", err)
	}
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: "archive.tar.gz", Path: shared},
		},
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	// The dial loop registers the peer before the 0.6 handshake has
	// finished; a QUERY written into a half-open handshake corrupts it.
	// There is no exported "handshake complete" signal, so this waits
	// for the peer and gives the loopback exchange a moment to finish,
	// as the two-engine search test does.
	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	dir := t.TempDir()
	res, err := engA.Fetch(context.Background(), "archive", dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, "archive.tar.gz")
	if res.Path != wantPath {
		t.Errorf("Path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != size {
		t.Errorf("Bytes = %d, want %d", res.Bytes, size)
	}
	wantHit := FileHit{FileIndex: index, FileSize: size, FileName: "archive.tar.gz"}
	if res.FileHit != wantHit {
		t.Errorf("FileHit = %+v, want the advertised %+v", res.FileHit, wantHit)
	}
	if want := engB.Addr().String(); res.Source != want {
		t.Errorf("Source = %q, want the serving engine %q", res.Source, want)
	}
	if res.QueryHit.HitCount != 1 || len(res.QueryHit.Hits) != 1 {
		t.Errorf("QueryHit = %+v, want one hit", res.QueryHit)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read %s: %v", res.Path, err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match the served content (%d bytes)",
			len(onDisk), len(content))
	}
}

// TestFetchNoHits pins the empty-search path: an engine with no live peer
// writes nothing, collects nothing, and Fetch must say so with ErrNoHits
// rather than trying to download a candidate that does not exist.
func TestFetchNoHits(t *testing.T) {
	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     100 * time.Millisecond,
	})
	defer cancel()

	_, err := eng.Fetch(context.Background(), "nothing", t.TempDir())
	if !errors.Is(err, ErrNoHits) {
		t.Fatalf("Fetch error = %v, want ErrNoHits", err)
	}
}

// TestFetchAllCandidatesMismatchLeavesNoPartial is the all-mismatch
// path: the QUERYHIT declares one size and the servent serves a different
// body length, so every candidate is refused, Fetch reports the last
// failure, and the destination is restored rather than left holding the
// refused bytes. The body is chunked and carries no length header, so the
// count of received bytes against the declared size is the check that
// catches it.
func TestFetchAllCandidatesMismatchLeavesNoPartial(t *testing.T) {
	const (
		declared = 512
		served   = 128
	)
	body := testContent(served)
	ip, port := httpSource(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Flush first so net/http cannot infer a Content-Length from the
		// write: a declared length the client trusted would mask the
		// body-length check this test exists to pin.
		writeChunked(w, body)
	}))
	hits := []FileHit{
		{FileIndex: 1, FileSize: declared, FileName: "short-a.bin"},
		{FileIndex: 2, FileSize: declared, FileName: "short-b.bin"},
	}
	addr, ready := startScriptedServent(t, ip, port, hits)
	eng := startFetchEngine(t, addr, ready)

	dir := t.TempDir()
	_, err := eng.Fetch(context.Background(), "short", dir)
	if err == nil {
		t.Fatal("Fetch succeeded, want a size-mismatch failure")
	}
	if !errors.Is(err, ErrSizeMismatch) {
		t.Errorf("Fetch error = %v, want ErrSizeMismatch (the only integrity check Gnutella 1 has)", err)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			t.Fatalf("stat %s: %v", e.Name(), err)
		}
		if fi.Size() != 0 {
			t.Errorf("%s is %d bytes after a refused transfer, want 0", e.Name(), fi.Size())
		}
	}
}

// TestFetchHitsButNoFiles pins the sentinel for a search that answered
// but named nothing: an engine whose Catalogue is empty still replies to
// a QUERY with a zero-hit QUERYHIT (handleQuery sends one regardless), so
// Fetch sees a hit but no candidate to try and must say so, not fall back
// to ErrNoHits.
func TestFetchHitsButNoFiles(t *testing.T) {
	ip, port := httpSource(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	addr, ready := startScriptedServent(t, ip, port, nil)
	eng := startFetchEngine(t, addr, ready)

	_, err := eng.Fetch(context.Background(), "nothing", t.TempDir())
	if !errors.Is(err, ErrAllCandidatesFailed) {
		t.Fatalf("Fetch error = %v, want ErrAllCandidatesFailed", err)
	}
}

// TestFetchHonoursCancelledContext pins the cancellable half: Search
// still runs its full window (it has no context), but once a candidate
// exists Fetch must notice the cancelled context before starting a
// transfer and return it, rather than fetching anyway.
func TestFetchHonoursCancelledContext(t *testing.T) {
	const (
		index = 9
		size  = 1024
	)
	content := testContent(size)
	path := "/gnutella/" + strconv.Itoa(index)
	ip, port := httpSource(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	addr, ready := startScriptedServent(t, ip, port,
		[]FileHit{{FileIndex: index, FileSize: size, FileName: "x.bin"}})
	eng := startFetchEngine(t, addr, ready)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := eng.Fetch(ctx, "x", t.TempDir()); !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch error = %v, want context.Canceled", err)
	}
}

// TestFetchOrdersCandidatesByDescendingSize pins the order candidates are
// considered in. The larger hit is advertised second and both are
// servable, so a descending order downloads it first and the smaller file
// is never written; a missing or reversed sort downloads the small one
// and the assertions go red.
func TestFetchOrdersCandidatesByDescendingSize(t *testing.T) {
	const (
		smallIndex = 1
		smallSize  = 1024
		largeIndex = 2
		largeSize  = 4096
	)
	smallContent := testContent(smallSize)
	largeContent := testContent(largeSize)
	ip, port := httpSource(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gnutella/" + strconv.Itoa(smallIndex):
			w.Header().Set("Content-Length", strconv.Itoa(smallSize))
			_, _ = w.Write(smallContent)
		case "/gnutella/" + strconv.Itoa(largeIndex):
			w.Header().Set("Content-Length", strconv.Itoa(largeSize))
			_, _ = w.Write(largeContent)
		default:
			http.NotFound(w, r)
		}
	}))
	hits := []FileHit{
		{FileIndex: smallIndex, FileSize: smallSize, FileName: "small.bin"},
		{FileIndex: largeIndex, FileSize: largeSize, FileName: "large.bin"},
	}
	addr, ready := startScriptedServent(t, ip, port, hits)
	eng := startFetchEngine(t, addr, ready)

	dir := t.TempDir()
	res, err := eng.Fetch(context.Background(), "file", dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.FileHit.FileIndex != largeIndex {
		t.Errorf("winner = index %d, want the largest declared hit (index %d)",
			res.FileHit.FileIndex, largeIndex)
	}
	if res.Bytes != largeSize {
		t.Errorf("Bytes = %d, want %d", res.Bytes, largeSize)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read %s: %v", res.Path, err)
	}
	if !bytes.Equal(onDisk, largeContent) {
		t.Errorf("winner's bytes do not match the large hit's content")
	}
	if _, err := os.Stat(filepath.Join(dir, "small.bin")); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("small.bin exists: Fetch did not stop at the first candidate that transferred")
	}
}
