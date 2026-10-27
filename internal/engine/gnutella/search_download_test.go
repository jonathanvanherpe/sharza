// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end tests composing Engine.Search and Downloader.Fetch over real
// TCP, with an httptest servent standing in for the peer that serves the
// file. Engine A advertises a catalogue entry whose QUERYHIT Port is the
// servent's port (via advertisePort); engine B searches A, picks the
// first usable hit, and fetches the file over HTTP.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func TestSearchDownloadRoundTrip(t *testing.T) {
	const (
		index = 7
		size  = 1234
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
	serventPort := srv.Listener.Addr().(*net.TCPAddr).Port

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(size), Name: "song.mp3"},
		},
		advertisePort: uint16(serventPort),
	})
	defer cancelA()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engA.Addr().String()},
	})
	defer cancelB()

	waitForPeers(t, engB, 1)
	time.Sleep(150 * time.Millisecond)

	// Composition at the call site: Search, then pick a usable hit, then
	// Fetch. This is the evidence that the two primitives compose.
	results, err := engB.Search("song")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	qh, hit, ok := firstUsableHit(results)
	if !ok {
		t.Fatal("no usable hit from Search")
	}
	dir := t.TempDir()
	res, err := engB.Downloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("downloaded bytes do not match servent payload")
	}
	if filepath.Base(res.Path) != "song.mp3" {
		t.Errorf("path base = %q, want song.mp3", filepath.Base(res.Path))
	}
	if res.Bytes != size {
		t.Errorf("Bytes = %d, want %d", res.Bytes, size)
	}

	// Fused entry point must produce the same outcome.
	dir2 := t.TempDir()
	job, err := engB.SearchAndDownload(context.Background(), Query{Search: "song"}, dir2)
	if err != nil {
		t.Fatalf("SearchAndDownload: %v", err)
	}
	if job == nil || job.Path == "" {
		t.Fatal("SearchAndDownload returned no job")
	}
	onDisk2, err := os.ReadFile(job.Path)
	if err != nil {
		t.Fatalf("read fused result: %v", err)
	}
	if !bytes.Equal(onDisk2, content) {
		t.Errorf("fused downloaded bytes do not match servent payload")
	}
	if job.Size != size {
		t.Errorf("job.Size = %d, want %d", job.Size, size)
	}
	if job.Hit == nil || job.Hit.Port != uint16(serventPort) {
		t.Errorf("job.Hit.Port = %v, want %d", job.Hit, serventPort)
	}
}

func TestSearchDownloadSkipsUnusableHits(t *testing.T) {
	cases := []struct {
		name string
		qh   QueryHit
	}{
		{
			name: "zero port",
			qh: QueryHit{
				HitCount: 1,
				Port:     0,
				IP:       [4]byte{127, 0, 0, 1},
				Hits:     []FileHit{{FileIndex: 1, FileSize: 10, FileName: "a.bin"}},
			},
		},
		{
			name: "unspecified IP",
			qh: QueryHit{
				HitCount: 1,
				Port:     6346,
				IP:       [4]byte{0, 0, 0, 0},
				Hits:     []FileHit{{FileIndex: 2, FileSize: 10, FileName: "b.bin"}},
			},
		},
		{
			name: "empty file",
			qh: QueryHit{
				HitCount: 1,
				Port:     6346,
				IP:       [4]byte{127, 0, 0, 1},
				Hits:     []FileHit{{FileIndex: 3, FileSize: 0, FileName: "c.bin"}},
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			eng, cancel := startEngine(t, Options{
				KeepAliveInterval: time.Hour,
				IdleTimeout:       10 * time.Second,
				SearchTimeout:     300 * time.Millisecond,
			})
			defer cancel()

			// Scripted peer dials in and answers the QUERY with the
			// unusable hit, echoing the query's descriptor ID.
			r, conn := dialEngine(t, eng.Addr().String())
			waitForPeers(t, eng, 1)

			dir := t.TempDir()
			type result struct {
				job *DownloadJob
				err error
			}
			resCh := make(chan result, 1)
			go func() {
				job, err := eng.SearchAndDownload(context.Background(), Query{Search: "x"}, dir)
				resCh <- result{job, err}
			}()

			hdr, payload := readMsg(t, r)
			if hdr.Type != MsgQuery {
				t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
			}
			if _, err := DecodeQuery(payload); err != nil {
				t.Fatalf("query payload: %v", err)
			}
			tc.qh.HitCount = uint8(len(tc.qh.Hits))
			hp := EncodeQueryHit(tc.qh)
			sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

			res := <-resCh
			if !errors.Is(res.err, ErrNoSuitableHit) {
				t.Fatalf("err = %v, want ErrNoSuitableHit", res.err)
			}
			if res.job != nil {
				t.Fatalf("job = %+v, want nil", res.job)
			}
			// No file should have been written: selection failed before
			// any Fetch, so the directory stays empty.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("readdir: %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("directory not empty after failed selection: %v", entries)
			}
		})
	}
}

func TestSearchDownloadContextCancellation(t *testing.T) {
	// A silent peer keeps the collection window open for the whole
	// SearchTimeout; cancelling the context must end it early.
	eng, cancelEng := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     2 * time.Second,
	})
	defer cancelEng()

	// Silent peer: completes handshake, never answers.
	_, silentConn := dialEngine(t, eng.Addr().String())
	defer silentConn.Close()
	waitForPeers(t, eng, 1)

	ctx, cancel := context.WithCancel(context.Background())
	start := time.Now()
	resCh := make(chan error, 1)
	go func() {
		_, err := eng.SearchAndDownload(ctx, Query{Search: "cancel"}, t.TempDir())
		resCh <- err
	}()

	time.Sleep(100 * time.Millisecond)
	cancel()

	select {
	case err := <-resCh:
		if err == nil {
			t.Fatal("expected error from cancelled search, got nil")
		}
		if !errors.Is(err, context.Canceled) {
			// Accept either ctx.Err() or ErrNoSuitableHit as long as it
			// returned promptly; log for diagnosis.
			t.Logf("returned err: %v", err)
		}
	case <-time.After(1 * time.Second):
		t.Fatal("SearchAndDownload did not return promptly after cancellation")
	}
	if elapsed := time.Since(start); elapsed > 1*time.Second {
		t.Errorf("took %s, want < 1s (collection wait not cancelled)", elapsed)
	}
}

func TestSearchDownloadNoDiskWritesOnFailure(t *testing.T) {
	// A search that yields only unusable hits must not create the
	// destination file.
	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     300 * time.Millisecond,
	})
	defer cancel()

	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	dir := t.TempDir()
	type result struct {
		err error
	}
	resCh := make(chan result, 1)
	go func() {
		_, err := eng.SearchAndDownload(context.Background(), Query{Search: "x"}, dir)
		resCh <- result{err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}
	qh := QueryHit{
		HitCount: 1,
		Port:     0, // unusable
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 1, FileSize: 10, FileName: "should-not-exist.bin"}},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if !errors.Is(res.err, ErrNoSuitableHit) {
		t.Fatalf("err = %v, want ErrNoSuitableHit", res.err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("readdir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("directory not empty after failed selection: %v", entries)
	}
}
