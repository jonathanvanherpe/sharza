// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Search-and-download integration: Engine.SearchAndDownload over real
// TCP, end to end. A live engine A is linked to a scripted 0.6 servent
// B that answers a QUERY with a QUERYHIT, and an httptest HTTP server
// that serves the file the QUERYHIT names. Nothing here uses an
// in-memory pipe: the QUERY and QUERYHIT travel over a real TCP
// connection the way they would against a gtk-gnutella peer, and the
// file travels over a second real TCP connection to the HTTP servent.
//
// The three cases cover the leg's whole contract: a hit that resolves
// into a complete file at a sanitised path, a partial file on disk that
// the same call resumes, and an unusable hit that errors without
// writing anything.

import (
	"bufio"
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
	"strings"
	"testing"
	"time"
)

// startFileServent serves content at /gnutella/<index> and returns a
// QueryHit/FileHit pair naming its real address. It mirrors the whole
// file, and answers a Range only when it names a valid prefix, so a
// resume that lost its Range header is caught by the resulting size
// mismatch rather than silently re-serving the whole file.
func startFileServent(t *testing.T, index, size uint32, name string, content []byte) (QueryHit, FileHit) {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		rng := r.Header.Get("Range")
		if rng == "" || !strings.HasPrefix(rng, "bytes=") {
			w.Header().Set("Content-Length", strconv.Itoa(int(size)))
			w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(int(size)))
			_, _ = w.Write(content)
			return
		}
		startStr := strings.TrimSuffix(strings.TrimPrefix(rng, "bytes="), "-")
		start64, err := strconv.ParseInt(startStr, 10, 64)
		if err != nil || start64 < 0 || start64 >= int64(size) {
			w.Header().Set("Content-Length", strconv.Itoa(int(size)))
			_, _ = w.Write(content)
			return
		}
		start := int(start64)
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", start, size-1, size))
		w.Header().Set("Content-Length", strconv.Itoa(int(size)-start))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(int(size)))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(content[start:])
	}))
	t.Cleanup(srv.Close)

	qh, hit := hitFor(t, srv, index, size, name)
	return qh, hit
}

// linkServent connects a scripted 0.6 client to eng and waits until the
// engine has accepted it, so a QUERY is guaranteed to have somewhere to
// go.
func linkServent(t *testing.T, eng *Engine) (*bufio.Reader, net.Conn) {
	t.Helper()
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)
	return r, conn
}

// runSearchAndDownload starts SearchAndDownload in its own goroutine and
// returns a channel that yields its single result. The caller must then
// answer the QUERY (via the reader from linkServent) before the channel
// can produce anything.
func runSearchAndDownload(ctx context.Context, eng *Engine, q Query, dir string) chan downloadAttempt {
	ch := make(chan downloadAttempt, 1)
	go func() {
		job, err := eng.SearchAndDownload(ctx, q, dir)
		ch <- downloadAttempt{job, err}
	}()
	return ch
}

// downloadAttempt carries one SearchAndDownload outcome to the test.
type downloadAttempt struct {
	job *DownloadJob
	err error
}

func TestSearchAndDownload_CompletesSearchAndFetch(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)
	// A hostile name: path separators and leading dots must not escape
	// dir. sanitizeFileName reduces it to "evil.mp3".
	hostileName := "../../evil.mp3"
	wantFile := "evil.mp3"

	qh, _ := startFileServent(t, index, size, hostileName, content)

	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})
	r, conn := linkServent(t, engA)

	dir := t.TempDir()
	ch := runSearchAndDownload(context.Background(), engA, Query{Search: "song"}, dir)

	// The engine sends one QUERY; decode it to check the caller's
	// criteria reached the wire.
	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	gotQuery, err := DecodeQuery(payload)
	if err != nil {
		t.Fatalf("decode query: %v", err)
	}
	if gotQuery.Search != "song" {
		t.Errorf("query criteria = %q, want %q", gotQuery.Search, "song")
	}

	// Answer under the QUERY's own descriptor ID, from the HTTP
	// servent's real address.
	qh.HitCount = 1
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	var got downloadAttempt
	select {
	case got = <-ch:
	case <-time.After(testDeadline):
		t.Fatal("SearchAndDownload did not return")
	}
	if got.err != nil {
		t.Fatalf("SearchAndDownload: %v", got.err)
	}
	if got.job.Hit == nil {
		t.Fatal("job.Hit is nil; the chosen QUERYHIT must be returned")
	}
	if got.job.Hit.Port != qh.Port {
		t.Errorf("job.Hit.Port = %d, want the chosen hit's %d", got.job.Hit.Port, qh.Port)
	}
	if got.job.Hit.IP != qh.IP {
		t.Errorf("job.Hit.IP = %v, want the chosen hit's %v", got.job.Hit.IP, qh.IP)
	}

	// The path is inside dir, under the sanitised single-component name.
	wantPath := filepath.Join(dir, wantFile)
	if got.job.Path != wantPath {
		t.Errorf("job.Path = %q, want %q", got.job.Path, wantPath)
	}
	if !strings.HasPrefix(got.job.Path, dir+string(filepath.Separator)) {
		t.Errorf("job.Path %q escapes dir %q", got.job.Path, dir)
	}
	if got.job.Size != size {
		t.Errorf("job.Size = %d, want %d", got.job.Size, size)
	}

	onDisk, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}

func TestSearchAndDownload_ResumesPartialFile(t *testing.T) {
	const (
		index   = 42
		size    = 900
		partial = 300
	)
	content := testContent(size)
	name := "resume.mp3"

	qh, _ := startFileServent(t, index, size, name, content)

	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})
	r, conn := linkServent(t, engA)

	dir := t.TempDir()
	// Seed a valid prefix under the sanitised name, as a previous
	// interrupted Fetch would have left it.
	if err := os.WriteFile(filepath.Join(dir, name), content[:partial], 0o644); err != nil {
		t.Fatalf("seed partial: %v", err)
	}

	ch := runSearchAndDownload(context.Background(), engA, Query{Search: "resume"}, dir)

	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	qh.HitCount = 1
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	var got downloadAttempt
	select {
	case got = <-ch:
	case <-time.After(testDeadline):
		t.Fatal("SearchAndDownload did not return")
	}
	if got.err != nil {
		t.Fatalf("SearchAndDownload: %v", got.err)
	}

	wantPath := filepath.Join(dir, name)
	if got.job.Path != wantPath {
		t.Errorf("job.Path = %q, want %q", got.job.Path, wantPath)
	}
	// The job reports the whole file's size even though only the tail
	// arrived this call.
	if got.job.Size != size {
		t.Errorf("job.Size = %d, want the full %d", got.job.Size, size)
	}
	onDisk, err := os.ReadFile(wantPath)
	if err != nil {
		t.Fatalf("read resumed file: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("resumed file (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}

func TestSearchAndDownload_NoSuitableHit(t *testing.T) {
	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
	})
	r, conn := linkServent(t, engA)

	dir := filepath.Join(t.TempDir(), "downloads")
	ch := runSearchAndDownload(context.Background(), engA, Query{Search: "nothing"}, dir)

	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	// A QUERYHIT with a zero port and an unspecified address: it cannot
	// be dialled, so it is not a usable hit even though it names a file.
	bad := QueryHit{
		HitCount: 1,
		Port:     0,
		IP:       [4]byte{0, 0, 0, 0},
		Hits:     []FileHit{{FileIndex: 5, FileSize: 10, FileName: "ghost.mp3"}},
	}
	hp := EncodeQueryHit(bad)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	var got downloadAttempt
	select {
	case got = <-ch:
	case <-time.After(testDeadline):
		t.Fatal("SearchAndDownload did not return")
	}
	if !errors.Is(got.err, ErrNoSuitableHit) {
		t.Fatalf("err = %v, want ErrNoSuitableHit", got.err)
	}
	if got.job != nil {
		t.Errorf("job = %+v, want nil on an unusable hit", got.job)
	}
	// Nothing may be created: not dir itself, not any file in its parent.
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Errorf("dir exists after an unusable hit (stat err = %v); selection must not touch disk", err)
	}
	entries, err := os.ReadDir(filepath.Dir(dir))
	if err != nil {
		t.Fatalf("read parent of dir: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("parent of dir holds %d entries after an unusable hit, want 0", len(entries))
	}
}
