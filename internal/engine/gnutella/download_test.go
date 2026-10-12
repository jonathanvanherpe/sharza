// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Tests for the Gnutella 1 download client. The peer is an
// httptest.NewServer, which is a real TCP listener speaking real HTTP,
// so the transfer goes through the same net/http path a live servent
// would take; nothing here reaches the network.

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
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// testContent returns n deterministic, non-repeating bytes.
func testContent(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i % 251)
	}
	return b
}

// hitFor returns a QueryHit naming srv's real TCP address and a FileHit
// with the given index, size and name.
func hitFor(t *testing.T, srv *httptest.Server, index, size uint32, name string) (QueryHit, FileHit) {
	t.Helper()
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}
	var qh QueryHit
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)
	hit := FileHit{FileIndex: index, FileSize: size, FileName: name}
	qh.Hits = []FileHit{hit}
	return qh, hit
}

// writeChunked flushes the headers first so net/http cannot derive a
// Content-Length; the client then has only the body bytes to count.
func writeChunked(w http.ResponseWriter, body []byte) {
	if f, ok := w.(http.Flusher); ok {
		f.Flush()
	}
	_, _ = w.Write(body)
}

func TestDownloadFullFileAndRequestHeaders(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	var got struct {
		path, xgcl, rng, accept, conn, ua string
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.path = r.URL.Path
		got.xgcl = r.Header.Get("X-Gnutella-Content-Length")
		got.rng = r.Header.Get("Range")
		got.accept = r.Header.Get("Accept")
		got.conn = r.Header.Get("Connection")
		got.ua = r.Header.Get("User-Agent")
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	qh, hit := hitFor(t, srv, index, size, "song.mp3")
	dir := t.TempDir()
	res, err := NewDownloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if got.path != fmt.Sprintf("/gnutella/%d", index) {
		t.Errorf("request path = %q, want /gnutella/%d", got.path, index)
	}
	if got.xgcl != strconv.Itoa(size) {
		t.Errorf("X-Gnutella-Content-Length = %q, want %d", got.xgcl, size)
	}
	if got.rng != "" {
		t.Errorf("Range = %q, want none on a whole-file transfer", got.rng)
	}
	if got.accept != "*/*" {
		t.Errorf("Accept = %q, want */*", got.accept)
	}
	if !strings.EqualFold(got.conn, "keep-alive") {
		t.Errorf("Connection = %q, want Keep-Alive", got.conn)
	}
	if got.ua == "" {
		t.Error("User-Agent is empty; the servent must identify itself")
	}

	wantPath := filepath.Join(dir, "song.mp3")
	if res.Path != wantPath {
		t.Errorf("result path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != size || res.Offset != 0 || res.Resumed() {
		t.Errorf("result = %+v, want %d bytes at offset 0, not resumed", res, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match served content (%d bytes)",
			len(onDisk), len(content))
	}
}

func TestDownloadResumeRange(t *testing.T) {
	const (
		index   = 3
		size    = 1000
		partial = 400
	)
	content := testContent(size)

	var gotRange, gotXGCL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		gotXGCL = r.Header.Get("X-Gnutella-Content-Length")
		if r.Header.Get("Range") != fmt.Sprintf("bytes=%d-", partial) {
			// Without the right Range, serve the whole file; a resumed
			// transfer that reached here is a bug the assertions catch.
			w.Header().Set("Content-Length", strconv.Itoa(size))
			_, _ = w.Write(content)
			return
		}
		w.Header().Set("Content-Range", fmt.Sprintf("bytes %d-%d/%d", partial, size-1, size))
		w.Header().Set("Content-Length", strconv.Itoa(size-partial))
		w.WriteHeader(http.StatusPartialContent)
		_, _ = w.Write(content[partial:])
	}))
	defer srv.Close()

	qh, hit := hitFor(t, srv, index, size, "resume.bin")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "resume.bin"), content[:partial], 0o644); err != nil {
		t.Fatalf("seed partial: %v", err)
	}

	res, err := NewDownloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotRange != fmt.Sprintf("bytes=%d-", partial) {
		t.Errorf("Range = %q, want bytes=%d-", gotRange, partial)
	}
	if gotXGCL != strconv.Itoa(size) {
		t.Errorf("X-Gnutella-Content-Length = %q, want the full size %d", gotXGCL, size)
	}
	if res.Offset != partial || !res.Resumed() {
		t.Errorf("result offset = %d (resumed %v), want %d", res.Offset, res.Resumed(), partial)
	}
	if res.Bytes != size-partial {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size-partial)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("resumed file (%d bytes) does not match served content", len(onDisk))
	}
}

func TestDownloadRefusesAlreadyComplete(t *testing.T) {
	const size = 64
	content := testContent(size)

	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	qh, hit := hitFor(t, srv, 1, size, "done.bin")
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "done.bin"), content, 0o644); err != nil {
		t.Fatalf("seed complete file: %v", err)
	}
	res, err := NewDownloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Complete || res.Bytes != 0 {
		t.Errorf("result = %+v, want an already-complete file with no bytes moved", res)
	}
	if requests != 0 {
		t.Errorf("made %d request(s) for an already-complete file, want none", requests)
	}
}

func TestDownloadSizeMismatch(t *testing.T) {
	const (
		index = 9
		size  = 500
	)
	content := testContent(size)

	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "200 body shorter than declared",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeChunked(w, content[:size-1])
			},
		},
		{
			name: "200 body longer than declared",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeChunked(w, append(append([]byte{}, content...), 0xFF))
			},
		},
		{
			name: "200 wrong X-Gnutella-Content-Length",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size+1))
				w.Header().Set("Content-Length", strconv.Itoa(size))
				_, _ = w.Write(content)
			},
		},
		{
			name: "206 wrong Content-Range total",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", size-1, size+1))
				w.Header().Set("Content-Length", strconv.Itoa(size))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(content)
			},
		},
		{
			name: "206 missing Content-Range",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Length", strconv.Itoa(size))
				w.WriteHeader(http.StatusPartialContent)
				_, _ = w.Write(content)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(tc.handler)
			defer srv.Close()
			qh, hit := hitFor(t, srv, index, size, "bad.bin")
			dir := t.TempDir()
			_, err := NewDownloader(qh, hit).Fetch(context.Background(), dir)
			if !errors.Is(err, ErrSizeMismatch) {
				t.Fatalf("Fetch error = %v, want ErrSizeMismatch", err)
			}
		})
	}
}

func TestDownloadRefusesErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	qh, hit := hitFor(t, srv, 1, 10, "x.bin")
	_, err := NewDownloader(qh, hit).Fetch(context.Background(), t.TempDir())
	if err == nil || errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("Fetch error = %v, want a non-size failure for a 503", err)
	}
}

func TestDownloadSanitisesHostileName(t *testing.T) {
	const (
		index = 12
		size  = 32
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	parent := t.TempDir()
	dir := filepath.Join(parent, "dest")

	cases := []struct {
		name string
		want string
	}{
		{"../../etc/passwd", "etcpasswd"},
		{`..\..\evil.exe`, "evil.exe"},
		{"/absolute/path.txt", "absolutepath.txt"},
		{"..hidden", "hidden"},
		{"a/b/c.txt", "abc.txt"},
		{"bad\x00name\x1b.bin", "badname.bin"},
		{"...", "file-12"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			qh, hit := hitFor(t, srv, index, size, tc.name)
			res, err := NewDownloader(qh, hit).Fetch(context.Background(), dir)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if filepath.Dir(res.Path) != dir {
				t.Errorf("wrote to %q, want a file directly inside %q", res.Path, dir)
			}
			if base := filepath.Base(res.Path); base != tc.want {
				t.Errorf("file name = %q, want %q", base, tc.want)
			}
			if _, err := os.Stat(res.Path); err != nil {
				t.Errorf("stat result: %v", err)
			}
		})
	}
}

func TestDownloadRejectsMissingSource(t *testing.T) {
	hit := FileHit{FileIndex: 1, FileSize: 4, FileName: "x.bin"}
	if _, err := NewDownloader(QueryHit{Port: 0}, hit).Fetch(context.Background(), t.TempDir()); err == nil {
		t.Error("Fetch accepted a QUERYHIT with no port")
	}
	var qh QueryHit
	qh.Port = 6346 // zero IP is unspecified
	if _, err := NewDownloader(qh, hit).Fetch(context.Background(), t.TempDir()); err == nil {
		t.Error("Fetch accepted a QUERYHIT with an unspecified address")
	}
}

func TestQueryHitSource(t *testing.T) {
	qh := QueryHit{IP: [4]byte{192, 168, 1, 2}, Port: 6346}
	if got, want := qh.Source(), "192.168.1.2:6346"; got != want {
		t.Errorf("Source() = %q, want %q", got, want)
	}
}

func TestSanitizeFileName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"song.mp3", "song.mp3"},
		{"../../etc/passwd", "etcpasswd"},
		{"/etc/passwd", "etcpasswd"},
		{`..\..\evil.exe`, "evil.exe"},
		{"a/b/c.txt", "abc.txt"},
		{"..hidden", "hidden"},
		{"...", ""},
		{"..", ""},
		{"", ""},
		{"a\x00b", "ab"},
		{"  spaced  ", "spaced"},
		{"..a..b", "a..b"},
	}
	for _, tc := range cases {
		if got := sanitizeFileName(tc.in); got != tc.want {
			t.Errorf("sanitizeFileName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestParseContentRange(t *testing.T) {
	cases := []struct {
		in           string
		start, total int64
		ok           bool
	}{
		{"bytes 400-999/1000", 400, 1000, true},
		{"bytes 0-99/100", 0, 100, true},
		{"bytes 400-999", 0, 0, false},
		{"bytes */1000", 0, 0, false},
		{"bytes 400-999/*", 0, 0, false},
		{"items 1-2/3", 0, 0, false},
		{"", 0, 0, false},
	}
	for _, tc := range cases {
		start, total, err := parseContentRange(tc.in)
		if tc.ok {
			if err != nil {
				t.Errorf("parseContentRange(%q) error: %v", tc.in, err)
				continue
			}
			if start != tc.start || total != tc.total {
				t.Errorf("parseContentRange(%q) = %d,%d want %d,%d",
					tc.in, start, total, tc.start, tc.total)
			}
			continue
		}
		if err == nil {
			t.Errorf("parseContentRange(%q) succeeded, want error", tc.in)
		}
	}
}

// servePushedHit stands in for a firewalled servent. It listens on
// 127.0.0.1 and, per accepted connection, greets with the GIV line a
// pushing servent opens with (0.6 draft 4.2, of the form
// "GIV <file index hex>:<servent id>/<file name>"), reads the
// requester's request head, and hands it to h to write a byte-exact
// response. greet may be empty to simulate a peer that never greets.
// Returns the listen address.
func servePushedHit(t *testing.T, greet string, h func(w io.Writer, r *http.Request)) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				if greet == "" {
					// A peer that never greets: close the door so the
					// client's GIV read fails promptly, which is what
					// TestDownloadPushedConnRequiresGIV wants.
					return
				}
				_, _ = io.WriteString(c, greet)
				req, err := http.ReadRequest(bufio.NewReader(c))
				if err != nil {
					return
				}
				h(c, req)
			}(c)
		}
	}()
	return ln.Addr().String()
}

// pushedRequest is what the Downloader asked the pushed servent for.
type pushedRequest struct {
	path, xgcl, rng, ua string
}

func TestDownloadOverPushedConn(t *testing.T) {
	const (
		index = 11
		size  = 777
	)
	content := testContent(size)

	sid := testServentID(0x40)
	greet := fmt.Sprintf("GIV %d:%x/pushed.mp3\r\n", index, sid)
	gotCh := make(chan pushedRequest, 1)
	addr := servePushedHit(t, greet, func(w io.Writer, r *http.Request) {
		gotCh <- pushedRequest{r.URL.Path, r.Header.Get("X-Gnutella-Content-Length"), r.Header.Get("Range"), r.Header.Get("User-Agent")}
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			_, _ = io.WriteString(w, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
			return
		}
		fmt.Fprintf(w, "HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Gnutella-Content-Length: %d\r\nConnection: close\r\n\r\n", size, size)
		_, _ = w.Write(content)
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial pushed conn: %v", err)
	}
	// A firewalled hit: the advertised source cannot be dialed (its
	// address is unspecified and its port is zero), yet Fetch must
	// transfer over the supplied connection.
	hit := FileHit{FileIndex: index, FileSize: size, FileName: "pushed.mp3"}
	qh := QueryHit{Port: 0, Hits: []FileHit{hit}}
	dir := t.TempDir()
	d := NewDownloader(qh, hit)
	d.Conn = conn
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch over pushed conn: %v", err)
	}

	select {
	case got := <-gotCh:
		if got.path != fmt.Sprintf("/gnutella/%d", index) {
			t.Errorf("request path = %q, want /gnutella/%d", got.path, index)
		}
		if got.xgcl != strconv.Itoa(size) {
			t.Errorf("X-Gnutella-Content-Length = %q, want %d", got.xgcl, size)
		}
		if got.rng != "" {
			t.Errorf("Range = %q, want none on a fresh push transfer", got.rng)
		}
		if got.ua == "" {
			t.Error("User-Agent is empty; the pushed servent must identify the client")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("pushed servent never saw a request")
	}

	if res.Bytes != size || res.Offset != 0 {
		t.Errorf("result = %+v, want %d bytes at offset 0", res, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("pushed file (%d bytes) does not match served content", len(onDisk))
	}

	// The pushed connection serves exactly one transfer: Fetch must
	// have closed it. A closed conn refuses even a read deadline;
	// otherwise a read after Fetch must fail with net.ErrClosed, not
	// merely stall.
	if err := conn.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		return // already closed: single-transfer confirmed
	}
	var one [1]byte
	if _, err := conn.Read(one[:]); err == nil || !errors.Is(err, net.ErrClosed) {
		t.Errorf("read after Fetch: err = %v, want net.ErrClosed", err)
	}
}

func TestDownloadOverPushedConnSizeMismatch(t *testing.T) {
	const (
		index = 12
		size  = 500
	)
	content := testContent(size)

	// Close-delimited body one byte short of the declared size: no
	// Content-Length, so only the body count can expose the lie.
	addr := servePushedHit(t, "GIV 12:00/pushed.bin\r\n", func(w io.Writer, r *http.Request) {
		_, _ = io.WriteString(w, "HTTP/1.1 200 OK\r\nConnection: close\r\n\r\n")
		_, _ = w.Write(content[:size-1])
	})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial pushed conn: %v", err)
	}
	hit := FileHit{FileIndex: index, FileSize: size, FileName: "pushed.bin"}
	qh := QueryHit{Port: 0, Hits: []FileHit{hit}}
	d := NewDownloader(qh, hit)
	d.Conn = conn
	_, err = d.Fetch(context.Background(), t.TempDir())
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("Fetch error = %v, want ErrSizeMismatch over the pushed conn", err)
	}
}

func TestDownloadPushedConnRequiresGIV(t *testing.T) {
	// A peer that accepts the push and then closes without greeting is
	// not a servent: Fetch must refuse rather than hang an HTTP parse
	// on silence.
	addr := servePushedHit(t, "", func(w io.Writer, r *http.Request) {})

	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial pushed conn: %v", err)
	}
	hit := FileHit{FileIndex: 1, FileSize: 10, FileName: "x.bin"}
	qh := QueryHit{Port: 0, Hits: []FileHit{hit}}
	d := NewDownloader(qh, hit)
	d.Conn = conn
	_, err = d.Fetch(context.Background(), t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "GIV") {
		t.Fatalf("Fetch error = %v, want a GIV-related refusal", err)
	}
}

func TestEngineDownloaderWiresLogSink(t *testing.T) {
	var logged atomic.Bool
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Logf: func(format string, args ...any) {
			logged.Store(true)
		},
		OnQueryHit: func(_ net.Addr, _ [idSize]byte, _ QueryHit) {},
	})
	qh, hit := QueryHit{IP: [4]byte{127, 0, 0, 1}, Port: 1}, FileHit{FileIndex: 1, FileSize: 1, FileName: "x"}
	d := eng.Downloader(qh, hit)
	if d == nil || d.QH.IP != qh.IP || d.Hit.FileIndex != hit.FileIndex {
		t.Fatalf("Downloader() = %+v, want the passed hit", d)
	}
	// The engine's log sink is wired through: invoking the downloader's
	// Logf must reach the engine's sink.
	d.Logf("probe")
	if !logged.Load() {
		t.Error("Downloader did not receive the engine's Logf")
	}
}
