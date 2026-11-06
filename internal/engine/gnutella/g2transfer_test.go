// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestG2TransferFullFileAndRequestHeaders(t *testing.T) {
	const size = 1200
	content := testContent(size)
	url := "" // filled below

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
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	url = srv.URL + "/g2/file"

	tr := NewG2Transfer(url, size)
	tr.Name = "song.mp3"
	dir := t.TempDir()
	res, err := tr.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
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
		t.Error("User-Agent is empty")
	}

	wantPath := filepath.Join(dir, "song.mp3")
	if res.Path != wantPath {
		t.Errorf("result path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != int64(size) || res.Offset != 0 || res.Resumed() {
		t.Errorf("result = %+v, want %d bytes at offset 0, not resumed", res, size)
	}
	onDisk, _ := os.ReadFile(res.Path)
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk does not match served content")
	}
	_ = url
}

func TestG2TransferResumeRange(t *testing.T) {
	const (
		size    = 1000
		partial = 400
	)
	content := testContent(size)

	var gotRange, gotXGCL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotRange = r.Header.Get("Range")
		gotXGCL = r.Header.Get("X-Gnutella-Content-Length")
		if r.Header.Get("Range") != fmt.Sprintf("bytes=%d-", partial) {
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

	tr := NewG2Transfer(srv.URL+"/f", size)
	tr.Name = "resume.bin"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "resume.bin"), content[:partial], 0o644); err != nil {
		t.Fatalf("seed partial: %v", err)
	}

	res, err := tr.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if gotRange != fmt.Sprintf("bytes=%d-", partial) {
		t.Errorf("Range = %q, want bytes=%d-", gotRange, partial)
	}
	if gotXGCL != strconv.Itoa(size) {
		t.Errorf("X-Gnutella-Content-Length = %q, want %d", gotXGCL, size)
	}
	if res.Offset != partial || !res.Resumed() {
		t.Errorf("result offset = %d", res.Offset)
	}
	if res.Bytes != size-partial {
		t.Errorf("result bytes = %d, want %d", res.Bytes, size-partial)
	}
	onDisk, _ := os.ReadFile(res.Path)
	if !bytes.Equal(onDisk, content) {
		t.Errorf("resumed file does not match")
	}
}

func TestG2TransferRefusesAlreadyComplete(t *testing.T) {
	const size = 64
	content := testContent(size)

	var requests int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests++
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	tr := NewG2Transfer(srv.URL+"/f", size)
	tr.Name = "done.bin"
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "done.bin"), content, 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	res, err := tr.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !res.Complete || res.Bytes != 0 {
		t.Errorf("result = %+v", res)
	}
	if requests != 0 {
		t.Errorf("made %d requests, want none", requests)
	}
}

func TestG2TransferSizeMismatch(t *testing.T) {
	const size = 500
	content := testContent(size)

	cases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{
			name: "200 body shorter",
			handler: func(w http.ResponseWriter, r *http.Request) {
				writeChunked(w, content[:size-1])
			},
		},
		{
			name: "200 body longer",
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
			tr := NewG2Transfer(srv.URL+"/f", size)
			tr.Name = "bad.bin"
			dir := t.TempDir()
			// seed partial for 206 cases? Server returns 206 regardless; offset 0 here, so 206 with rangeStart 0 matches offset 0. Fine.
			_, err := tr.Fetch(context.Background(), dir)
			if !errors.Is(err, ErrSizeMismatch) {
				t.Fatalf("Fetch error = %v, want ErrSizeMismatch", err)
			}
		})
	}
}

func TestG2TransferRefusesErrorStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	tr := NewG2Transfer(srv.URL+"/f", 10)
	tr.Name = "x.bin"
	_, err := tr.Fetch(context.Background(), t.TempDir())
	if err == nil || errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("Fetch error = %v, want non-size failure for 503", err)
	}
}

func TestG2TransferSanitisesHostileName(t *testing.T) {
	const size = 32
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
		{"...", "g2-file-0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := NewG2Transfer(srv.URL+"/f", size)
			tr.Name = tc.name
			res, err := tr.Fetch(context.Background(), dir)
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if filepath.Dir(res.Path) != dir {
				t.Errorf("wrote to %q, want inside %q", res.Path, dir)
			}
			if base := filepath.Base(res.Path); base != tc.want {
				t.Errorf("file name = %q, want %q", base, tc.want)
			}
		})
	}
}

func TestG2TransferEmptyURLAndSize(t *testing.T) {
	tr := NewG2Transfer("", 10)
	tr.Name = "x.bin"
	if _, err := tr.Fetch(context.Background(), t.TempDir()); err == nil {
		t.Error("Fetch accepted empty URL")
	}
	tr2 := NewG2Transfer("http://example.com/f", 0)
	tr2.Name = "x.bin"
	if _, err := tr2.Fetch(context.Background(), t.TempDir()); err == nil {
		t.Error("Fetch accepted zero size")
	}
	tr3 := NewG2Transfer("http://example.com/f", -5)
	tr3.Name = "x.bin"
	if _, err := tr3.Fetch(context.Background(), t.TempDir()); err == nil {
		t.Error("Fetch accepted negative size")
	}
}

func TestG2TransferNameFallbackEmpty(t *testing.T) {
	const size = 8
	content := testContent(size)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()
	tr := NewG2Transfer(srv.URL+"/f", size)
	// Name empty
	res, err := tr.Fetch(context.Background(), t.TempDir())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if filepath.Base(res.Path) != "g2-file-0" {
		t.Errorf("fallback name = %q, want g2-file-0", filepath.Base(res.Path))
	}
}
