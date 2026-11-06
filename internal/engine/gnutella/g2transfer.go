// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella2 HTTP transfer client: the HTTP GET that moves a file
// named by a G2 URL. G2 carries no block protocol on this path (only a
// PART completeness hint over UDP), so the transfer is a plain HTTP GET
// of the advertised URL, and the only integrity check available is the
// size the source declared. That is enough to move bytes, and
// deliberately all this file does: no job store, no scheduler, no retry
// loop. Resume is a byte-offset Range on the same GET.
//
// Unlike the Gnutella 1 download client, the source is not derived from
// a QUERYHIT: the caller supplies the URL, the expected size and an
// optional display name. The file name is sanitised to one path
// component before it is joined with the caller's directory, so a
// hostile name cannot leave it.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/version"
)

// g2TransferHeaderTimeout bounds how long a peer may take to send the
// response status and headers. Mirrors downloadHeaderTimeout.
const g2TransferHeaderTimeout = 30 * time.Second

// NewG2Transfer returns a transfer for one URL of the given size.
func NewG2Transfer(url string, size int64) *G2Transfer {
	return &G2Transfer{URL: url, Size: size}
}

// G2Transfer moves one file over HTTP from a G2 source. Construct it
// with NewG2Transfer and call Fetch once per transfer.
type G2Transfer struct {
	// URL is the HTTP URL to GET.
	URL string

	// Size is the expected full file size in bytes.
	Size int64

	// Name is an optional display name for the destination file.
	Name string

	// Client performs the GET. Nil selects defaultDownloadClient.
	Client *http.Client

	// Logf receives log lines. Nil logs to stderr.
	Logf func(format string, args ...any)
}

// Fetch downloads the file into dir and returns the path it wrote. The
// file name is sanitised, so a hostile name cannot leave dir. If dir
// already holds a partial file, the transfer resumes with a Range
// request; if it already holds the complete file, Fetch returns without
// contacting the peer.
//
// The size the caller declared is the only check G2 offers on this path,
// so every declared length (Content-Length, Content-Range,
// X-Gnutella-Content-Length) and the actual body length are verified
// against it. A transfer that is longer or shorter than declared is
// refused and the destination is restored to the offset it started at.
func (g *G2Transfer) Fetch(ctx context.Context, dir string) (DownloadResult, error) {
	if g.URL == "" {
		return DownloadResult{}, errors.New("gnutella: g2 transfer: no url")
	}
	if g.Size <= 0 {
		return DownloadResult{}, errors.New("gnutella: g2 transfer: no size")
	}
	size := g.Size

	name := sanitizeFileName(g.Name)
	if name == "" {
		name = "g2-file-0"
	}

	if err := os.MkdirAll(dir, 0o755); err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: g2 transfer dir %s: %w", dir, err)
	}
	dest := filepath.Join(dir, name)

	var offset int64
	if fi, err := os.Stat(dest); err == nil {
		offset = fi.Size()
		if offset > size {
			return DownloadResult{}, fmt.Errorf("%w: %s is %d bytes, expected %d",
				ErrSizeMismatch, dest, offset, size)
		}
		if offset == size {
			return DownloadResult{Path: dest, Offset: offset, Complete: true}, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return DownloadResult{}, fmt.Errorf("gnutella: stat %s: %w", dest, err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.URL, nil)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: g2 transfer request %s: %w", g.URL, err)
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("X-Gnutella-Content-Length", strconv.FormatInt(size, 10))
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}

	client := g.Client
	if client == nil {
		client = defaultDownloadClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: g2 transfer %s: %w", g.URL, err)
	}
	defer resp.Body.Close()

	if resp.Uncompressed {
		return DownloadResult{}, fmt.Errorf("%w: peer returned a compressed body", ErrSizeMismatch)
	}

	start := offset
	switch resp.StatusCode {
	case http.StatusOK:
		start = 0
		if err := checkDeclaredSize(resp, size); err != nil {
			return DownloadResult{}, err
		}
	case http.StatusPartialContent:
		rangeStart, total, err := parseContentRange(resp.Header.Get("Content-Range"))
		if err != nil {
			return DownloadResult{}, err
		}
		if rangeStart != offset || total != size {
			return DownloadResult{}, fmt.Errorf("%w: Content-Range %q, expected bytes %d-%d/%d",
				ErrSizeMismatch, resp.Header.Get("Content-Range"), offset, size-1, size)
		}
		if resp.ContentLength >= 0 && resp.ContentLength != size-offset {
			return DownloadResult{}, fmt.Errorf("%w: Content-Length %d, expected %d",
				ErrSizeMismatch, resp.ContentLength, size-offset)
		}
	default:
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return DownloadResult{}, fmt.Errorf("gnutella: g2 transfer %s: status %s", g.URL, resp.Status)
	}

	flags := os.O_WRONLY | os.O_CREATE
	if start == 0 {
		flags |= os.O_TRUNC
	} else {
		flags |= os.O_APPEND
	}
	f, err := os.OpenFile(dest, flags, 0o644)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: create %s: %w", dest, err)
	}
	defer f.Close()

	want := size - start
	n, err := io.Copy(f, io.LimitReader(resp.Body, want+1))
	if err != nil {
		truncateTo(f, start)
		return DownloadResult{}, fmt.Errorf("gnutella: g2 transfer %s: %w", g.URL, err)
	}
	if n != want {
		truncateTo(f, start)
		return DownloadResult{}, fmt.Errorf("%w: body %d bytes, expected %d", ErrSizeMismatch, n, want)
	}
	if err := f.Sync(); err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: sync %s: %w", dest, err)
	}
	g.logf()("g2 transfer %s: %d bytes at offset %d", g.URL, n, start)
	return DownloadResult{Path: dest, Bytes: n, Offset: start}, nil
}

func (g *G2Transfer) logf() func(format string, args ...any) {
	if g.Logf != nil {
		return g.Logf
	}
	return func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "sharzad: gnutella: g2 transfer: "+format+"\n", args...)
	}
}
