// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella 1 download client: the HTTP transfer a servent answers
// for a file named in a QUERYHIT.
//
// Gnutella 1 has no content hash and no block protocol on this path, so
// the transfer is a plain HTTP GET of /gnutella/<file index> from the
// peer the QUERYHIT advertises, and the only integrity check available
// is the size the QUERYHIT declared. That is enough to move bytes, and
// deliberately all this file does: no job store, no scheduler, no retry
// loop. Resume is a byte-offset Range on the same GET.
//
// The source is taken from the QUERYHIT itself (its IP and port, not
// the connection that delivered it): the peer that answered a query
// need not be the peer that can serve the file, and the QUERYHIT is
// where the servent convention puts the downloadable address. A
// QUERYHIT is untrusted input, so the file name it carries is sanitised
// to one path component before it is joined with the caller's
// directory, and every declared and actual size is checked against the
// declared one before any byte is kept.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/version"
)

// downloadHeaderTimeout bounds how long a peer may take to send the
// response status and headers after accepting the connection. The body
// is bounded by the caller's context instead: a large transfer may take
// as long as the caller tolerates, but a peer that accepts and then
// says nothing must not pin the transfer goroutine. This mirrors the
// handshake and webcache deadlines elsewhere in the package.
const downloadHeaderTimeout = 30 * time.Second

// ErrSizeMismatch reports a transfer whose declared or received length
// disagrees with the size the QUERYHIT advertised. Gnutella 1 offers no
// content hash, so this is the only integrity check there is, and a
// disagreement is refused rather than written.
var ErrSizeMismatch = errors.New("gnutella: size mismatch")

// defaultDownloadClient is used when Downloader.Client is nil. It
// reuses the engine's dial timeout, refuses to wait on a peer that
// accepts and never answers, and disables the transport's transparent
// gzip so the body on the wire is the file's bytes: a decompressed body
// would have a length unrelated to the advertised size.
var defaultDownloadClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		ResponseHeaderTimeout: downloadHeaderTimeout,
		DisableCompression:    true,
	},
}

// Downloader moves one file named in a QUERYHIT from the peer that
// answered the search. Construct it with NewDownloader (or the Engine
// convenience) and call Fetch once per transfer.
type Downloader struct {
	// QH is the QUERYHIT that carried Hit. Its IP and Port name the
	// source; Gnutella 1 carries no other address.
	QH QueryHit

	// Hit is the advertised file to fetch.
	Hit FileHit

	// Client performs the GET. Nil selects defaultDownloadClient.
	Client *http.Client

	// Logf receives log lines. Nil logs to stderr.
	Logf func(format string, args ...any)
}

// DownloadResult reports a finished transfer.
type DownloadResult struct {
	// Path is the file written, always inside the caller's directory.
	Path string

	// Bytes is how many bytes this call received and wrote.
	Bytes int64

	// Offset is the byte offset the transfer started at: zero for a
	// whole-file (200) transfer, the existing partial size for a
	// resumed (206) one.
	Offset int64

	// Complete is true when the destination already held the full file
	// and no bytes moved.
	Complete bool
}

// Resumed reports whether the transfer continued an existing partial.
func (r DownloadResult) Resumed() bool { return r.Offset > 0 }

// NewDownloader returns a Downloader for one hit.
func NewDownloader(qh QueryHit, hit FileHit) *Downloader {
	return &Downloader{QH: qh, Hit: hit}
}

// Source returns the host:port a QUERYHIT advertises as the file's
// source, which is where the Gnutella 1 download GET is sent.
func (qh QueryHit) Source() string {
	return net.JoinHostPort(net.IP(qh.IP[:]).String(), strconv.Itoa(int(qh.Port)))
}

// Fetch downloads the hit into dir and returns the path it wrote. The
// file name is sanitised from the QUERYHIT, so a hostile name cannot
// leave dir. If dir already holds a partial file, the transfer resumes
// with a Range request; if it already holds the complete file, Fetch
// returns without contacting the peer.
//
// The size the QUERYHIT advertised is the only check Gnutella 1 offers,
// so every declared length (Content-Length, Content-Range,
// X-Gnutella-Content-Length) and the actual body length are verified
// against it. A transfer that is longer or shorter than declared is
// refused and the destination is restored to the offset it started at.
func (d *Downloader) Fetch(ctx context.Context, dir string) (DownloadResult, error) {
	if dir == "" {
		return DownloadResult{}, errors.New("gnutella: download: no destination directory")
	}
	if d.QH.Port == 0 {
		return DownloadResult{}, errors.New("gnutella: download: queryhit has no source port")
	}
	if net.IP(d.QH.IP[:]).IsUnspecified() {
		return DownloadResult{}, errors.New("gnutella: download: queryhit has no source address")
	}

	p, done, err := d.prepare(dir)
	if err != nil {
		return DownloadResult{}, err
	}
	if done {
		return DownloadResult{Path: p.dest, Offset: p.offset, Complete: true}, nil
	}

	src := d.QH.Source()
	rawURL := fmt.Sprintf("http://%s/gnutella/%d", src, d.Hit.FileIndex)
	req, err := d.newRequest(ctx, rawURL, p.offset)
	if err != nil {
		return DownloadResult{}, err
	}
	client := d.Client
	if client == nil {
		client = defaultDownloadClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: download %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	return d.receive(p, resp, rawURL, src)
}

// prepare decides what a transfer does before any byte moves: it
// sanitises the name, creates the directory, and works out the resume
// point from the file already on disk. done reports that the destination
// already holds the full file, so there is nothing to fetch; the caller
// returns the plan's dest as a complete result. Both the direct download
// and the pushed one start here, so they agree on where the bytes go and
// what a partial is.
func (d *Downloader) prepare(dir string) (p plan, done bool, err error) {
	if dir == "" {
		return plan{}, false, errors.New("gnutella: download: no destination directory")
	}
	p.size = int64(d.Hit.FileSize)
	p.name = sanitizeFileName(d.Hit.FileName)
	if p.name == "" {
		// A name that is nothing but separators, dots or control
		// characters is not a destination, but the hit still names a
		// file index, and serving that index is the request. Fall back
		// to it rather than refusing a file an honest peer advertised
		// under a hostile-looking name.
		p.name = fmt.Sprintf("file-%d", d.Hit.FileIndex)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return plan{}, false, fmt.Errorf("gnutella: download dir %s: %w", dir, err)
	}
	p.dest = filepath.Join(dir, p.name)

	// Decide the resume point from what is already on disk. A file
	// larger than the hit is not a partial of it, so it is refused
	// rather than truncated into one.
	if fi, err := os.Stat(p.dest); err == nil {
		p.offset = fi.Size()
		if p.offset > p.size {
			return plan{}, false, fmt.Errorf("%w: %s is %d bytes, hit %q is %d",
				ErrSizeMismatch, p.dest, p.offset, d.Hit.FileName, p.size)
		}
		if p.offset == p.size {
			return p, true, nil
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return plan{}, false, fmt.Errorf("gnutella: stat %s: %w", p.dest, err)
	}
	return p, false, nil
}

// plan is the outcome of Downloader.plan: where the bytes go and the
// byte offset the transfer starts at.
type plan struct {
	name   string // sanitised file name, for logs
	dest   string // the file written, inside the caller's directory
	size   int64  // size the QUERYHIT advertised
	offset int64  // existing partial size; the transfer resumes here
}

// newRequest builds the servent GET for rawURL with the request headers
// every transfer sends. It is shared by the direct download and the
// pushed one, which sends the same request over the dial-back socket.
func (d *Downloader) newRequest(ctx context.Context, rawURL string, offset int64) (*http.Request, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, fmt.Errorf("gnutella: download request %s: %w", rawURL, err)
	}
	// Servent request convention. The length header tells the peer the
	// size the QUERYHIT advertised, which is the whole file even for a
	// resumed range.
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", "*/*")
	req.Header.Set("Connection", "Keep-Alive")
	req.Header.Set("X-Gnutella-Content-Length", strconv.FormatInt(int64(d.Hit.FileSize), 10))
	if offset > 0 {
		req.Header.Set("Range", fmt.Sprintf("bytes=%d-", offset))
	}
	return req, nil
}

// receive checks a response against the plan and writes its body. It is
// the one place a body is accepted, so the size checks, the truncation
// on refusal and the one-byte-over read apply to every transfer alike.
// The caller owns resp.Body and closes it.
func (d *Downloader) receive(p plan, resp *http.Response, rawURL, src string) (DownloadResult, error) {
	// A transparently decompressed body is not the file: the peer
	// wrapped the content or lied about its length, and neither the
	// bytes nor their count can be trusted. The default client disables
	// the automatic gzip that would cause this; a caller-supplied
	// client might not, so it is refused here too.
	if resp.Uncompressed {
		return DownloadResult{}, fmt.Errorf("%w: peer returned a compressed body", ErrSizeMismatch)
	}

	size, offset, dest := p.size, p.offset, p.dest
	start := offset
	switch resp.StatusCode {
	case http.StatusOK:
		// The whole file, even if a Range was requested: the peer
		// ignored it. Rewrite from zero, so the result is the file the
		// QUERYHIT named rather than a splice onto a partial.
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
		// Drain a little so the connection can be reused, then refuse:
		// an error page is not the file.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return DownloadResult{}, fmt.Errorf("gnutella: download %s: status %s", rawURL, resp.Status)
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

	// Read one byte past the expected length: that single extra byte is
	// what distinguishes an exactly-right body from an over-long one,
	// and a short read is caught by the count either way.
	want := size - start
	n, err := io.Copy(f, io.LimitReader(resp.Body, want+1))
	if err != nil {
		truncateTo(f, start)
		return DownloadResult{}, fmt.Errorf("gnutella: download %s: %w", rawURL, err)
	}
	if n != want {
		truncateTo(f, start)
		return DownloadResult{}, fmt.Errorf("%w: body %d bytes, expected %d", ErrSizeMismatch, n, want)
	}
	if err := f.Sync(); err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: sync %s: %w", dest, err)
	}
	d.logf()("downloaded %s from %s: %d bytes at offset %d", p.name, src, n, start)
	return DownloadResult{Path: dest, Bytes: n, Offset: start}, nil
}

// checkDeclaredSize verifies the lengths a peer declared in a 200
// response against the hit's size. Both headers are optional, but a
// present one must agree; the body length is checked separately as it
// is read.
func checkDeclaredSize(resp *http.Response, size int64) error {
	if v := resp.Header.Get("X-Gnutella-Content-Length"); v != "" {
		n, err := strconv.ParseInt(strings.TrimSpace(v), 10, 64)
		if err != nil || n != size {
			return fmt.Errorf("%w: X-Gnutella-Content-Length %q, expected %d",
				ErrSizeMismatch, v, size)
		}
	}
	if resp.ContentLength >= 0 && resp.ContentLength != size {
		return fmt.Errorf("%w: Content-Length %d, expected %d",
			ErrSizeMismatch, resp.ContentLength, size)
	}
	return nil
}

// parseContentRange parses "bytes <start>-<end>/<total>". Gnutella 1
// servents know the file size, so an unknown total ("*") is refused:
// without it the advertised size cannot be checked, and checking it is
// the whole point.
func parseContentRange(v string) (start, total int64, err error) {
	bad := func() error {
		return fmt.Errorf("%w: bad Content-Range %q", ErrSizeMismatch, v)
	}
	v = strings.TrimSpace(v)
	const prefix = "bytes "
	if !strings.HasPrefix(v, prefix) {
		return 0, 0, bad()
	}
	rest := v[len(prefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return 0, 0, bad()
	}
	rangePart, totalPart := rest[:slash], rest[slash+1:]
	dash := strings.IndexByte(rangePart, '-')
	if dash < 0 {
		return 0, 0, bad()
	}
	start, err = strconv.ParseInt(strings.TrimSpace(rangePart[:dash]), 10, 64)
	if err != nil {
		return 0, 0, bad()
	}
	total, err = strconv.ParseInt(strings.TrimSpace(totalPart), 10, 64)
	if err != nil {
		return 0, 0, bad()
	}
	return start, total, nil
}

// truncateTo restores a partially written file to the offset the
// transfer started at, so a refused transfer leaves exactly the partial
// bytes a later resume would have found. A truncate failure is ignored:
// the transfer already failed and that failure is the one to report.
func truncateTo(f *os.File, offset int64) {
	_ = f.Truncate(offset)
}

// sanitizeFileName reduces a QUERYHIT file name to a safe single path
// component: directory separators are removed, as are control
// characters, and leading dots are trimmed so the result is never ".",
// "..", or a hidden-file escape. An empty result means nothing usable
// was left; the caller substitutes the file index.
//
// A separator becomes nothing rather than a placeholder: "..foo" and
// "../foo" are different inputs, and mapping both to the same safe
// component is more honest than inventing a character the peer never
// sent.
func sanitizeFileName(name string) string {
	var b strings.Builder
	b.Grow(len(name))
	for _, r := range name {
		switch {
		case r == '/' || r == '\\':
			continue
		case r < 0x20 || r == 0x7f:
			continue
		default:
			b.WriteRune(r)
		}
	}
	s := strings.TrimLeft(b.String(), ".")
	s = strings.TrimSpace(s)
	return s
}

// logf returns the transfer's log sink, defaulting to stderr like the
// rest of the engine.
func (d *Downloader) logf() func(format string, args ...any) {
	if d.Logf != nil {
		return d.Logf
	}
	return func(format string, args ...any) {
		fmt.Fprintf(os.Stderr, "sharzad: gnutella: download: "+format+"\n", args...)
	}
}
