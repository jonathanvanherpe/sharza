// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The upload (serving) half of Gnutella 1: the HTTP transfer a servent
// answers for a file its own QUERYHIT advertised.
//
// The servent convention puts the downloadable address and the Gnutella
// listen port in the same place: the port field of a QUERYHIT is the
// port a peer connects to for both the 0.6 handshake and the HTTP
// download GET. Sharza's engine therefore has to serve two protocols on
// one listener, and which one an accepted connection is decides from
// its first bytes: a Gnutella CONNECT starts with "GNUTELLA", a download
// starts with "GET ". Both start with 'G', so the peek reads enough
// bytes to tell them apart without consuming any: the buffered reader
// is handed on to whichever path wins, so the handshake path still sees
// every byte it buffered.
//
// The HTTP side is net/http rather than a hand-rolled parser: it is
// stdlib (the daemon stays cgo-free), and http.ServeContent already
// implements the byte-range contract (200, 206 with Content-Range, 416)
// that the download client and a real servent both rely on. Serving a
// single already-accepted connection needs a one-connection listener,
// because http.Server.Serve takes a net.Listener, not a net.Conn.

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

// downloadPathPrefix is the request path a Gnutella 1 download uses:
// /gnutella/<file index>, where the index is the one the QUERYHIT
// advertised for the file.
const downloadPathPrefix = "/gnutella/"

// gnutellaHandshakeBytes is the first bytes of a 0.6 CONNECT request and
// httpMethodBytes the first bytes of a download GET. They share a first
// letter, so the sniff must read past it; eight bytes is the length of
// the longer of the two.
var (
	gnutellaHandshakeBytes = []byte("GNUTELLA")
	httpMethodBytes        = []byte("GET ")
)

// downloadWriteTimeout bounds writing a download response. It stops a
// client that requests a file and then stops reading from pinning the
// connection (and with it the engine's shutdown) forever. It is a cap
// on a stalled client, not a transfer budget: the client here is the
// engine's own Downloader, which reads as it goes.
const downloadWriteTimeout = 5 * time.Minute

// serveInbound handles one accepted connection. It peeks the first
// bytes to decide which protocol the peer is speaking and dispatches:
// a Gnutella 0.6 handshake goes to serveConn and is registered as a
// peer, a download GET goes to the HTTP servent. The peek does not
// consume, so neither path loses bytes.
func (e *Engine) serveInbound(ctx context.Context, conn net.Conn, logf func(string, ...any)) {
	br := bufio.NewReader(conn)
	// The peek must not block forever: a peer that connects and says
	// nothing is the same stalled connection the handshake's own
	// deadline guards. Each path resets or replaces this deadline.
	if err := conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		_ = conn.Close()
		return
	}
	isHTTP, err := sniffProtocol(br)
	if err != nil {
		_ = conn.Close()
		logf("inbound %s: %v", conn.RemoteAddr(), err)
		return
	}
	if isHTTP {
		e.serveDownloadHTTP(ctx, conn, br)
		return
	}

	pc := &peerConn{conn: conn, addr: conn.RemoteAddr()}
	e.mu.Lock()
	e.peers[pc] = struct{}{}
	e.mu.Unlock()
	if err := serveConn(ctx, br, conn, true, e.opts, e.laddr); err != nil {
		logf("inbound %s: %v", conn.RemoteAddr(), err)
	}
	e.mu.Lock()
	delete(e.peers, pc)
	e.mu.Unlock()
}

// sniffProtocol reports whether the connection's first bytes are an
// HTTP download request rather than a Gnutella handshake. Any read
// error is returned with a false classification; a short read that did
// yield bytes is classified from what it has, and anything that is not
// "GET " falls to the handshake path, which answers a non-HTTP peer
// with an informative status line.
func sniffProtocol(br *bufio.Reader) (isHTTP bool, err error) {
	b, err := br.Peek(len(gnutellaHandshakeBytes))
	if len(b) == 0 {
		return false, err
	}
	if bytes.HasPrefix(b, httpMethodBytes) {
		return true, nil
	}
	return false, nil
}

// serveDownloadHTTP answers one HTTP download GET over an already-read
// connection. The connection is wrapped so the bytes the sniff peeked
// (still buffered in br) are read before the socket, and served through
// a one-connection listener so net/http can parse the request and
// http.ServeContent can do the byte-range work.
func (e *Engine) serveDownloadHTTP(ctx context.Context, conn net.Conn, br *bufio.Reader) {
	done := make(chan struct{})
	sc := &servedConn{Conn: conn, r: br, done: done}
	srv := &http.Server{
		Handler:           http.HandlerFunc(e.handleDownload),
		ReadHeaderTimeout: handshakeDeadline,
		WriteTimeout:      downloadWriteTimeout,
	}
	// One request per connection: a download is a complete transfer, and
	// closing after it means the accept-loop goroutine is released as
	// soon as the response is written rather than when a client decides
	// to close a pooled keep-alive connection.
	srv.SetKeepAlivesEnabled(false)
	// Closing the server is how a transfer in flight is told the engine
	// is shutting down: the engine's context is not the connection's.
	stopClose := context.AfterFunc(ctx, func() { _ = srv.Close() })
	defer stopClose()

	l := &singleConnListener{conn: sc, done: done, addr: conn.LocalAddr()}
	if err := srv.Serve(l); err != nil &&
		!errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		e.opts.logf()("download %s: %v", conn.RemoteAddr(), err)
	}
}

// handleDownload serves one catalogue file. GET /gnutella/<index> is
// the only route; the index is resolved against Options.Catalogue and
// the file at its Path is served. An unknown index, or one whose entry
// has no Path, is 404: an empty catalogue shares nothing. A Range
// request gets 206 with Content-Range; a range past the end gets 416.
//
// X-Gnutella-Content-Length is the whole file's length even for a 206,
// matching what the transfer declares and what the client checks the
// eventual complete file against.
func (e *Engine) handleDownload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	index, ok := downloadIndex(r.URL.Path)
	if !ok {
		http.NotFound(w, r)
		return
	}
	fe, ok := e.catalogueByIndex(index)
	if !ok || fe.Path == "" {
		http.NotFound(w, r)
		return
	}
	f, err := os.Open(fe.Path)
	if err != nil {
		e.opts.logf()("download index %d (%s): %v", index, fe.Path, err)
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil || fi.IsDir() {
		http.NotFound(w, r)
		return
	}

	// Set the type and the servent length before ServeContent, which
	// keeps a Content-Type it finds already set and would otherwise
	// sniff or guess one.
	w.Header().Set("Content-Type", "application/binary")
	w.Header().Set("X-Gnutella-Content-Length", strconv.FormatInt(fi.Size(), 10))
	e.opts.logf()("serving index %d (%s): %d bytes to %s", index, fe.Name, fi.Size(), r.RemoteAddr)
	http.ServeContent(w, r, fe.Name, fi.ModTime(), f)
}

// downloadIndex extracts the file index from a download path. It accepts
// /gnutella/<index> and is lenient about a trailing name a servent may
// append, e.g. /gnutella/5/song.mp3: the index is the first path
// segment and the rest is ignored.
func downloadIndex(path string) (uint32, bool) {
	if !strings.HasPrefix(path, downloadPathPrefix) {
		return 0, false
	}
	rest := path[len(downloadPathPrefix):]
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return 0, false
	}
	n, err := strconv.ParseUint(rest, 10, 32)
	if err != nil {
		return 0, false
	}
	return uint32(n), true
}

// catalogueByIndex returns the catalogue entry for a file index. The
// catalogue is immutable once Run has bound the listener, so no lock is
// needed; e.opts is written under e.mu before Ready is closed, and any
// request that reaches here is later.
func (e *Engine) catalogueByIndex(index uint32) (FileEntry, bool) {
	for _, fe := range e.opts.Catalogue {
		if fe.Index == index {
			return fe, true
		}
	}
	return FileEntry{}, false
}

// servedConn is a net.Conn whose reads come from the buffered reader
// the protocol sniff used, so bytes the peek left in that buffer are
// seen before the socket. Closing it also signals done, which is how
// the one-connection listener learns the transfer is over.
type servedConn struct {
	net.Conn
	r    io.Reader
	done chan struct{}
	once sync.Once
}

func (c *servedConn) Read(p []byte) (int, error) { return c.r.Read(p) }

func (c *servedConn) Close() error {
	c.once.Do(func() { close(c.done) })
	return c.Conn.Close()
}

// singleConnListener turns one already-accepted connection into a
// net.Listener, so net/http's Server can serve it. The first Accept
// returns the connection; later Accepts block until it is closed, then
// fail.
//
// Blocking (rather than failing immediately) is what makes the accept
// loop's goroutine wait for the response: net/http's Server.Serve
// returns as soon as Accept errors and does not wait for the
// connection's handler, so an immediate second error would let the
// engine consider the connection finished while the response was still
// being written.
type singleConnListener struct {
	conn net.Conn
	done <-chan struct{}
	addr net.Addr
}

func (l *singleConnListener) Accept() (net.Conn, error) {
	if l.conn != nil {
		c := l.conn
		l.conn = nil
		return c, nil
	}
	<-l.done
	return nil, net.ErrClosed
}

// Close is a no-op: the connection belongs to the http.Server, which
// closes it, and Serve's own deferred Close must not close it ahead of
// the handler it is still running.
func (l *singleConnListener) Close() error { return nil }

func (l *singleConnListener) Addr() net.Addr { return l.addr }
