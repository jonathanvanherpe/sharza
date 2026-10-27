// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella engine: one listener for inbound peers, one dial loop
// per configured peer address, and a goroutine per connection. All
// logging goes to a Logf sink that defaults to stderr, which is where
// the supervisor collects worker output.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Dial knobs. dialTimeout bounds a single connect attempt; dialBackoff
// is the base retry delay for failed connections. The dial loop
// applies exponential backoff with a cap so repeated failures don't
// hammer peers and trigger "429 Banned" responses.
const (
	dialTimeout    = 10 * time.Second
	dialBackoff    = 5 * time.Second
	dialBackoffMax = 30 * time.Second
)

// searchTimeout is the default window Search waits for QUERYHITs after
// writing its QUERY. The window always runs to the end, so a peer that
// answers first does not cut short the peers that have not answered yet;
// see Options.SearchTimeout.
const searchTimeout = 5 * time.Second

// ErrNoSuitableHit is returned by SearchAndDownload when the search
// collected hits but none of them was usable: every hit had a zero
// port, an unspecified source address, or no non-empty file. No
// transfer was attempted and no disk write occurred.
var ErrNoSuitableHit = errors.New("gnutella: no suitable hit")

// Options tunes an Engine. Zero values select sane defaults.
// FileEntry is a file in the local catalogue for QUERY responses.
type FileEntry struct {
	Index uint32
	Size  uint32
	Name  string
}

// Options tunes an Engine. Zero values select sane defaults.
type Options struct {
	// Listen is the address to accept connections on, host:port.
	Listen string

	// Peers lists host:port addresses to dial and keep connected.
	Peers []string

	// Caches lists GWebCache URLs queried once at Run start. Every
	// host a cache returns is fed into the same dial machinery as
	// Peers, so a fresh daemon can find peers without an operator
	// maintaining a gnutella_peers list by hand. A cache that fails
	// is logged and skipped; it never stops the engine.
	Caches []string

	// cacheAllowLoopback relaxes the webcache host filter so that a
	// loopback address from a cache is kept. Production never sets it:
	// a cache handing out 127.0.0.1 is either broken or pointing us at
	// a local service, and the swarm we want is out on the network.
	// Tests set it to point a cache at a listener on 127.0.0.1, since
	// a test may not reach anything else.
	cacheAllowLoopback bool

	// advertisePort overrides the port a QUERYHIT advertises as its
	// source. Zero means "use the listener port", which is what
	// production does: a peer serves files from the same port it
	// listens for Gnutella connections on. A non-zero value lets a test
	// point the download at a separate servent (e.g. an httptest
	// server) while the engine keeps its own listener port.
	advertisePort uint16

	// KeepAliveInterval is how often a silent connection receives an
	// empty PING. Zero means the default 90 s.
	KeepAliveInterval time.Duration

	// IdleTimeout closes a connection that has not delivered a
	// complete message within this window. Zero means 5 minutes.
	IdleTimeout time.Duration

	// Logf receives log lines. Nil logs to stderr.
	Logf func(format string, args ...any)

	// Catalogue is the local file list used to answer incoming QUERYs.
	Catalogue []FileEntry

	// SearchTimeout is the window Search waits for QUERYHITs after
	// writing its QUERY, before returning the hits it has. Zero means
	// the default 5 s.
	SearchTimeout time.Duration

	// OnQueryHit is called for every QUERYHIT received from a peer,
	// with the descriptor ID the hit echoed. The id lets a caller match
	// the hit to the Search that asked for it; Engine.Search collects
	// its own hits and does not depend on this callback.
	OnQueryHit func(peer net.Addr, id [idSize]byte, qh QueryHit)

	// searches is the engine's in-flight search registry. Run sets it;
	// callers do not. Inbound QUERYHITs are delivered through it.
	searches *searchRegistry
}

func (o Options) withDefaults() Options {
	if o.KeepAliveInterval <= 0 {
		o.KeepAliveInterval = 90 * time.Second
	}
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = 5 * time.Minute
	}
	if o.SearchTimeout <= 0 {
		o.SearchTimeout = searchTimeout
	}
	if o.Logf == nil {
		o.Logf = func(format string, args ...any) {
			fmt.Fprintf(os.Stderr, "sharzad: gnutella: "+format+"\n", args...)
		}
	}
	return o
}

func (o Options) logf() func(format string, args ...any) {
	return o.withDefaults().Logf
}

// Engine accepts and maintains Gnutella 0.6 peer connections.
type peerConn struct {
	conn net.Conn
	addr net.Addr
	mu   sync.Mutex
}

type Engine struct {
	mu      sync.Mutex
	started bool

	opts  Options
	ln    net.Listener
	laddr net.Addr
	ready chan struct{}
	wg    sync.WaitGroup

	peers map[*peerConn]struct{}

	// searches correlates inbound QUERYHITs with the Search that asked
	// for them, by descriptor ID.
	searches *searchRegistry

	// dialed records every address a dial loop has been started for,
	// so a host listed by both the config and a webcache (or by two
	// caches) gets one loop, not two competing connections.
	dialed map[string]struct{}
}

// New returns an idle engine. Call Run with the desired options.
func New() *Engine {
	return &Engine{
		ready:    make(chan struct{}),
		peers:    make(map[*peerConn]struct{}),
		dialed:   make(map[string]struct{}),
		searches: newSearchRegistry(),
	}
}

// Ready is closed once Run has bound the listener. It never closes if
// Run fails before binding.
func (e *Engine) Ready() <-chan struct{} {
	return e.ready
}

// Addr returns the bound listener address (with the real port, even if
// Listen asked for port 0). Valid after Ready.
func (e *Engine) Addr() net.Addr {
	return e.laddr
}

// Run binds the listener, dials the configured peers, and serves until
// ctx is cancelled. It returns nil on a clean shutdown and an error
// only on a genuine failure, so a supervisor can restart the worker on
// error and treat a nil return as "told to stop".
func (e *Engine) Run(ctx context.Context, opts Options) error {
	e.mu.Lock()
	if e.started {
		e.mu.Unlock()
		return errors.New("gnutella: engine already running")
	}
	e.started = true
	e.opts = opts.withDefaults()
	// Every peer gets this engine's registry, so a QUERYHIT delivered on
	// any connection can be matched to the Search that is waiting for it.
	e.opts.searches = e.searches
	e.mu.Unlock()

	ln, err := net.Listen("tcp", e.opts.Listen)
	if err != nil {
		return fmt.Errorf("gnutella: listen %s: %w", e.opts.Listen, err)
	}
	e.ln = ln
	e.laddr = ln.Addr()
	close(e.ready)
	logf := e.opts.Logf

	logf("listening on %s (%d peer(s), %d cache(s) configured)",
		ln.Addr(), len(e.opts.Peers), len(e.opts.Caches))
	for _, addr := range e.opts.Peers {
		e.startDial(ctx, addr)
	}
	// Caches are fetched concurrently with serving: a slow or dead
	// webcache delays only its own hosts, never the listener, and the
	// dial loops it discovers are the same ones a configured peer gets.
	for _, cacheURL := range e.opts.Caches {
		e.wg.Add(1)
		go e.cacheLoop(ctx, cacheURL)
	}

	// Closing the listener is how Accept is unblocked when the context
	// ends; connections themselves are closed by each serveConn.
	stopClose := context.AfterFunc(ctx, func() { _ = ln.Close() })
	defer stopClose()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				break
			}
			return fmt.Errorf("gnutella: accept: %w", err)
		}
		pc := &peerConn{conn: conn, addr: conn.RemoteAddr()}
		e.mu.Lock()
		e.peers[pc] = struct{}{}
		e.mu.Unlock()
		e.wg.Add(1)
		go func(c net.Conn, pc *peerConn) {
			defer e.wg.Done()
			if err := serveConn(ctx, c, true, e.opts, e.laddr); err != nil {
				logf("inbound %s: %v", c.RemoteAddr(), err)
			}
			e.mu.Lock()
			delete(e.peers, pc)
			e.mu.Unlock()
		}(conn, pc)
	}

	// Wait is safe from Add-after-Wait because every goroutine that
	// can still Add is itself counted: the accept loop's handlers
	// (added before this point), the dial loops started from Run, and
	// the cache loops started from Run, whose startDial calls happen
	// while their own count is still held.
	e.wg.Wait()
	logf("stopped")
	return nil
}

// startDial starts the per-peer dial loop for addr exactly once.
// Configured Peers and the hosts a webcache returns go through this one
// path, so a dead node retries with the same dialBackoff whichever
// source named it, and the same address never gets two loops fighting
// over it.
//
// Every caller is either Run itself or a cacheLoop goroutine the
// WaitGroup already counts, so the Add here is safe against Wait: the
// counter is never zero while a caller is still running.
func (e *Engine) startDial(ctx context.Context, addr string) {
	e.mu.Lock()
	if _, dup := e.dialed[addr]; dup {
		e.mu.Unlock()
		return
	}
	e.dialed[addr] = struct{}{}
	e.mu.Unlock()

	e.wg.Add(1)
	go e.dialLoop(ctx, addr)
}

// cacheLoop fetches one webcache and hands every host it returns to
// startDial. A failure is logged and dropped: the client does not retry
// (the dial loops own retrying), and one bad cache must not stop the
// engine or the other caches.
func (e *Engine) cacheLoop(ctx context.Context, cacheURL string) {
	defer e.wg.Done()
	logf := e.opts.Logf

	res, err := e.fetchCache(ctx, cacheURL)
	if err != nil {
		logf("cache %s: %v", cacheURL, err)
		return
	}
	logf("cache %s: %d host(s), %d url(s)", cacheURL, len(res.Hosts), len(res.URLs))
	for _, in := range res.Info {
		// Kept (in res.Info) for pacing; nothing paces on them yet,
		// so they are logged where an operator can see them.
		logf("cache %s: %s=%s", cacheURL, in.Key, in.Value)
	}
	for _, h := range res.Hosts {
		e.startDial(ctx, h.Addr)
	}
}

// fetchCache is FetchHosts with the engine's loopback policy applied.
func (e *Engine) fetchCache(ctx context.Context, cacheURL string) (CacheResult, error) {
	if e.opts.cacheAllowLoopback {
		return fetchHosts(ctx, cacheURL, true)
	}
	return FetchHosts(ctx, cacheURL)
}

// dialLoop keeps one outbound peer connected. It retries forever with
// exponential backoff capped at dialBackoffMax: a peer that is down at
// startup may come up later, and a refusal may become an acceptance
// when the far side frees a slot.
func (e *Engine) dialLoop(ctx context.Context, addr string) {
	defer e.wg.Done()
	logf := e.opts.Logf
	delay := dialBackoff
	for {
		conn, err := net.DialTimeout("tcp", addr, dialTimeout)
		if err != nil {
			logf("dial %s failed: %v (retrying in %s)", addr, err, delay)
		} else {
			pc := &peerConn{conn: conn, addr: conn.RemoteAddr()}
			e.mu.Lock()
			e.peers[pc] = struct{}{}
			e.mu.Unlock()
			if err := serveConn(ctx, conn, false, e.opts, e.laddr); err != nil && ctx.Err() == nil {
				logf("peer %s: %v", addr, err)
			}
			e.mu.Lock()
			delete(e.peers, pc)
			e.mu.Unlock()
			delay = dialBackoff
			select {
			case <-ctx.Done():
				return
			case <-time.After(delay):
				continue
			}
		}
		delay = delay * 2
		if delay > dialBackoffMax {
			delay = dialBackoffMax
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(delay):
		}
	}
}

// Downloader returns a transfer for one hit delivered to OnQueryHit,
// wired to the engine's log sink. It is the convenience that turns the
// QueryHit/FileHit pair a callback receives into a file transfer in one
// call:
//
//	opts.OnQueryHit = func(_ net.Addr, _ [idSize]byte, qh QueryHit) {
//		for _, h := range qh.Hits {
//			d := eng.Downloader(qh, h)
//			go func() { _, _ = d.Fetch(ctx, dir) }()
//		}
//	}
//
// The engine holds no job state for the transfer: Fetch writes only to
// the directory the caller passes, exactly like NewDownloader does.
func (e *Engine) Downloader(qh QueryHit, hit FileHit) *Downloader {
	e.mu.Lock()
	logf := e.opts.Logf
	e.mu.Unlock()
	d := NewDownloader(qh, hit)
	d.Logf = logf
	return d
}

// Search sends one QUERY to every live peer, collects the QUERYHITs that
// echo its descriptor ID within SearchTimeout, and returns them.
//
// The query is registered before it is written: a peer on a fast link can
// answer before the write call returns, and an unregistered ID would drop
// that answer. Only hits echoing this query's own ID are returned; a hit
// under any other ID answers a different query and is left to the
// OnQueryHit callback.
//
// The collection window always runs to SearchTimeout, so a peer answering
// first does not cut short the peers that have not answered yet; that is
// what makes the timeout path return partial hits and no error. The error
// return is the first write error, if any, so a search that reached no
// peer says why alongside whatever it did collect. No live peer is not an
// error: the search simply finds nothing.
// Search is a thin wrapper over searchQuery for the common text-only
// case. It uses a background context, so it always runs the full
// collection window; pass a context to searchQuery/SearchAndDownload
// when cancellation matters.
func (e *Engine) Search(text string) ([]QueryHit, error) {
	return e.searchQuery(context.Background(), Query{MinSpeed: 0, Search: text})
}

// SearchContext is the context-aware form of Search for callers that
// want the collection window to end early when ctx is cancelled.
func (e *Engine) SearchContext(ctx context.Context, text string) ([]QueryHit, error) {
	return e.searchQuery(ctx, Query{MinSpeed: 0, Search: text})
}

// searchQuery sends one QUERY built from q to every live peer, collects
// the QUERYHITs that echo its descriptor ID within SearchTimeout (or
// until ctx is cancelled), and returns them.
//
// The query is registered before it is written: a peer on a fast link can
// answer before the write call returns, and an unregistered ID would drop
// that answer. Only hits echoing this query's own ID are returned; a hit
// under any other ID answers a different query and is left to the
// OnQueryHit callback.
//
// The collection window always runs to SearchTimeout unless ctx is
// cancelled, so a peer answering first does not cut short the peers that
// have not answered yet; that is what makes the timeout path return
// partial hits and no error. The error return is the first write error,
// if any, or ctx.Err() when the wait was cancelled, so a search that
// reached no peer says why alongside whatever it did collect. No live
// peer is not an error: the search simply finds nothing.
func (e *Engine) searchQuery(ctx context.Context, q Query) ([]QueryHit, error) {
	payload := EncodeQuery(q)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgQuery,
		TTL:    7, // direct peer, TTL can be modest
		Hops:   0,
		Length: uint32(len(payload)),
	}
	buf := hdr.AppendTo(nil)
	buf = append(buf, payload...)

	e.mu.Lock()
	peers := make([]*peerConn, 0, len(e.peers))
	for pc := range e.peers {
		peers = append(peers, pc)
	}
	reg := e.searches
	timeout := e.opts.SearchTimeout
	e.mu.Unlock()

	if len(peers) == 0 {
		return nil, nil
	}

	// Register before any write: the answer can arrive first.
	reg.register(hdr.ID)

	var (
		wg       sync.WaitGroup
		written  atomic.Int32
		errMu    sync.Mutex
		firstErr error
	)
	for _, pc := range peers {
		wg.Add(1)
		go func(pc *peerConn) {
			defer wg.Done()
			pc.mu.Lock()
			defer pc.mu.Unlock()
			err := pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err == nil {
				_, err = pc.conn.Write(buf)
			}
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			written.Add(1)
		}(pc)
	}
	wg.Wait()

	// Wait out the collection window so late hits are collected. If no
	// write succeeded there is no peer that can answer, so the wait would
	// only delay an empty result. A cancelled context ends the wait
	// early.
	cancelled := false
	if written.Load() > 0 {
		timer := time.NewTimer(timeout)
		select {
		case <-timer.C:
		case <-ctx.Done():
			cancelled = true
		}
		timer.Stop()
	}

	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	if cancelled && ctx.Err() != nil {
		err = ctx.Err()
	}
	return reg.close(hdr.ID), err
}

// usableHit reports whether a (query hit, file hit) pair can be
// downloaded: a non-zero source port, a specified source address, and a
// file with a non-zero size. The check is deliberately cheap and touches
// no disk.
func usableHit(qh QueryHit, hit FileHit) bool {
	if qh.Port == 0 {
		return false
	}
	if net.IP(qh.IP[:]).IsUnspecified() {
		return false
	}
	if hit.FileSize == 0 {
		return false
	}
	return true
}

// firstUsableHit walks the collected hits in order and returns the first
// (query hit, file hit) pair that usableHit accepts, together with ok.
func firstUsableHit(hits []QueryHit) (QueryHit, FileHit, bool) {
	for _, qh := range hits {
		for _, h := range qh.Hits {
			if usableHit(qh, h) {
				return qh, h, true
			}
		}
	}
	return QueryHit{}, FileHit{}, false
}

// SearchAndDownload runs a search and, if a usable hit exists, fetches
// the first usable file into dir. It composes Search (via searchQuery)
// and Downloader.Fetch without reimplementing either: the selection
// happens in memory and touches no disk, and an unusable hit is skipped
// rather than fatal. Returns ErrNoSuitableHit when no hit was usable.
func (e *Engine) SearchAndDownload(ctx context.Context, q Query, dir string) (*DownloadJob, error) {
	hits, err := e.searchQuery(ctx, q)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	qh, hit, ok := firstUsableHit(hits)
	if !ok {
		return nil, ErrNoSuitableHit
	}
	d := e.Downloader(qh, hit)
	res, err := d.Fetch(ctx, dir)
	if err != nil {
		return nil, err
	}
	qhCopy := qh
	return &DownloadJob{Hit: &qhCopy, Path: res.Path, Size: int64(hit.FileSize)}, nil
}
