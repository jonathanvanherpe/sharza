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
	"bufio"
	"bytes"
	"strings"
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
const (
	searchTimeout = 5 * time.Second
	pushTimeout   = 15 * time.Second
)

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

	// PushTimeout is the window to wait for a firewalled peer's
	// GIV connection after sending PUSH. Zero means the default 15s.
	PushTimeout time.Duration
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
		if o.PushTimeout <= 0 {
			o.PushTimeout = pushTimeout
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

	// pendingPush maps a servent ID to a channel that receives the
	// connection from a firewalled peer dialing back after a PUSH.
	pendingPush sync.Map // [16]byte -> chan net.Conn

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
		e.wg.Add(1)
		go func(c net.Conn) {
			defer e.wg.Done()
			if err := e.serveInbound(ctx, c); err != nil {
				logf("inbound %s: %v", c.RemoteAddr(), err)
			}
		}(conn)
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
func (e *Engine) Search(text string) ([]QueryHit, error) {
	q := Query{MinSpeed: 0, Search: text}
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
	// only delay an empty result.
	if written.Load() > 0 {
		timer := time.NewTimer(timeout)
		<-timer.C
	}

	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	return reg.close(hdr.ID), err
}

// serveInbound classifies an inbound connection. If it starts with "GIV:",
// it is a firewalled peer dialing back after a PUSH; otherwise it is
// a regular peer connection and goes through the normal handshake/serve path.
func (e *Engine) serveInbound(ctx context.Context, conn net.Conn) error {
	defer conn.Close()

	// Peek for GIV
	br := bufio.NewReader(conn)
	peek, err := br.Peek(3)
	if err != nil {
		if ctx.Err() != nil {
			return nil
		}
		return err
	}
	if string(peek) == "GIV" {
		return e.handleGiv(ctx, br, conn)
	}

	// Not a GIV; treat as peer connection. Use prefixConn to replay peeked bytes.
	pc := &peerConn{conn: conn, addr: conn.RemoteAddr()}
	e.mu.Lock()
	e.peers[pc] = struct{}{}
	e.mu.Unlock()
	defer func() {
		e.mu.Lock()
		delete(e.peers, pc)
		e.mu.Unlock()
	}()
	if err := serveConnWithReader(ctx, conn, true, e.opts, e.laddr, br); err != nil {
		return err
	}
	return nil
}

// handleGiv handles a GIV: callback from a firewalled peer after receiving PUSH.
// Format: "GIV: /<file index>/<servant id>\n\n"
// The connection is returned to whoever is waiting for that servant ID.
func (e *Engine) handleGiv(ctx context.Context, br *bufio.Reader, conn net.Conn) error {
	// Read until \n\n or \r\n\r\n
	var buf []byte
	for {
		b, err := br.ReadByte()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		buf = append(buf, b)
		if len(buf) >= 2 && buf[len(buf)-2] == '\n' && buf[len(buf)-1] == '\n' {
			break
		}
		if len(buf) >= 4 && bytes.Equal(buf[len(buf)-4:], []byte("\r\n\r\n")) {
			break
		}
		if len(buf) > 512 {
			break
		}
	}
	line := string(buf)
	// Parse /<index>/<guid>
	if idx := strings.Index(line, "GIV:"); idx >= 0 {
		line = line[idx+4:]
	}
	line = strings.TrimSpace(line)
	if line == "" {
		return fmt.Errorf("invalid GIV")
	}
	if line[0] == '/' {
		line = line[1:]
	}
	slash := strings.IndexByte(line, '/')
	if slash < 0 {
		return fmt.Errorf("invalid GIV")
	}
	idxStr := line[:slash]
	guidStr := line[slash+1:]
	guidStr = strings.TrimRight(guidStr, "\r\n")

	var fileIndex uint32
	fmt.Sscanf(idxStr, "%d", &fileIndex)

	var guid [16]byte
	// Try to parse as 32 hex chars or as raw bytes in some forms; for now just copy if hex length matches
	if len(guidStr) == 32 {
		for i := 0; i < 16; i++ {
			var v byte
			fmt.Sscanf(guidStr[2*i:2*i+2], "%02x", &v)
			guid[i] = v
		}
	}

	if v, ok := e.pendingPush.Load(guid); ok {
		ch := v.(chan net.Conn)
		select {
		case ch <- conn:
		default:
		}
	}
	return nil
}

// FetchHit attempts to download a hit, sending PUSH if the source appears
// firewalled (dial fails).
func (e *Engine) FetchHit(ctx context.Context, from net.Addr, queryID [16]byte, qh QueryHit, hit FileHit, dir string) (DownloadResult, error) {
	d := NewDownloader(qh, hit)
	d.Logf = e.opts.logf()
	res, err := d.Fetch(ctx, dir)
	if err == nil {
		return res, nil
	}
	// If it fails due to dial failure, try PUSH
	// Simple heuristic: look for dial/network errors
	var opErr *net.OpError
	if errors.As(err, &opErr) || errors.Is(err, context.DeadlineExceeded) {
		// Try PUSH
		var push Push
		copy(push.ServentID[:], qh.ServentID[:])
		push.FileIndex = hit.FileIndex
		if la, ok := e.laddr.(*net.TCPAddr); ok && la.IP != nil {
			if ip4 := la.IP.To4(); ip4 != nil {
				copy(push.RequesterIP[:], ip4)
			}
		}
		if la, ok := e.laddr.(*net.TCPAddr); ok {
			push.Port = uint16(la.Port)
		}

		ch := make(chan net.Conn, 1)
		e.pendingPush.Store(push.ServentID, ch)
		defer e.pendingPush.Delete(push.ServentID)

		// Send PUSH to the peer that gave us the hit
		if from != nil {
			// TODO: send PUSH over the connection that delivered the hit
		}

		select {
		case <-ctx.Done():
			return DownloadResult{}, ctx.Err()
		case conn := <-ch:
			// Got callback connection; perform download over it
			return FetchOverConn(ctx, conn, dir, d)
		case <-time.After(e.opts.PushTimeout):
			return DownloadResult{}, fmt.Errorf("push timeout")
		}
	}
	return res, err
}
