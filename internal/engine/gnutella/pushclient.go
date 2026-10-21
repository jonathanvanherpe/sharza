// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The push transfer, both ends of the dial-back.
//
// Requester (download) side, the one this engine drives:
//
//  1. PushFetch registers a pending push under (servent ID, file index),
//     writes a PUSH to the peer that delivered the hit, and waits.
//  2. The firewalled source recognises its servent ID, dials the address
//     the PUSH named, and writes "GIV <index>:<servent-id>/<name>\n\n".
//  3. serveConn sees the GIV before any handshake parse and hands the
//     socket to the waiting push. Nothing else claims it.
//  4. The requester sends the same GET a direct download would, over that
//     same socket, and receives the body through Downloader.receive, so
//     the size, truncation and name rules are the direct ones.
//
// Source (pusher) side, the minimum the two-engine test needs: an engine
// that receives a PUSH naming its own servent ID dials back, announces the
// transfer with GIV, and answers the GET with a catalogued file's bytes.
// A PUSH for any other servent ID is ignored.
//
// Lock discipline: the registry has one mutex for its maps and nothing
// else. The PUSH itself is written under peerConn.mu, the engine's write
// lock, and the GET over the dial-back socket is not shared with any other
// writer, so peer.mu is not taken here.

import (
	"bufio"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pushWaitTimeout bounds how long PushFetch waits for the source to dial
// back. The caller's context usually ends the wait sooner.
const pushWaitTimeout = 30 * time.Second

// pushKey identifies one pending push: the source's servent ID and the
// file index requested from it. A GIV must match both to be claimed.
type pushKey struct {
	id    [idSize]byte
	index uint32
}

// pushConn is a dial-back socket claimed by a waiting push. r is the
// reader that consumed the GIV line; anything it buffered past that line
// belongs to the response and must be read through it.
type pushConn struct {
	conn net.Conn
	r    *bufio.Reader
}

// pushRegistry holds the engine's push state: the route each servent ID
// was last heard on, and the pushes waiting for a dial-back.
type pushRegistry struct {
	mu sync.Mutex
	// routes maps a servent ID to the connection that delivered a
	// QUERYHIT from it. A PUSH for that servent is written there.
	routes map[[idSize]byte]*peerConn
	// pending maps a waiting push to the channel its socket is handed
	// over on. The channel has room for one, and a key is removed before
	// its socket is sent, so a second GIV for the same push is refused.
	pending map[pushKey]chan pushConn
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{
		routes:  make(map[[idSize]byte]*peerConn),
		pending: make(map[pushKey]chan pushConn),
	}
}

// setRoute records pc as the connection a hit from id arrived on.
func (r *pushRegistry) setRoute(id [idSize]byte, pc *peerConn) {
	r.mu.Lock()
	r.routes[id] = pc
	r.mu.Unlock()
}

// route returns the connection a PUSH for id should be written to, or nil
// when no hit from id has been seen.
func (r *pushRegistry) route(id [idSize]byte) *peerConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routes[id]
}

// register records a pending push and returns the channel its dial-back
// socket will arrive on.
func (r *pushRegistry) register(key pushKey) chan pushConn {
	ch := make(chan pushConn, 1)
	r.mu.Lock()
	r.pending[key] = ch
	r.mu.Unlock()
	return ch
}

// claim hands a dial-back socket to the push waiting on key. It reports
// false when nothing is waiting, in which case the caller must close the
// socket: an unsolicited GIV is not a transfer.
func (r *pushRegistry) claim(key pushKey, pc pushConn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	ch, ok := r.pending[key]
	if !ok {
		return false
	}
	delete(r.pending, key)
	ch <- pc
	return true
}

// cancel withdraws a pending push that is no longer waiting. A socket
// already claimed but never received is closed here, because nobody else
// will own it. Once cancel returns, no further claim can succeed for key.
func (r *pushRegistry) cancel(key pushKey) {
	r.mu.Lock()
	ch, ok := r.pending[key]
	delete(r.pending, key)
	r.mu.Unlock()
	if !ok {
		return
	}
	select {
	case pc := <-ch:
		_ = pc.conn.Close()
	default:
	}
}

// ---- Requester side ---------------------------------------------------

// acceptGIV handles an inbound connection whose first bytes are "GIV ".
// It reads the GIV line and the blank line that ends it, then claims the
// socket for the waiting push. On success serveConn returns without
// closing the socket: the push owns it from here.
func (p *peer) acceptGIV(r *bufio.Reader) error {
	if err := p.conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return err
	}
	line, err := readGIVLine(r)
	if err != nil {
		return err
	}
	index, id, err := parseGIV(line)
	if err != nil {
		return err
	}
	key := pushKey{id: id, index: index}
	if p.opts.pushes == nil || !p.opts.pushes.claim(key, pushConn{conn: p.conn, r: r}) {
		_ = p.conn.Close()
		return fmt.Errorf("unsolicited GIV for index %d servent %x from %s",
			index, id, p.conn.RemoteAddr())
	}
	p.logf("push dial-back from %s: index=%d", p.conn.RemoteAddr(), index)
	return nil
}

// readGIVLine reads "GIV <index>:<servent-id>/<name>" and the blank line
// that terminates it. ReadSlice is bounded by the reader's buffer, so a
// peer cannot grow the line without limit by never sending a newline.
func readGIVLine(r *bufio.Reader) (string, error) {
	line, err := r.ReadSlice('\n')
	if err != nil {
		return "", fmt.Errorf("giv: %w", err)
	}
	blank, err := r.ReadSlice('\n')
	if err != nil {
		return "", fmt.Errorf("giv: terminator: %w", err)
	}
	if s := strings.TrimRight(string(blank), "\r\n"); s != "" {
		return "", fmt.Errorf("giv: expected blank line after GIV, got %q", s)
	}
	return strings.TrimRight(string(line), "\r\n"), nil
}

// parseGIV decodes "GIV <index>:<32 hex digits>/<name>". The name is not
// used to route the transfer and is ignored. The servent ID is the GUID
// the PUSH named, so a GIV for any other servent is unsolicited.
func parseGIV(line string) (index uint32, id [idSize]byte, err error) {
	bad := func() error { return fmt.Errorf("%w: GIV line %q", ErrPushBadFormat, line) }
	rest, ok := strings.CutPrefix(line, "GIV ")
	if !ok {
		return 0, id, bad()
	}
	idxStr, tail, ok := strings.Cut(rest, ":")
	if !ok {
		return 0, id, bad()
	}
	guidHex, _, _ := strings.Cut(tail, "/")
	n, err := strconv.ParseUint(idxStr, 10, 32)
	if err != nil {
		return 0, id, bad()
	}
	raw, err := hex.DecodeString(guidHex)
	if err != nil || len(raw) != idSize {
		return 0, id, bad()
	}
	copy(id[:], raw)
	return uint32(n), id, nil
}

// fetchPushed performs the transfer over a claimed dial-back socket: the
// same GET a direct download sends, written to the socket, and the
// response read from the reader that consumed the GIV. The socket is
// closed by the caller; ctx cancellation closes it here so a stalled body
// cannot hold the goroutine.
func (d *Downloader) fetchPushed(ctx context.Context, p plan, pc pushConn) (DownloadResult, error) {
	stop := context.AfterFunc(ctx, func() { _ = pc.conn.Close() })
	defer stop()

	src := d.QH.Source()
	rawURL := fmt.Sprintf("http://%s/gnutella/%d", src, d.Hit.FileIndex)
	req, err := d.newRequest(ctx, rawURL, p.offset)
	if err != nil {
		return DownloadResult{}, err
	}
	if err := pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return DownloadResult{}, err
	}
	if err := req.Write(pc.conn); err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: push GET %s: %w", rawURL, err)
	}
	if err := pc.conn.SetReadDeadline(time.Now().Add(downloadHeaderTimeout)); err != nil {
		return DownloadResult{}, err
	}
	resp, err := http.ReadResponse(pc.r, req)
	if err != nil {
		return DownloadResult{}, fmt.Errorf("gnutella: push response %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	// The body is bounded by the caller's context, not a deadline, as in
	// a direct download.
	if err := pc.conn.SetReadDeadline(time.Time{}); err != nil {
		return DownloadResult{}, err
	}
	return d.receive(p, resp, rawURL, src)
}

// ---- Source (pusher) side --------------------------------------------

// handlePush reacts to a PUSH that reached this engine. A PUSH is for us
// only when its servent ID is ours; any other is ignored, because this
// engine does not route PUSH (see docs/handoff.md). A PUSH for us makes
// us dial the requester back; that runs off the read loop so a slow
// requester cannot stall the connection it arrived on.
func (p *peer) handlePush(ctx context.Context, payload []byte) error {
	push, err := DecodePush(payload)
	if err != nil {
		p.logf("bad push from %s: %v", p.conn.RemoteAddr(), err)
		return nil
	}
	if push.ServentID != p.opts.servent {
		p.logf("ignoring push for servent %x from %s: not ours", push.ServentID, p.conn.RemoteAddr())
		return nil
	}
	p.logf("push for us from %s: index=%d, dialing back", p.conn.RemoteAddr(), push.FileIndex)
	go p.dialBack(ctx, push)
	return nil
}

// dialBack connects to the address a PUSH named, announces the transfer
// with GIV, and serves the GET the requester sends back over the same
// socket. A file not in the catalogue, or a request for another path, is
// answered 404 and the socket closes.
func (p *peer) dialBack(ctx context.Context, push Push) {
	addr := net.JoinHostPort(net.IP(push.IP[:]).String(), strconv.Itoa(int(push.Port)))
	dialer := net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		p.logf("push dial-back to %s failed: %v", addr, err)
		return
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()

	entry, ok := p.catalogueEntry(push.FileIndex)
	if !ok {
		p.logf("push dial-back to %s: index %d not served", addr, push.FileIndex)
		return
	}
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return
	}
	giv := fmt.Sprintf("GIV %d:%x/%s\n\n", push.FileIndex, p.opts.servent, sanitizeFileName(entry.Name))
	if _, err := conn.Write([]byte(giv)); err != nil {
		p.logf("push GIV to %s: %v", addr, err)
		return
	}

	r := bufio.NewReader(conn)
	if err := conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return
	}
	req, err := http.ReadRequest(r)
	if err != nil {
		p.logf("push request from %s: %v", addr, err)
		return
	}
	defer req.Body.Close()
	if req.Method != http.MethodGet || req.URL.Path != fmt.Sprintf("/gnutella/%d", push.FileIndex) {
		_, _ = io.WriteString(conn, "HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
		return
	}
	head := fmt.Sprintf("HTTP/1.1 200 OK\r\nContent-Length: %d\r\nX-Gnutella-Content-Length: %d\r\n"+
		"Content-Type: application/binary\r\nConnection: close\r\n\r\n", len(entry.Data), len(entry.Data))
	if err := conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return
	}
	if _, err := conn.Write(append([]byte(head), entry.Data...)); err != nil {
		p.logf("push body to %s: %v", addr, err)
		return
	}
	p.logf("served index %d to %s by push: %d bytes", push.FileIndex, addr, len(entry.Data))
}

// catalogueEntry finds a served file by index. An entry with no Data is
// advertised in QUERYHITs but not served, so it is not a match here.
func (p *peer) catalogueEntry(index uint32) (FileEntry, bool) {
	for _, fe := range p.opts.Catalogue {
		if fe.Index == index && fe.Data != nil {
			return fe, true
		}
	}
	return FileEntry{}, false
}

// errNoRoute is returned by PushFetch when no live connection delivered a
// hit from the source's servent, so there is no peer to write the PUSH to.
var errNoRoute = errors.New("gnutella: push: no live route to the source's servent")
