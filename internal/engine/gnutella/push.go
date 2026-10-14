// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Gnutella 0.6 push, downloader half.
//
// A firewalled servent advertises itself in a QUERYHIT with no reachable
// address (port 0, or an unspecified IP), so a downloader cannot open
// the transfer connection to it. The convention is: the downloader sends
// a PUSH message naming the servent to be pushed, carrying its own
// dial-back address; that servent then opens a new connection back to
// the dial-back address and identifies itself with a "GIV" line; the
// downloader matches the GIV to the PUSH it sent and sends its HTTP GET
// over that same new connection.
//
// This file implements the downloader side: the PUSH codec, the GIV
// codec, the registry that matches a dial-back to the PUSH that caused
// it, and the accept-path handler that turns a dial-back into a usable
// connection. The responder half (answering an inbound PUSH by dialling
// back and serving the GET) is out of scope for this slice; see
// docs/handoff.md.
//
// Wire format, verified against the published 0.6 message architecture
// and Shareaza (Network.cpp:SendPush, G1Packet.cpp:OnPush):
//
//	PUSH (0x40) payload, 26 bytes:
//	  16  servent identifier of the firewalled servent to push
//	   4  file index, little-endian
//	   4  dial-back IPv4 address, network (big-endian) order
//	   2  dial-back port, little-endian
//
//	GIV, the first line of the servent's dial-back:
//	  "GIV <index>:<32 hex digits>/<url-encoded name>\n\n"
//	The 32 hex digits are the dialling servent's own identifier, which
//	is the identifier the PUSH named: Handshake.cpp:OnConnected writes
//	MyProfile.oGUID, and CDownloadSource::CheckPush matches it against
//	the source's id from the QUERYHIT.

import (
	"bufio"
	"context"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// pushPayloadSize is the fixed length of a PUSH payload. Shareaza
// rejects anything shorter (G1Packet.cpp:OnPush: m_nLength < 26).
const pushPayloadSize = 26

// maxGIVLine caps a GIV line so a hostile dial-back cannot make us
// buffer without bound. A GIV line is a small index, 32 hex digits and a
// file name; 8 KiB is far past any real name.
const maxGIVLine = 8 << 10

// givPrefix is the first thing a push dial-back sends. The accept path
// peeks for it to tell a dial-back from a Gnutella handshake.
const givPrefix = "GIV "

// pushTTL is the TTL on an outbound PUSH. Shareaza sends
// MaximumTTL - 1 (Network.cpp:SendPush). A direct neighbour delivers it
// whole; the decrement only matters if the PUSH is forwarded.
const pushTTL byte = 7

// defaultPushTimeout bounds how long a downloader waits for a PUSH's
// dial-back before giving up. See Options.PushTimeout.
const defaultPushTimeout = 30 * time.Second

var (
	// ErrPushBadFormat is returned when a PUSH payload is malformed.
	ErrPushBadFormat = errors.New("gnutella: malformed push")

	// ErrGIVBadFormat is returned when a dial-back's GIV line is
	// malformed.
	ErrGIVBadFormat = errors.New("gnutella: malformed GIV")

	// ErrPushTimeout is returned when a PUSH's dial-back never arrives.
	ErrPushTimeout = errors.New("gnutella: push not answered")
)

// Push is a Gnutella PUSH message payload (0x40): the downloader half's
// request that a firewalled servent dial back.
type Push struct {
	// ServentID is the identifier of the servent to push: the
	// QUERYHIT's servent identifier, i.e. the firewalled peer that
	// holds the file.
	ServentID [idSize]byte

	// FileIndex is the index of the file the push is for.
	FileIndex uint32

	// IP and Port are where the pushed servent should dial back: the
	// downloader's own reachable address. IP is in network order.
	IP   [4]byte
	Port uint16
}

// EncodePush encodes a Push to its exact 26-byte wire payload.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:idSize], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[idSize:idSize+4], p.FileIndex)
	copy(out[idSize+4:idSize+8], p.IP[:]) // network order, as stored
	binary.LittleEndian.PutUint16(out[idSize+8:pushPayloadSize], p.Port)
	return out
}

// DecodePush decodes a PUSH payload. A payload shorter than 26 bytes is
// malformed; a longer one (a GGEP trailer) has its first 26 bytes read
// and the rest ignored, which is what Shareaza does.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload is %d bytes, want at least %d",
			ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	p := Push{
		FileIndex: binary.LittleEndian.Uint32(payload[idSize : idSize+4]),
		Port:      binary.LittleEndian.Uint16(payload[idSize+8 : pushPayloadSize]),
	}
	copy(p.ServentID[:], payload[0:idSize])
	copy(p.IP[:], payload[idSize+4:idSize+8])
	return p, nil
}

// GIV is the first line of a servent's push dial-back: it identifies the
// servent and the file it is about to serve.
type GIV struct {
	// FileIndex is the index the pushing servent is serving.
	FileIndex uint32

	// ServentID is the pushing servent's own identifier, which is the
	// identifier the PUSH named.
	ServentID [idSize]byte

	// Name is the file's name, URL-decoded. Shareaza's own GIV omits
	// it, so it may be empty.
	Name string
}

// FormatGIV renders a GIV line including the trailing blank line. The
// downloader only parses GIV; this is the encoder for tests and for a
// future responder half.
func FormatGIV(g GIV) string {
	return fmt.Sprintf("GIV %d:%s/%s\n\n", g.FileIndex, hex.EncodeToString(g.ServentID[:]), url.PathEscape(g.Name))
}

// ParseGIV parses one GIV line (without its trailing blank line). The
// format is "GIV <index>:<32 hex digits>/<url-encoded name>"; the name
// may be empty, and Shareaza accepts the hex digits in either case
// (Handshake.cpp:OnAcceptGive).
func ParseGIV(line string) (GIV, error) {
	line = strings.TrimRight(line, "\r\n")
	if !strings.HasPrefix(line, givPrefix) {
		return GIV{}, fmt.Errorf("%w: %q does not start with %q", ErrGIVBadFormat, line, givPrefix)
	}
	rest := line[len(givPrefix):]
	slash := strings.IndexByte(rest, '/')
	if slash < 0 {
		return GIV{}, fmt.Errorf("%w: %q has no file name separator", ErrGIVBadFormat, line)
	}
	head, rawName := rest[:slash], rest[slash+1:]
	colon := strings.IndexByte(head, ':')
	if colon <= 0 {
		return GIV{}, fmt.Errorf("%w: %q has no file index", ErrGIVBadFormat, line)
	}
	index, err := strconv.ParseUint(head[:colon], 10, 32)
	if err != nil {
		return GIV{}, fmt.Errorf("%w: bad file index in %q: %v", ErrGIVBadFormat, line, err)
	}
	idHex := head[colon+1:]
	if len(idHex) != idSize*2 {
		return GIV{}, fmt.Errorf("%w: servent id %q is not %d hex digits", ErrGIVBadFormat, idHex, idSize*2)
	}
	raw, err := hex.DecodeString(idHex)
	if err != nil {
		return GIV{}, fmt.Errorf("%w: bad servent id %q: %v", ErrGIVBadFormat, idHex, err)
	}
	g := GIV{FileIndex: uint32(index)}
	copy(g.ServentID[:], raw)
	if rawName != "" {
		name, err := url.PathUnescape(rawName)
		if err != nil {
			return GIV{}, fmt.Errorf("%w: bad file name escape %q: %v", ErrGIVBadFormat, rawName, err)
		}
		g.Name = name
	}
	return g, nil
}

// readGIV reads a GIV line and the blank line that follows it, leaving r
// positioned at whatever the peer sends next (the downloader's GET goes
// the other way, so in practice r is then idle).
func readGIV(r *bufio.Reader) (GIV, error) {
	line, err := readGIVLine(r)
	if err != nil {
		return GIV{}, err
	}
	g, err := ParseGIV(line)
	if err != nil {
		return GIV{}, err
	}
	if _, err := readGIVLine(r); err != nil {
		return GIV{}, err
	}
	return g, nil
}

// readGIVLine reads one newline-terminated line, bounded by maxGIVLine
// so a peer that never sends a newline cannot grow the buffer without
// bound.
func readGIVLine(r *bufio.Reader) (string, error) {
	var b strings.Builder
	for {
		c, err := r.ReadByte()
		if err != nil {
			return "", err
		}
		if c == '\n' {
			return strings.TrimSuffix(b.String(), "\r"), nil
		}
		if b.Len() >= maxGIVLine {
			return "", fmt.Errorf("%w: line exceeds %d bytes", ErrGIVBadFormat, maxGIVLine)
		}
		b.WriteByte(c)
	}
}

// pushConn is a delivered dial-back: the connection, its buffered
// reader (positioned just past the GIV's blank line), and the GIV.
type pushConn struct {
	conn net.Conn
	br   *bufio.Reader
	giv  GIV
}

// pushState is the lifecycle of a PushRequest. A request is waiting
// until either a dial-back is delivered or the waiter gives up on it;
// exactly one of the two wins.
type pushState int

const (
	pushWaiting pushState = iota
	pushDelivered
	pushEnded
)

// PushRequest is one in-flight PUSH. BeginPush registers it, writes the
// PUSH, and the caller waits on it for the dial-back the PUSH causes.
type PushRequest struct {
	registry  *pushRegistry
	serventID [idSize]byte
	timeout   time.Duration

	conns chan pushConn // capacity 1, so deliver never blocks

	mu    sync.Mutex
	state pushState
}

// Wait blocks until the pushed servent dials back, the timeout elapses,
// or ctx ends. On success the returned connection is owned by the
// caller, which must close it. On any error there is no connection.
func (req *PushRequest) Wait(ctx context.Context) (pushConn, error) {
	timer := time.NewTimer(req.timeout)
	defer timer.Stop()
	select {
	case pc := <-req.conns:
		req.end()
		return pc, nil
	case <-timer.C:
		return req.abandon(ErrPushTimeout)
	case <-ctx.Done():
		return req.abandon(ctx.Err())
	}
}

// abandon gives up on the request. If no dial-back has been delivered it
// marks the request ended, so a later dial-back is refused; if a
// dial-back won the race after all, its connection is taken off the
// channel and closed rather than leaked.
func (req *PushRequest) abandon(err error) (pushConn, error) {
	if req.end() {
		return pushConn{}, err
	}
	pc := <-req.conns
	_ = pc.conn.Close()
	return pushConn{}, err
}

// end marks the request finished if it is still waiting, and always
// removes it from the registry. It reports whether this call is the one
// that ended the request.
func (req *PushRequest) end() bool {
	req.mu.Lock()
	won := false
	if req.state == pushWaiting {
		req.state = pushEnded
		won = true
	}
	req.mu.Unlock()
	req.registry.forget(req.serventID, req)
	return won
}

// deliver hands a dial-back to the waiting downloader. It reports
// whether the request was still waiting: a false return means the
// downloader timed out first, and the caller must close the connection.
func (req *PushRequest) deliver(pc pushConn) bool {
	req.mu.Lock()
	if req.state != pushWaiting {
		req.mu.Unlock()
		return false
	}
	req.state = pushDelivered
	req.mu.Unlock()
	// The channel has capacity 1 and deliver is the only sender, so this
	// never blocks even if Wait has already left the select.
	req.conns <- pc
	return true
}

// pushRegistry matches a dial-back to the PUSH that caused it. The key
// is the servent identifier the PUSH named, which is also the
// identifier the dial-back's GIV carries.
type pushRegistry struct {
	mu      sync.Mutex
	pending map[[idSize]byte]*PushRequest
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{pending: make(map[[idSize]byte]*PushRequest)}
}

// register claims id for a new request. It reports false if another PUSH
// is already pending for the same servent, which is a conflict rather
// than a queue: one servent dials back at most once per PUSH, and two
// requests for it could not be told apart by their GIVs.
func (r *pushRegistry) register(id [idSize]byte, timeout time.Duration) (*PushRequest, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.pending[id]; dup {
		return nil, false
	}
	req := &PushRequest{
		registry:  r,
		serventID: id,
		timeout:   timeout,
		conns:     make(chan pushConn, 1),
	}
	r.pending[id] = req
	return req, true
}

// lookup returns the request waiting under id, or nil.
func (r *pushRegistry) lookup(id [idSize]byte) *PushRequest {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending[id]
}

// forget removes req from under id, if it is still the registered one.
func (r *pushRegistry) forget(id [idSize]byte, req *PushRequest) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[id] == req {
		delete(r.pending, id)
	}
}

// isPushDialback reports whether an accepted connection is a push
// dial-back rather than a Gnutella handshake, by peeking at its first
// bytes for the GIV prefix. It leaves the bytes in the reader for
// whichever path runs next. A peer that connects and says nothing is not
// a dial-back; the peek times out and the handshake path reports the
// stall.
func isPushDialback(conn net.Conn, br *bufio.Reader) bool {
	if err := conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return false
	}
	p, err := br.Peek(len(givPrefix))
	if err != nil {
		return false
	}
	return string(p) == givPrefix
}

// servePush handles a dial-back on the accept path. Its first line is a
// GIV naming the servent and file. On a match, ownership of conn passes
// to the waiting downloader and servePush must not close it; on any
// failure servePush closes conn itself (the caller closes it on a
// non-nil return).
func (e *Engine) servePush(conn net.Conn, br *bufio.Reader) error {
	if err := conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return err
	}
	giv, err := readGIV(br)
	if err != nil {
		return err
	}
	req := e.pushes.lookup(giv.ServentID)
	if req == nil {
		// Nobody asked for this. Tell the dialler, as Shareaza does
		// (Handshake.cpp:OnAcceptGive), so it stops waiting.
		refusePush(conn)
		return fmt.Errorf("dial-back from %s names servent %x, which no live PUSH is waiting for",
			conn.RemoteAddr(), giv.ServentID)
	}
	if !req.deliver(pushConn{conn: conn, br: br, giv: giv}) {
		return fmt.Errorf("dial-back from %s arrived after the PUSH was abandoned", conn.RemoteAddr())
	}
	return nil
}

// refusePush writes the 503 a GIV receiver sends when it does not
// recognise the push, best-effort: the dialler is about to be dropped.
func refusePush(conn net.Conn) {
	_ = conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	_, _ = conn.Write([]byte("GNUTELLA/0.6 503 Unknown push\r\n\r\n"))
}
