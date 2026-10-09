// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Peer connection handling: the 0.6 four-step handshake (request, 200,
// confirmation, messages) in both directions, then a message loop that
// answers PINGs with PONGs, drops TTL-zero messages, pings keep-alive,
// and closes on idle, oversize or cancellation.
//
// One bufio.Reader is shared by the handshake and the message loop. The
// handshake reader may buffer bytes past the CRLF CRLF terminator, and
// losing them would corrupt the first message, so the reader lives for
// the whole connection.

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/version"
)

// handshakeDeadline bounds each step of the handshake. Both sides
// normally answer within a round trip; 30 s only stops a stalled peer
// from pinning a goroutine.
const handshakeDeadline = 30 * time.Second

// writeTimeout bounds any single write, so a peer that stops reading
// cannot pin the connection's writer forever.
const writeTimeout = 30 * time.Second

// keepAliveTTL is the TTL carried by our keep-alive PINGs. Forwarding
// counters are meaningless on a direct link, and this matches the
// "modern servent" headers of real clients.
const keepAliveTTL byte = 7

// pongPayloadSize is the fixed PONG payload: 2-byte port, 4-byte IPv4
// address, 4-byte file count and 4-byte kB count, all little-endian
// except the address.
const pongPayloadSize = 14

// peer is one established-or-connecting TCP link.
type peer struct {
	conn    net.Conn
	inbound bool // accepted by us, rather than dialed by us
	opts    Options
	laddr   net.Addr // our listen address, used in Listen-IP and PONG
	logf    func(format string, args ...any)
	mu      sync.Mutex // serialises writes to conn
}

// serveConn runs one connection until the context ends, the peer dies,
// or a protocol violation is seen, and returns why it stopped. A nil
// return means the context was cancelled or the peer left cleanly.
func serveConn(ctx context.Context, conn net.Conn, inbound bool, opts Options, laddr net.Addr) error {
	p := &peer{
		conn:    conn,
		inbound: inbound,
		opts:    opts,
		laddr:   laddr,
		logf:    opts.logf(),
	}
	if tc, ok := conn.(*net.TCPConn); ok {
		_ = tc.SetKeepAlive(true)
		_ = tc.SetNoDelay(true)
	}
	// Closing the connection is how an idle readLoop, blocked in
	// DecodeHeader, is told the context ended.
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopClose()

	r := bufio.NewReader(conn)
	if inbound {
		if err := p.accept(r); err != nil {
			return err
		}
	} else {
		if err := p.connect(r); err != nil {
			return err
		}
	}
	return p.loop(ctx, r)
}

// accept performs the server side of the 0.6 handshake.
func (p *peer) accept(r *bufio.Reader) error {
	if err := p.conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return err
	}
	hs, err := ReadHandshake(r)
	if err != nil {
		p.writeError(400, "Bad Request")
		return fmt.Errorf("handshake: %w", err)
	}
	if !hs.Request {
		p.writeError(503, "Connect expected")
		return fmt.Errorf("handshake: got %s where GNUTELLA CONNECT/0.6 was expected", hs.Status())
	}
	if !supportsVersion(hs.Version) {
		p.writeError(503, "Unsupported version "+hs.Version)
		return fmt.Errorf("handshake: unsupported version %s", hs.Version)
	}
	p.logf("connect request from %s: version=%s network=%q user-agent=%q remote-ip=%q",
		p.conn.RemoteAddr(), hs.Version, hs.Network(), hs.UserAgent(), hs.RemoteIP())

	if err := p.write(OKReply(
		Field{"Listen-IP", p.listenIPPort()},
		Field{"Remote-IP", stripPort(p.conn.RemoteAddr().String())},
		Field{"User-Agent", version.UserAgent()},
	)); err != nil {
		return err
	}

	// Step 6: the client confirms the 200 before either side sends
	// binary messages.
	if err := p.conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return err
	}
	confirm, err := ReadHandshake(r)
	if err != nil {
		return fmt.Errorf("client confirmation: %w", err)
	}
	if !confirm.IsOK() {
		return fmt.Errorf("client refused connection: %s", confirm.Status())
	}
	p.logf("handshake complete with %s", p.conn.RemoteAddr())
	return nil
}

// connect performs the client side of the 0.6 handshake.
func (p *peer) connect(r *bufio.Reader) error {
	if err := p.conn.SetWriteDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return err
	}
	if err := p.write(ConnectRequest(
		Field{"Listen-IP", p.listenIPPort()},
		Field{"Remote-IP", p.conn.RemoteAddr().String()},
		Field{"User-Agent", version.UserAgent()},
	)); err != nil {
		return err
	}
	if err := p.conn.SetReadDeadline(time.Now().Add(handshakeDeadline)); err != nil {
		return err
	}
	hs, err := ReadHandshake(r)
	if err != nil {
		return fmt.Errorf("response: %w", err)
	}
	if !hs.IsOK() {
		return fmt.Errorf("peer refused connection: %s", hs.Status())
	}
	// Step 6: confirm, then the peer starts sending binary messages.
	if err := p.write(OKReply()); err != nil {
		return err
	}
	p.logf("connected to %s: version=%s network=%q user-agent=%q",
		p.conn.RemoteAddr(), hs.Version, hs.Network(), hs.UserAgent())
	return nil
}

// loop pumps messages and PINGs until the context or the peer ends.
func (p *peer) loop(ctx context.Context, r *bufio.Reader) error {
	ticker := time.NewTicker(p.opts.KeepAliveInterval)
	defer ticker.Stop()

	errCh := make(chan error, 1)
	go func() { errCh <- p.readLoop(ctx, r) }()

	for {
		select {
		case <-ctx.Done():
			_ = p.conn.Close()
			<-errCh
			return nil
		case err := <-errCh:
			_ = p.conn.Close()
			if err == nil {
				return nil
			}
			return err
		case <-ticker.C:
			if err := p.sendKeepAlive(); err != nil {
				_ = p.conn.Close()
				return fmt.Errorf("keep-alive: %w", err)
			}
		}
	}
}

// readLoop reads messages until the connection fails, the context
// ends, or IdleTimeout elapses without a complete message.
func (p *peer) readLoop(ctx context.Context, r *bufio.Reader) error {
	for {
		if err := p.conn.SetReadDeadline(time.Now().Add(p.opts.IdleTimeout)); err != nil {
			return err
		}
		hdr, err := DecodeHeader(r)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				return fmt.Errorf("idle: no message within %s", p.opts.IdleTimeout)
			}
			return err
		}
		buf := make([]byte, hdr.Length)
		if _, err := io.ReadFull(r, buf); err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		// A message with TTL 0 must neither be processed nor
		// forwarded: its life is over. This is what keeps our PONG
		// TTL-minus-one replies from being answered again in a loop.
		if hdr.TTL == 0 {
			p.logf("dropping %s from %s: TTL reached zero", typeName(hdr.Type), p.conn.RemoteAddr())
			continue
		}
		if err := p.handle(hdr, buf); err != nil {
			return err
		}
	}
}

// handle processes one message. Routing and file transfer are out of
// scope for this item, so Query, QueryHit and Push are acknowledged in
// the log and ignored.
func (p *peer) handle(hdr Header, payload []byte) error {
	switch hdr.Type {
	case MsgPing:
		return p.handlePing(hdr)
	case MsgPong:
		p.logf("pong from %s: id=%x ttl=%d hops=%d payload=%d bytes",
			p.conn.RemoteAddr(), hdr.ID, hdr.TTL, hdr.Hops, len(payload))
		return nil
	case MsgQuery, MsgQueryHit, MsgPush:
		p.logf("ignoring %s from %s: routing and transfer are out of scope",
			typeName(hdr.Type), p.conn.RemoteAddr())
		return nil
	default:
		p.logf("ignoring unknown payload type 0x%02x from %s", hdr.Type, p.conn.RemoteAddr())
		return nil
	}
}

// handlePing replies to a PING with a PONG echoing the descriptor ID.
// The reply TTL is the ping TTL minus one: a forwarded reply would
// expire one hop sooner, and the hop at which it dies (TTL 0) is where
// it is dropped. See docs/handoff.md for how this trades against the
// 0.6 pong-caching scheme.
//
// The decrement is clamped to a minimum of 1: a direct/keep-alive PING
// arrives with TTL=1 and Hops=0, and a PONG with TTL=0 and Hops=0 is an
// invalid descriptor per the annotated 0.4 spec ("All servents MUST
// consider that TTL+Hops values between 1 and 7 are valid"). Such a
// reply would also be dropped by our own readLoop before it is seen,
// so this is a self-inconsistency as much as a spec violation.
func (p *peer) handlePing(ping Header) error {
	payload := p.pongPayload()
	ttl := ping.TTL - 1
	if ttl == 0 {
		ttl = 1
	}
	hdr := Header{
		ID:     ping.ID,
		Type:   MsgPong,
		TTL:    ttl,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	p.logf("replying pong to %s: id=%x ttl=%d->%d hops=%d",
		p.conn.RemoteAddr(), ping.ID, ping.TTL, hdr.TTL, hdr.Hops)
	return p.writeMessage(hdr, payload)
}

// sendKeepAlive sends an empty PING. A fresh descriptor ID is used each
// time; old Gnutella versions could not tell such PINGs apart from the
// first handshake probe, but 0.6 peers answer them, which is all a
// liveness link needs.
func (p *peer) sendKeepAlive() error {
	hdr := Header{ID: newDescriptorID(), Type: MsgPing, TTL: keepAliveTTL, Hops: 0}
	return p.writeMessage(hdr, nil)
}

// pongPayload encodes the fixed 14-byte PONG payload: our listen port,
// the IPv4 address this connection is reachable at (0.0.0.0 if the
// local address is not IPv4), and zeros for shared-file counts.
func (p *peer) pongPayload() []byte {
	b := make([]byte, pongPayloadSize)
	binary.LittleEndian.PutUint16(b[0:2], p.listenPort())
	if ta, ok := p.conn.LocalAddr().(*net.TCPAddr); ok {
		if ip4 := ta.IP.To4(); ip4 != nil {
			copy(b[2:6], ip4)
		}
	}
	return b
}

// writeMessage writes a header and its payload in one call.
func (p *peer) writeMessage(hdr Header, payload []byte) error {
	buf := hdr.AppendTo(nil)
	buf = append(buf, payload...)
	return p.write(buf)
}

// write serialises writes from the reader goroutine (PONGs) and the
// loop goroutine (keep-alive PINGs).
func (p *peer) write(b []byte) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if err := p.conn.SetWriteDeadline(time.Now().Add(writeTimeout)); err != nil {
		return err
	}
	_, err := p.conn.Write(b)
	return err
}

// writeError sends a refusal, best-effort: the peer is probably gone or
// about to hang up anyway.
func (p *peer) writeError(code int, reason string) {
	_ = p.write(ErrorReply(code, reason))
}

// listenPort is the port our engine listens on, as advertised in PONGs.
func (p *peer) listenPort() uint16 {
	ta, ok := p.laddr.(*net.TCPAddr)
	if !ok {
		return 0
	}
	return uint16(ta.Port)
}

// listenIPPort renders "ip:port" for the Listen-IP header. An
// unspecified local address (0.0.0.0 listener) is advertised as
// 0.0.0.0:port, which is what real clients send for "I'm not sure".
func (p *peer) listenIPPort() string {
	ta, ok := p.laddr.(*net.TCPAddr)
	if !ok {
		return ""
	}
	ip := ta.IP.String()
	if ip == "" || ta.IP.IsUnspecified() {
		return "0.0.0.0:" + fmt.Sprint(ta.Port)
	}
	return ip + ":" + fmt.Sprint(ta.Port)
}

// stripPort removes the ":port" suffix of a host:port string. Used for
// the Remote-IP header.
func stripPort(hostport string) string {
	if host, _, err := net.SplitHostPort(hostport); err == nil {
		return host
	}
	return hostport
}
