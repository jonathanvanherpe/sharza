// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Gnutella 0.6 PUSH: the downloader half of a transfer from a servent
// that cannot accept inbound connections.
//
// A QUERYHIT may advertise a source that is unreachable: an unspecified
// IPv4 address or a zero port. Its trailing 16-byte servent identifier
// is the routing key for a PUSH. The downloader writes a PUSH back over
// the connection the QUERYHIT arrived on, naming the servent that should
// act. That is the QUERYHIT's own servent identifier, exactly as
// Shareaza's CG1Packet::OnPush decides with
// validAndEqual(oClientID, MyProfile.oGUID): the holder recognises its
// own GUID and opens the connection back to us. The address in the PUSH
// is the one the holder should connect to, which is this engine's local
// address on that link plus its listen port.
//
// The holder dials that address. The engine routes the dial-back
// connection to a pending-push registry instead of the 0.6 handshake;
// the caller takes the connection and runs the transfer over it with
// Downloader.FetchConn.
//
// Two deliberate simplifications, both recorded in docs/handoff.md:
//
//   - Real clients open a pushed connection with a "GIV <index>:<guid>/"
//     line and only then expect the HTTP request. This slice sends the
//     GET straight over the dial-back and never reads a GIV, so it is
//     proven against a scripted peer that tolerates that, not against a
//     live client.
//   - The registry keys a pending push by servent identifier and file
//     index, and matches the inbound dial-back by source IP. A real peer
//     that dials back from a different address, or two holders behind one
//     address, are not distinguished; the claim timeout bounds the
//     damage.

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

// pushPayloadSize is the fixed part of a PUSH payload before any GGEP
// block: 16-byte servent identifier, 4-byte file index, 4-byte IPv4
// address and 2-byte port.
const pushPayloadSize = 26

// pushTTL is the TTL carried by a PUSH. The message travels one direct
// link; like a keep-alive PING, the forwarding counters are meaningful
// only to a router, which this engine is not.
const pushTTL byte = 7

// pushClaimTimeout is the default window between registering a push and
// the holder's dial-back being claimed. An inbound connection that is
// offered to a push nobody claims is closed when the window lapses, so
// it can neither pin the accept loop nor linger as an idle socket.
const pushClaimTimeout = 30 * time.Second

// Push is a Gnutella PUSH message (0x40). ServentID is the routing key
// and names the servent that should act (the QUERYHIT's own identifier);
// FileIndex is the file to serve; IP and Port are the address the holder
// connects back to. The index and port are little-endian and the IPv4
// address is big-endian, like every other message in the protocol.
type Push struct {
	ServentID [idSize]byte
	FileIndex uint32
	IP        [4]byte
	Port      uint16
}

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// ErrNoPushRoute reports that no live peer connection is registered for
// a QUERYHIT's servent identifier, so the PUSH cannot be delivered.
var ErrNoPushRoute = errors.New("gnutella: no peer route for push")

// ErrNoPushPending reports that a push was never requested, or was
// abandoned before its dial-back arrived.
var ErrNoPushPending = errors.New("gnutella: no pending push")

// ErrPushTimeout reports that a pending push's claim window lapsed
// before the holder's dial-back was claimed.
var ErrPushTimeout = errors.New("gnutella: push claim timed out")

// EncodePush encodes a Push to its wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload. Anything past the fixed 26
// bytes is a GGEP block and is not interpreted.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload %d bytes, want at least %d",
			ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	var p Push
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushKey identifies one pending push: the servent that will do the
// pushing and the file it was asked for. The servent identifier is the
// routing key a QUERYHIT carries, and the file index separates two
// requests to the same holder.
type pushKey struct {
	id    [idSize]byte
	index uint32
}

// pendingPush is one registered push waiting for its dial-back.
// connCh carries the connection the holder opened; done closes when the
// entry is claimed or its window lapses. Every field is guarded by the
// owning registry's mutex.
type pendingPush struct {
	key    pushKey
	srcIP  [4]byte
	connCh chan net.Conn
	done   chan struct{}
	timer  *time.Timer
	closed bool
}

// pushRegistry maps a QUERYHIT's servent identifier to the peer
// connection it arrived on, and holds the pushes awaiting their
// dial-back. One lock guards both: the accept loop, the peer message
// loops and the transfer caller all touch it, and none of them does
// enough work under it to matter.
type pushRegistry struct {
	mu      sync.Mutex
	routes  map[[idSize]byte]*peerConn
	pending map[pushKey]*pendingPush
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{
		routes:  make(map[[idSize]byte]*peerConn),
		pending: make(map[pushKey]*pendingPush),
	}
}

// recordRoute remembers that id arrived over pc, so a later PUSH for
// that servent is written back over the same connection.
func (r *pushRegistry) recordRoute(id [idSize]byte, pc *peerConn) {
	r.mu.Lock()
	r.routes[id] = pc
	r.mu.Unlock()
}

// removePeer drops every route that pointed at pc. Called when a
// connection ends, so a dead peer is never written to.
func (r *pushRegistry) removePeer(pc *peerConn) {
	r.mu.Lock()
	for id, p := range r.routes {
		if p == pc {
			delete(r.routes, id)
		}
	}
	r.mu.Unlock()
}

// route returns the peer connection a servent identifier was last seen
// on, or nil.
func (r *pushRegistry) route(id [idSize]byte) *peerConn {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routes[id]
}

// register starts a pending push. A second registration for the same key
// replaces the first, which is abandoned. The claim timeout removes the
// entry and closes any unclaimed connection it holds.
func (r *pushRegistry) register(key pushKey, srcIP [4]byte, timeout time.Duration) *pendingPush {
	pp := &pendingPush{
		key:    key,
		srcIP:  srcIP,
		connCh: make(chan net.Conn, 1),
		done:   make(chan struct{}),
	}
	r.mu.Lock()
	if old := r.pending[key]; old != nil {
		r.expireLocked(old)
	}
	r.pending[key] = pp
	r.mu.Unlock()

	pp.timer = time.AfterFunc(timeout, func() {
		r.mu.Lock()
		if r.pending[key] == pp {
			delete(r.pending, key)
			r.expireLocked(pp)
		}
		r.mu.Unlock()
	})
	return pp
}

// get returns the pending entry for key, or nil.
func (r *pushRegistry) get(key pushKey) *pendingPush {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pending[key]
}

// claimFor returns an unclaimed pending push whose source IP matches the
// dial-back, or nil. It does not claim the entry: the caller offers the
// connection with offer, and the transfer claims it by taking it from
// connCh.
func (r *pushRegistry) claimFor(ip [4]byte) *pendingPush {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pp := range r.pending {
		if pp.srcIP == ip && !pp.closed {
			return pp
		}
	}
	return nil
}

// offer hands a dial-back connection to a pending push. It never blocks:
// a closed entry, or one that already holds a connection, closes the
// connection instead. The registry lock makes the check and the send
// atomic with respect to claim and expire, so a connection is never
// buffered behind a closed entry.
func (r *pushRegistry) offer(pp *pendingPush, c net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pp.closed {
		_ = c.Close()
		return
	}
	select {
	case pp.connCh <- c:
	default:
		_ = c.Close()
	}
}

// claim removes the pending entry because the transfer has taken its
// connection, and lapses it if it had not already. Any connection left
// in the channel (a second dial-back cannot be, but a race with the
// timer can leave one) is closed.
func (r *pushRegistry) claim(key pushKey, pp *pendingPush) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.pending[key] == pp {
		delete(r.pending, key)
	}
	r.expireLocked(pp)
}

// closeAll lapses every pending push, closing any unclaimed connection.
// Called on engine shutdown.
func (r *pushRegistry) closeAll() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, pp := range r.pending {
		r.expireLocked(pp)
	}
	r.pending = make(map[pushKey]*pendingPush)
}

// expireLocked lapses pp: closes its done channel, stops its timer and
// closes any connection it still holds. Must be called with r.mu held.
func (r *pushRegistry) expireLocked(pp *pendingPush) {
	if pp.closed {
		return
	}
	pp.closed = true
	if pp.timer != nil {
		pp.timer.Stop()
	}
	close(pp.done)
	for {
		select {
		case c := <-pp.connCh:
			_ = c.Close()
		default:
			return
		}
	}
}

// RequestPush writes a PUSH for one QUERYHIT hit back over the peer
// connection that delivered the QUERYHIT, and registers a pending push
// so the holder's dial-back can be claimed. The hit must carry a servent
// identifier: it is both the routing key and the servent the PUSH names.
//
// The pending entry is registered before the PUSH is written. A holder
// on a fast link can dial back before the write call returns, and an
// unregistered dial-back would be mistaken for an ordinary peer and sent
// through the 0.6 handshake.
func (e *Engine) RequestPush(qh QueryHit, hit FileHit) error {
	if !qh.HasServentID {
		return errors.New("gnutella: push: queryhit has no servent identifier")
	}
	e.mu.Lock()
	reg := e.pushes
	timeout := e.opts.PushClaimTimeout
	e.mu.Unlock()
	if reg == nil {
		return errors.New("gnutella: push: engine is not running")
	}

	pc := reg.route(qh.ServentID)
	if pc == nil {
		return ErrNoPushRoute
	}
	srcIP, ok := ipv4Of(pc.addr)
	if !ok {
		return fmt.Errorf("gnutella: push: peer %s is not IPv4", pc.addr)
	}
	ip, port := pushAcceptAddr(pc.conn.LocalAddr(), e.laddr)

	key := pushKey{id: qh.ServentID, index: hit.FileIndex}
	pp := reg.register(key, srcIP, timeout)

	push := Push{
		ServentID: qh.ServentID,
		FileIndex: hit.FileIndex,
		IP:        ip,
		Port:      port,
	}
	payload := EncodePush(push)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    pushTTL,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	buf := hdr.AppendTo(nil)
	buf = append(buf, payload...)

	pc.mu.Lock()
	err := pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
	if err == nil {
		_, err = pc.conn.Write(buf)
	}
	pc.mu.Unlock()
	if err != nil {
		reg.claim(key, pp)
		return fmt.Errorf("gnutella: push: %w", err)
	}
	return nil
}

// AwaitPush waits for the holder's dial-back connection for a push
// requested with RequestPush, and returns it for Downloader.FetchConn.
// It returns ErrNoPushPending if no push is registered for the hit, and
// ErrPushTimeout if the pending push's claim window lapses first.
func (e *Engine) AwaitPush(ctx context.Context, qh QueryHit, hit FileHit) (net.Conn, error) {
	e.mu.Lock()
	reg := e.pushes
	e.mu.Unlock()
	if reg == nil {
		return nil, errors.New("gnutella: push: engine is not running")
	}
	key := pushKey{id: qh.ServentID, index: hit.FileIndex}
	pp := reg.get(key)
	if pp == nil {
		return nil, ErrNoPushPending
	}
	select {
	case c := <-pp.connCh:
		reg.claim(key, pp)
		return c, nil
	case <-pp.done:
		return nil, ErrPushTimeout
	case <-ctx.Done():
		reg.claim(key, pp)
		return nil, ctx.Err()
	}
}

// pushAcceptAddr is the address a holder is told to connect back to: the
// local IPv4 address this link is reachable at, and the engine's listen
// port. A local address that is not IPv4 falls back to the listener's,
// so a loopback test listener still advertises a usable address.
func pushAcceptAddr(local, laddr net.Addr) ([4]byte, uint16) {
	var ip [4]byte
	if got, ok := ipv4Of(local); ok {
		ip = got
	} else if got, ok := ipv4Of(laddr); ok {
		ip = got
	}
	port := uint16(0)
	if ta, ok := laddr.(*net.TCPAddr); ok {
		port = uint16(ta.Port)
	}
	return ip, port
}

// ipv4Of extracts the big-endian IPv4 address of a net.Addr, rejecting
// unspecified and non-IPv4 addresses.
func ipv4Of(addr net.Addr) ([4]byte, bool) {
	var out [4]byte
	ta, ok := addr.(*net.TCPAddr)
	if !ok {
		if host, _, err := net.SplitHostPort(addr.String()); err == nil {
			ta = &net.TCPAddr{IP: net.ParseIP(host)}
		} else {
			return out, false
		}
	}
	ip4 := ta.IP.To4()
	if ip4 == nil || ta.IP.IsUnspecified() {
		return out, false
	}
	copy(out[:], ip4)
	return out, true
}
