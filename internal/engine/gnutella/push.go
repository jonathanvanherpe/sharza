// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Requester-side PUSH (payload type 0x40), the firewalled-source leg of
// the Gnutella 0.6 spec (rfc-0_6-draft §2.2.8). When a QUERYHIT
// advertises a source that cannot be dialled directly, the servent
// that sent the hit is asked to push the file to us instead: we send
// one PUSH over the very connection the QUERYHIT arrived on, carrying
// the hit's trailing servent identifier, the hit's file index, and our
// own reachable address.
//
// Pushing back down the connection that delivered the hit is what makes
// the request routable without any new machinery: the receiving servent
// recognises its own client id and, if it is the origin, hands the file
// to the address in the payload; if it is not, it relays the PUSH toward
// the origin by the usual TTL-bounded routing. We only ever send; an
// inbound PUSH means somebody wants a file from us, and serving uploads
// does not exist yet (see docs/handoff.md).

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

const (
	// pushPayloadSize is the fixed PUSH payload: the 16-byte target
	// servent identifier, the 4-byte file index (little-endian), the
	// 4-byte requester IPv4 (big-endian, like every other address in
	// the protocol) and the 2-byte requester port (little-endian).
	// Bytes past it are an OPTIONAL GGEP block (§2.2.8); DecodePush
	// ignores them rather than refusing a payload it does not need.
	pushPayloadSize = 26

	// pushTTL is the TTL on a PUSH we originate. A PUSH is not
	// broadcast: it is routed back toward the QUERYHIT origin by
	// servent identifier, so the TTL only bounds how many relays may
	// serve that route. 7 is the conventional maximum the spec allows
	// (TTL+Hops between 1 and 7); Shareaza sends its maximum TTL minus
	// one for the same reason.
	pushTTL byte = 7
)

// ErrPushBadFormat is returned when a PUSH payload is shorter than the
// fixed 26 bytes.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// ErrNoPushPath is returned when a PUSH cannot be delivered because no
// live connection matches the address it must go down: the peer that
// sent the QUERYHIT has disconnected since, or the hit arrived before
// the connection was registered.
var ErrNoPushPath = errors.New("gnutella: no live connection to deliver push")

// Push is the decoded PUSH payload (§2.2.8).
type Push struct {
	// Target is the servent identifier the PUSH is addressed to. It
	// must equal the trailing 16 bytes of the QUERYHIT whose source
	// could not be dialled: that is how the receiving servent knows
	// the request is for it.
	Target [idSize]byte

	// FileIndex is the index of the file to push, taken from the
	// QUERYHIT, little-endian on the wire.
	FileIndex uint32

	// IP is the IPv4 address the requester wants the file sent to,
	// big-endian on the wire. This is our listen address, not the
	// address of the connection the PUSH goes out on.
	IP [4]byte

	// Port is the port the requester wants the file sent to,
	// little-endian on the wire.
	Port uint16
}

// EncodePush encodes p to its wire representation: the fixed 26-byte
// payload, no trailing GGEP (which is optional and we have nothing to
// put in it).
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:idSize], p.Target[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a PUSH payload. A payload shorter than the fixed
// fields cannot be decoded at all; anything longer carries an optional
// GGEP block that is not needed to act on the request and is skipped.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload %d bytes, want at least %d",
			ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	var p Push
	copy(p.Target[:], payload[0:idSize])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushRegistry maps the remote address of each live connection to the
// peer behind it, so a PUSH for a QUERYHIT can be written down the same
// connection the hit arrived on. The QUERYHIT records that connection
// only as a net.Addr (the wire format has no peer object), so the
// address is the join key: it is stable for the life of a TCP
// connection and changes when a peer reconnects, which is exactly when
// the old path stops being usable.
//
// Every method is nil-safe: an engine that never wired a registry (a
// caller that built Options by hand) simply has no push path rather
// than panicking on one.
type pushRegistry struct {
	mu     sync.Mutex
	byAddr map[string]*peer
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{byAddr: make(map[string]*peer)}
}

// add records p as the live connection at its remote address. It is
// called once the handshake has completed, before the message loop
// starts, so a hit can never reference a connection that is still
// negotiating.
func (r *pushRegistry) add(p *peer) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.byAddr[p.conn.RemoteAddr().String()] = p
	r.mu.Unlock()
}

// remove drops p from the registry. The identity check matters: when a
// peer reconnects from the same address the new connection registers
// itself, and the old connection's deferred remove must not delete the
// new registration just because the address matches.
func (r *pushRegistry) remove(p *peer) {
	if r == nil {
		return
	}
	addr := p.conn.RemoteAddr().String()
	r.mu.Lock()
	if r.byAddr[addr] == p {
		delete(r.byAddr, addr)
	}
	r.mu.Unlock()
}

// send writes one PUSH for target/fileIndex down the connection at via.
// It returns ErrNoPushPath when that connection is gone: the failure is
// reported to the caller (and logged) but never retried here, because a
// registry with no path has nothing to retry with.
func (r *pushRegistry) send(via net.Addr, target [idSize]byte, fileIndex uint32) error {
	if r == nil || via == nil {
		return ErrNoPushPath
	}
	r.mu.Lock()
	p := r.byAddr[via.String()]
	r.mu.Unlock()
	if p == nil {
		return fmt.Errorf("%w: %s", ErrNoPushPath, via)
	}
	return p.sendPush(target, fileIndex)
}

// sendPush writes one PUSH message for target/fileIndex. The requester
// address in the payload is this connection's local address (the same
// logic as PONG): it is the address the receiving servent will connect
// back to, so it must be the one we are reachable on, and a non-IPv4
// local address leaves it zero, which the receiving side will refuse to
// dial rather than dial wrongly.
//
// The message gets a fresh descriptor ID, not the QUERYHIT's: §2.2.8
// says a PUSH SHOULD carry a new ID, and duplicate detection on the
// receiving side is keyed on the message ID, so reusing the hit's ID
// would make a legitimate request look like a repeat.
func (p *peer) sendPush(target [idSize]byte, fileIndex uint32) error {
	push := Push{
		Target:    target,
		FileIndex: fileIndex,
		Port:      p.listenPort(),
	}
	if ta, ok := p.conn.LocalAddr().(*net.TCPAddr); ok {
		if ip4 := ta.IP.To4(); ip4 != nil {
			copy(push.IP[:], ip4)
		}
	}
	payload := EncodePush(push)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    pushTTL,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	p.logf("sending push to %s: target=%x index=%d -> %s:%d",
		p.conn.RemoteAddr(), target, fileIndex, net.IP(push.IP[:]), push.Port)
	return p.writeMessage(hdr, payload)
}
