// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrNoPushPath is returned when a PUSH cannot be sent because the
// connection that delivered the corresponding QUERYHIT is gone (or was
// never registered). Requester-side PUSH needs a live path back to the
// peer that advertised the file; without one there is nothing to ask.
var ErrNoPushPath = errors.New("gnutella: no push path to peer")

// pushPayloadSize is the fixed PUSH payload: 16-byte target servent ID,
// 4-byte file index (LE), 4-byte IP (BE), 2-byte port (LE). Trailing
// GGEP extensions, if any, are ignored on decode.
const pushPayloadSize = 26

// Push is a Gnutella PUSH message (0x40): a request to the peer that
// advertised a file to open a connection back to the requester and
// serve it. ServentID names the target peer (the one that answered the
// QUERY), FileIndex the advertised file, and IP/Port where the target
// should connect to push the file.
type Push struct {
	ServentID [idSize]byte
	FileIndex uint32
	IP        [4]byte
	Port      uint16
}

// EncodePush encodes a Push to its 26-byte wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload. The payload must be at least
// pushPayloadSize bytes; any trailing bytes (GGEP extensions) are
// ignored.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("gnutella: malformed push: payload too short")
	}
	p := Push{}
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushRegistry maps a connection's remote address to the *peer that owns
// it, so a PUSH can be sent back down the link that delivered the
// QUERYHIT. It is nil-safe.
type pushRegistry struct {
	mu    sync.Mutex
	conns map[string]*peer
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{conns: make(map[string]*peer)}
}

// pushKey returns a stable string key for an address.
func pushKey(addr net.Addr) string {
	if addr == nil {
		return ""
	}
	return addr.String()
}

// add registers p under addr. A nil registry or nil peer is a no-op.
func (r *pushRegistry) add(addr net.Addr, p *peer) {
	if r == nil || p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.conns[pushKey(addr)] = p
}

// remove unregisters p under addr, but only if the currently registered
// peer is p itself. This identity check keeps a reconnect from clobbering
// (or being clobbered by) the registration of a newer connection.
func (r *pushRegistry) remove(addr net.Addr, p *peer) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if cur, ok := r.conns[pushKey(addr)]; ok && cur == p {
		delete(r.conns, pushKey(addr))
	}
}

// send writes a PUSH down the connection registered under addr. It
// returns ErrNoPushPath when no live peer is registered there.
func (r *pushRegistry) send(addr net.Addr, push Push) error {
	if r == nil {
		return ErrNoPushPath
	}
	r.mu.Lock()
	p := r.conns[pushKey(addr)]
	r.mu.Unlock()
	if p == nil {
		return ErrNoPushPath
	}
	return p.sendPush(push)
}

// sendPush writes a PUSH message down this peer's connection.
func (p *peer) sendPush(push Push) error {
	payload := EncodePush(push)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    1,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	return p.writeMessage(hdr, payload)
}
