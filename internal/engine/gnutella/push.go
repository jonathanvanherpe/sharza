// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrNoPushPath is returned by pushRegistry.send when no connection is
// registered for the requested delivery path.
var ErrNoPushPath = errors.New("gnutella: no push path")

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// Push is a Gnutella PUSH message (payload type 0x40). It asks the peer
// that owns ServentID to open a connection back to IP:Port and serve the
// file named by FileIndex.
type Push struct {
	ServentID [idSize]byte
	FileIndex uint32
	IP        [4]byte
	Port      uint16
}

// EncodePush encodes a Push to its 26-byte wire representation. Trailing
// GGEP data is not produced; a receiver must tolerate it on decode.
func EncodePush(p Push) []byte {
	out := make([]byte, 26)
	copy(out[0:16], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload. The fixed 26-byte prefix is
// required; any trailing bytes (GGEP) are ignored.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < 26 {
		return Push{}, fmt.Errorf("%w: payload too short", ErrPushBadFormat)
	}
	p := Push{}
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushRegistry tracks live peer connections that can be used as push
// delivery paths, keyed by the remote address of the connection. add
// and remove are identity-guarded: a connection is only removed when
// the pointer being removed is the one currently registered under that
// address, so a stale connection cannot evict a newer one.
type pushRegistry struct {
	mu    sync.Mutex
	conns map[net.Addr]*peer
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{conns: make(map[net.Addr]*peer)}
}

// add registers p as the push path for its remote address. It returns
// true when the registration took effect.
func (r *pushRegistry) add(p *peer) bool {
	if r == nil || p == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	addr := p.conn.RemoteAddr()
	if cur, ok := r.conns[addr]; ok && cur != p {
		return false
	}
	r.conns[addr] = p
	return true
}

// remove unregisters p, but only if it is still the connection
// registered under its address.
func (r *pushRegistry) remove(p *peer) bool {
	if r == nil || p == nil {
		return false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	addr := p.conn.RemoteAddr()
	if cur, ok := r.conns[addr]; ok && cur == p {
		delete(r.conns, addr)
		return true
	}
	return false
}

// send delivers push down the connection registered for via. It returns
// ErrNoPushPath when no such connection exists.
func (r *pushRegistry) send(via net.Addr, push Push) error {
	if r == nil {
		return ErrNoPushPath
	}
	r.mu.Lock()
	p := r.conns[via]
	r.mu.Unlock()
	if p == nil {
		return ErrNoPushPath
	}
	return p.sendPush(push)
}

// sendPush writes a PUSH message on this connection, taking the same
// write lock as every other write on it.
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