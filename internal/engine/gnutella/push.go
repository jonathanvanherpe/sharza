// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// ServentID is a 16-byte Gnutella servent identifier.
type ServentID [idSize]byte

const (
	// pushPayloadSize is the fixed size of a PUSH payload: 16-byte
	// servent ID, 4-byte file index, 4-byte IPv4 address, 2-byte port.
	pushPayloadSize = 26

	// pushTTL is the TTL carried by an outbound PUSH.
	pushTTL byte = 7
)

// Push represents a Gnutella PUSH message (0x40).
type Push struct {
	// Target is the servent ID of the peer that should open the pushed
	// connection. ServentID is kept as an alias field for callers that
	// use the protocol's name.
	Target [idSize]byte
	ServentID [idSize]byte

	FileIndex uint32 // little-endian
	IP        [4]byte
	Port      uint16 // little-endian
}

// ErrPushBadFormat is returned when PUSH is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// ErrNoPushPath is returned when no push path is available.
var ErrNoPushPath = errors.New("gnutella: no push path")

// EncodePush encodes a Push to its fixed 26-byte wire representation.
func EncodePush(p Push) []byte {
	target := p.Target
	if target == ([idSize]byte{}) {
		target = p.ServentID
	}
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], target[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload. The fixed 26-byte prefix is
// consumed; any trailing bytes (e.g. GGEP) are ignored.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload too short", ErrPushBadFormat)
	}
	var p Push
	copy(p.Target[:], payload[0:16])
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushRegistry tracks live push paths (peer connections) through which a
// PUSH can be injected into the network.
type pushRegistry struct {
	mu    sync.Mutex
	peers map[*peer]struct{}
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{peers: make(map[*peer]struct{})}
}

// add registers a peer as a push path.
func (r *pushRegistry) add(p *peer) {
	if r == nil || p == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		r.peers = make(map[*peer]struct{})
	}
	r.peers[p] = struct{}{}
}

// remove unregisters a peer, guarded by identity: a peer that was never
// registered (or a different one) is a no-op.
func (r *pushRegistry) remove(p *peer, identity ...interface{}) {
	if r == nil || p == nil {
		return
	}
	if len(identity) > 0 {
		if identity[0] != p {
			return
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		return
	}
	delete(r.peers, p)
}

// send injects push through one of the registered paths. It returns
// ErrNoPushPath when no path is available.
func (r *pushRegistry) send(p Push) error {
	if r == nil {
		return ErrNoPushPath
	}
	r.mu.Lock()
	peers := make([]*peer, 0, len(r.peers))
	for pc := range r.peers {
		peers = append(peers, pc)
	}
	r.mu.Unlock()
	if len(peers) == 0 {
		return ErrNoPushPath
	}
	payload := EncodePush(p)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    pushTTL,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	buf := hdr.AppendTo(nil)
	buf = append(buf, payload...)
	sent := false
	for _, pc := range peers {
		if err := pc.write(buf); err == nil {
			sent = true
		} else {
			r.remove(pc)
		}
	}
	if !sent {
		return ErrNoPushPath
	}
	return nil
}
