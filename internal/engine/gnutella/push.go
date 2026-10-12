// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella 1 PUSH message (0x40): the mechanism a firewalled
// servent is fetched through. A QUERYHIT whose source cannot accept
// incoming connections (an unspecified IP or a zero port) is answered
// by sending the servent that produced it a PUSH naming the file and
// the address to push to; the firewalled servent then opens a TCP
// connection to that address, and the file moves over it with a plain
// HTTP GET, exactly like a direct download.
//
// The payload is fixed at 26 bytes before the optional GGEP extension
// block, per the 0.6 draft (section 2.2.8): a 16-byte servent
// identifier (the value the corresponding QUERYHIT carried in its own
// last 16 bytes), a 4-byte little-endian file index, a 4-byte
// big-endian IPv4 address and a 2-byte little-endian port. This engine
// neither emits nor parses the optional GGEP block; the fixed part is
// what any 0.6 peer answers.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// pushPayloadSize is the fixed length of a PUSH payload: 16-byte
// servent identifier, 4-byte file index, 4-byte IPv4 address and
// 2-byte port. A GGEP extension block may follow, which this engine
// does not use.
const pushPayloadSize = 26

// pushClaimTimeout bounds how long an accepted dial-back may sit
// unclaimed. A connection nobody is waiting for is not a dial-back: it
// is an unsolicited connect to the push-accept port, and holding it
// open would let a scanner pin the accept loop.
const pushClaimTimeout = 2 * time.Second

// pushRouteTable maps the 0.6 servent identifiers heard in QUERYHITs
// to the peer connection that delivered each hit. A PUSH for that
// servent is sent back over the same connection: the 0.6 draft routes
// PUSH by servent identifier, and the connection that brought the
// QUERYHIT is the only one that can forward it toward the servent.
// The mapped peer may be gone by the time a push is asked for; the
// write then fails and the caller sees the error.
type pushRouteTable struct {
	mu sync.Mutex
	m  map[[idSize]byte]*peer
}

func newPushRouteTable() *pushRouteTable {
	return &pushRouteTable{m: make(map[[idSize]byte]*peer)}
}

// store records or replaces the route for a servent identifier. The
// latest connection wins: a servent heard through two peers should be
// pushed through the one we heard last.
func (t *pushRouteTable) store(id [idSize]byte, p *peer) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.m[id] = p
}

// lookup returns the peer to push a servent identifier through.
func (t *pushRouteTable) lookup(id [idSize]byte) (*peer, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	p, ok := t.m[id]
	return p, ok
}

// Push is a Gnutella PUSH message payload (0x40). ServentID names the
// servent asked to push (the value from the corresponding QUERYHIT),
// FileIndex the file on that servent, and IP and Port the address the
// push should connect back to (ours).
type Push struct {
	ServentID [idSize]byte
	FileIndex uint32 // little-endian
	IP        [4]byte
	Port      uint16 // little-endian
}

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// EncodePush encodes a Push to its 26-byte wire representation.
func EncodePush(p Push) []byte {
	b := make([]byte, pushPayloadSize)
	copy(b[0:idSize], p.ServentID[:])
	binary.LittleEndian.PutUint32(b[idSize:idSize+4], p.FileIndex)
	copy(b[idSize+4:idSize+8], p.IP[:])
	binary.LittleEndian.PutUint16(b[idSize+8:], p.Port)
	return b
}

// DecodePush decodes a PUSH payload. Only the fixed 26-byte part is
// read; a trailing GGEP extension block is ignored, and a payload
// shorter than pushPayloadSize is rejected.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload %d bytes, want at least %d",
			ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	var p Push
	copy(p.ServentID[:], payload[0:idSize])
	p.FileIndex = binary.LittleEndian.Uint32(payload[idSize : idSize+4])
	copy(p.IP[:], payload[idSize+4:idSize+8])
	p.Port = binary.LittleEndian.Uint16(payload[idSize+8 : pushPayloadSize])
	return p, nil
}