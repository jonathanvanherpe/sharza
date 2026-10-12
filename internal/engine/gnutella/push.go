// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella PUSH message (0x40), and the registry that recognises
// the dial-back it asks for.
//
// A servent behind a firewall cannot accept the download GET a QUERYHIT
// advertises, so the requester asks it to connect out instead: PUSH
// carries the servent GUID the request is for, the file index to serve,
// and the requester's own address (its dial-back target). The published
// 0.6 draft lays the payload out as a 16-byte GUID, a 4-byte file index
// (little-endian), a 4-byte IPv4 address and a 2-byte port
// (little-endian). Shareaza's CG1Packet::OnPush refuses anything shorter
// than 26 bytes, and 16+4+4+2 is exactly 26.
//
// The task brief said "reject payloads under 22 bytes". That is 16+4+2:
// it omits the 4-byte address and cannot describe a valid PUSH, so the
// published minimum is implemented instead, exactly as the handshake
// item followed the published values over the brief's. See
// docs/handoff.md.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
	"time"
)

// pushPayloadSize is the fixed PUSH payload length: 16-byte GUID,
// 4-byte file index (LE), 4-byte IPv4 (BE), 2-byte port (LE).
const pushPayloadSize = 26

// pushPendingTTL bounds how long a source address stays registered as
// awaiting a dial-back. A source behind NAT either connects back
// promptly or the push is lost; without a bound the registry would grow
// for the daemon's lifetime, since a push that is never answered never
// clears its own entry.
const pushPendingTTL = 60 * time.Second

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// Push is a Gnutella PUSH message (0x40). GUID names the servent the
// request is for, FileIndex the file it should serve, and IP/Port the
// dial-back target the requester can be reached at.
type Push struct {
	GUID      [16]byte
	FileIndex uint32  // little-endian
	IP        [4]byte // big-endian
	Port      uint16  // little-endian
}

// EncodePush encodes a Push to its fixed 26-byte wire representation.
// The address is written big-endian like every other IPv4 field.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.GUID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload. A payload shorter than the
// fixed 26 bytes is refused; the spec has no variable-length PUSH, and
// the bytes after the address (a GGEP trailer) are ignored here.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload too short", ErrPushBadFormat)
	}
	var p Push
	copy(p.GUID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pendingPushes remembers the source addresses a PUSH was sent to, so
// an inbound connection from one is logged as the expected dial-back
// rather than an unexplained peer.
type pendingPushes struct {
	mu      sync.Mutex
	entries map[string]time.Time
}

func newPendingPushes() *pendingPushes {
	return &pendingPushes{entries: make(map[string]time.Time)}
}

// add registers ip as awaiting a dial-back, pruning any entries that
// have outlived pushPendingTTL so the map stays bounded.
func (p *pendingPushes) add(ip string) {
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	for k, t := range p.entries {
		if now.Sub(t) > pushPendingTTL {
			delete(p.entries, k)
		}
	}
	p.entries[ip] = now
}

// take reports whether ip is a live pending dial-back, removing it on a
// hit: one push produces at most one recognised connection, so a later
// unrelated peer from the same address is not mislabelled.
func (p *pendingPushes) take(ip string) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	t, ok := p.entries[ip]
	if !ok {
		return false
	}
	delete(p.entries, ip)
	return time.Since(t) <= pushPendingTTL
}
