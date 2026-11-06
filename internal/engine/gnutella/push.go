// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// pushPayloadSize is the fixed size of a Gnutella PUSH payload before
// any optional GGEP extension: 16-byte servent ID, 4-byte file index,
// 4-byte IPv4 address, 2-byte port.
const pushPayloadSize = 26

// Push represents a Gnutella PUSH message (0x40).
// Payload: 16-byte servent ID, 4-byte file index (LE), 4-byte IPv4
// address (network order), 2-byte port (LE). Optional GGEP extensions
// may follow and are ignored by this codec.
type Push struct {
	ServentID [16]byte
	FileIndex uint32 // little-endian
	IP        [4]byte // network order (big-endian)
	Port      uint16  // little-endian
}

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// EncodePush encodes a Push to its wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload too short", ErrPushBadFormat)
	}
	p := Push{}
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}
