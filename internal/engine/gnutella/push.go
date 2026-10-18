// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Push represents a Gnutella 0.6 PUSH message (0x40).
// Payload (26 bytes): GUID (16) | IPv4 (4, big-endian) | port (2, little-endian) | file index (4, little-endian).
type Push struct {
	GUID      [idSize]byte
	IPAddress [4]byte
	Port      uint16 // little-endian
	FileIndex uint32 // little-endian
}

// pushPayloadSize is the size of the base PUSH payload (26 bytes).
const pushPayloadSize = 26

var ErrPushBadFormat = errors.New("gnutella: malformed push")

// EncodePush encodes a Push to its wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.GUID[:])
	copy(out[16:20], p.IPAddress[:])
	binary.LittleEndian.PutUint16(out[20:22], p.Port)
	binary.LittleEndian.PutUint32(out[22:26], p.FileIndex)
	return out
}

// DecodePush decodes a Push from payload.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload too short", ErrPushBadFormat)
	}
	var p Push
	copy(p.GUID[:], payload[0:16])
	copy(p.IPAddress[:], payload[16:20])
	p.Port = binary.LittleEndian.Uint16(payload[20:22])
	p.FileIndex = binary.LittleEndian.Uint32(payload[22:26])
	return p, nil
}
