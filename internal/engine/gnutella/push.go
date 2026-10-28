// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Push represents a Gnutella PUSH message (0x40). It asks a firewalled
// servent to initiate an HTTP upload to the requester identified by the
// servent ID, file index, IP address and port.
//
// Wire layout (26 bytes, fixed): 16-byte servent ID, 4-byte file index
// (little-endian), 4-byte IPv4 address (big-endian/network order), and
// 2-byte port (little-endian).
type Push struct {
	ServentID [16]byte
	FileIndex uint32
	IPAddress [4]byte
	Port      uint16
}

// pushPayloadSize is the fixed PUSH payload length.
const pushPayloadSize = 26

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// EncodePush encodes a Push to its wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IPAddress[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) != pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload length %d, want %d", ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	var p Push
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IPAddress[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}