// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
)

const pushPayloadSize = 26

// ErrPushBadFormat is returned when a PUSH message is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// Push represents a Gnutella PUSH message (0x40).
// Wire format: 16-byte Servent ID (GUID), 4-byte File Index (LE),
// 4-byte IP Address (BE), 2-byte Port (LE).
type Push struct {
	ServentID  [16]byte
	FileIndex  uint32
	RequesterIP [4]byte
	Port       uint16
}

// EncodePush encodes a Push to its wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.RequesterIP[:]) // BE
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) != pushPayloadSize {
		return Push{}, ErrPushBadFormat
	}
	var p Push
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.RequesterIP[:], payload[20:24]) // BE
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}
