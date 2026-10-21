// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella PUSH descriptor (payload type 0x40). A requester cannot
// connect to a firewalled source, so it asks the source to connect back:
// the PUSH names the source's servent ID, the address and port the
// requester listens on, and the file index. The source that recognises
// its own servent ID dials that address and announces the transfer with
// a GIV line (see pushclient.go).
//
// The payload is 26 bytes, and the field byte orders follow the published
// spec: the servent ID is opaque, the IPv4 address is big-endian (as every
// IPv4 address in Gnutella is), and the port and file index are
// little-endian like every other multi-byte field.

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// pushPayloadSize is the fixed PUSH payload length.
const pushPayloadSize = 26

// ErrPushBadFormat is returned when a PUSH payload is not 26 bytes.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// Push is a PUSH descriptor payload.
type Push struct {
	// ServentID names the firewalled source that must dial back. It is
	// the servent ID the QUERYHIT carried.
	ServentID [idSize]byte

	// IP and Port name the address the requester listens on, where the
	// source must connect. IP is written big-endian, Port little-endian.
	IP   [4]byte
	Port uint16

	// FileIndex is the index of the file the requester wants, as the
	// QUERYHIT advertised it. Little-endian.
	FileIndex uint32
}

// EncodePush encodes a Push to its 26-byte wire representation.
func EncodePush(p Push) []byte {
	b := make([]byte, pushPayloadSize)
	copy(b[0:16], p.ServentID[:])
	copy(b[16:20], p.IP[:])
	binary.LittleEndian.PutUint16(b[20:22], p.Port)
	binary.LittleEndian.PutUint32(b[22:26], p.FileIndex)
	return b
}

// DecodePush decodes a PUSH payload. Anything but exactly 26 bytes is
// refused: a longer payload is not a PUSH this engine can read the same
// way, and silently ignoring trailing bytes would hide a broken peer.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) != pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload is %d bytes, want %d",
			ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	var p Push
	copy(p.ServentID[:], payload[0:16])
	copy(p.IP[:], payload[16:20])
	p.Port = binary.LittleEndian.Uint16(payload[20:22])
	p.FileIndex = binary.LittleEndian.Uint32(payload[22:26])
	return p, nil
}
