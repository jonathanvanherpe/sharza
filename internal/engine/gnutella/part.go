// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Partial is the Gnutella2 PART completeness advertisement: the count of
// already-complete bytes of a file. It is carried as the payload of a G2
// packet whose type code is PART.
//
// Wire form: a big-endian count, written as a 4-byte DWORD when the
// value fits in 32 bits and an 8-byte QWORD otherwise. No other width
// is defined by the protocol.
type Partial struct {
	Complete uint64
}

// PART is the Gnutella2 type code for the partial-content tag.
const (
	PART                 = "PART"
	PartialType          = PART
	PartialTypeCode      = PART
	G2TypePartial        = PART
	G2PacketPartial      = PART
	PartialPacketType    = PART
	TypePartial          = PART
	PartialG2Type        = PART
)

// ErrPartialBadLength is returned when a PART payload is not exactly 4 or
// 8 bytes long.
var ErrPartialBadLength = errors.New("gnutella: malformed partial payload length")

// EncodePartial encodes p to its big-endian wire representation, using the
// 4-byte form when Complete fits in 32 bits and the 8-byte form otherwise.
func EncodePartial(p Partial) []byte {
	if p.Complete <= 0xFFFFFFFF {
		out := make([]byte, 4)
		binary.BigEndian.PutUint32(out, uint32(p.Complete))
		return out
	}
	out := make([]byte, 8)
	binary.BigEndian.PutUint64(out, p.Complete)
	return out
}

// DecodePartial decodes a big-endian PART payload. Only 4- and 8-byte
// payloads are accepted; any other length is rejected.
func DecodePartial(b []byte) (Partial, error) {
	switch len(b) {
	case 4:
		return Partial{Complete: uint64(binary.BigEndian.Uint32(b))}, nil
	case 8:
		return Partial{Complete: binary.BigEndian.Uint64(b)}, nil
	default:
		return Partial{}, fmt.Errorf("%w: got %d bytes", ErrPartialBadLength, len(b))
	}
}