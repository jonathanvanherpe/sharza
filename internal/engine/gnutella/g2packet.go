// SPDX-License-Identifier: GPL-3.0-or-later

// Package gnutella implements the Gnutella 0.6 TCP handshake and the
// binary message framing (descriptor headers, PING/PONG liveness) plus
// the Gnutella2 tree-structured packet codec.
//
// G2Packet is the Gnutella2 tree packet: a variable-length type code
// (1..8 bytes), a 1/2/3-byte payload length, a flags byte carrying the
// compound and big-endian bits, and a payload that is either raw bytes
// (leaf) or a sequence of nested child packets (compound). The format
// follows Shareaza's CG2Packet (G2Packet.h/.cpp): the top two bits of the
// first byte give the length width (1/2/3), the next three bits give the
// type-code length minus one, and the low three bits are flags
// (0x04 = compound, 0x02 = big-endian).
package gnutella

import (
	"errors"
	"fmt"
	"io"
)

const (
	// MaxG2TypeLen is the maximum length of a G2 type code in bytes.
	MaxG2TypeLen = 8
	// MaxG2Length is the maximum payload length representable by the
	// 3-byte length field.
	MaxG2Length = 0xFFFFFF
)

// ErrG2Truncated is returned when input ends before a complete packet.
var ErrG2Truncated = errors.New("gnutella: truncated G2 packet")

// ErrG2BadLengthWidth is returned when the length-width field is zero.
var ErrG2BadLengthWidth = errors.New("gnutella: invalid G2 length width")

// ErrG2BadTypeLen is returned when the type-code length field is invalid.
var ErrG2BadTypeLen = errors.New("gnutella: invalid G2 type code length")

// ErrG2LengthTooLarge is returned when a payload length exceeds the
// 3-byte maximum.
var ErrG2LengthTooLarge = errors.New("gnutella: G2 payload length too large")

// ErrG2Trailing is returned when trailing bytes follow a top-level packet.
var ErrG2Trailing = errors.New("gnutella: trailing bytes after G2 packet")

// ErrG2BadCompound is returned when a compound payload does not parse
// cleanly into child packets.
var ErrG2BadCompound = errors.New("gnutella: malformed compound G2 payload")

// G2Packet is a Gnutella2 tree-structured packet. Type is the
// variable-length type code (1..8 bytes, stored as a string so the
// trailing NUL padding of the on-wire QWORD is not part of it on the
// Go side? No: the exact bytes are preserved, including any NULs, so
// round-tripping is exact). Compound marks a payload that contains
// nested child packets; BigEndian selects big-endian length encoding.
// Payload holds the raw body of a leaf packet; Children holds the parsed
// children of a compound packet.
type G2Packet struct {
	Type      string
	Compound  bool
	BigEndian bool
	Payload   []byte
	Children  []*G2Packet
}

// cloneBytes returns a copy of b.
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// typeBytes returns the type code as bytes.
func (p *G2Packet) typeBytes() []byte {
	return []byte(p.Type)
}

// encodeG2Packet encodes a single packet to bytes.
func encodeG2Packet(p *G2Packet) ([]byte, error) {
	if p == nil {
		return nil, errors.New("gnutella: nil G2 packet")
	}
	tb := []byte(p.Type)
	if len(tb) == 0 || len(tb) > MaxG2TypeLen {
		return nil, fmt.Errorf("gnutella: G2 type code length %d out of range", len(tb))
	}
	compound := p.Compound || len(p.Children) > 0

	// Build body: children first, then any trailing payload.
	var body []byte
	if len(p.Children) > 0 {
		for _, c := range p.Children {
			cb, err := encodeG2Packet(c)
			if err != nil {
				return nil, err
			}
			body = append(body, cb...)
		}
	}
	body = append(body, p.Payload...)

	if len(body) > MaxG2Length {
		return nil, fmt.Errorf("gnutella: G2 payload length %d exceeds maximum", len(body))
	}

	nLenLen := 1
	if len(body) > 0xFF {
		nLenLen++
		if len(body) > 0xFFFF {
			nLenLen++
		}
	}
	nTypeLen := len(tb) - 1

	flags := byte(0)
	if compound {
		flags |= 0x04
	}
	if p.BigEndian {
		flags |= 0x02
	}

	out := make([]byte, 0, 1+nLenLen+len(tb)+len(body))
	out = append(out, byte(nLenLen<<6)|byte(nTypeLen<<3)|flags)

	if p.BigEndian {
		for i := nLenLen - 1; i >= 0; i-- {
			out = append(out, byte((len(body)>>uint(i*8))&0xFF))
		}
	} else {
		for i := 0; i < nLenLen; i++ {
			out = append(out, byte((len(body)>>uint(i*8))&0xFF))
		}
	}
	out = append(out, tb...)
	out = append(out, body...)
	return out, nil
}

// decodeG2Packet decodes one packet from data, returning the packet and
// the number of bytes consumed.
func decodeG2Packet(data []byte) (*G2Packet, int, error) {
	if len(data) == 0 {
		return nil, 0, ErrG2Truncated
	}
	first := data[0]
	if first == 0 {
		return nil, 0, errors.New("gnutella: zero G2 packet header")
	}
	nLenLen := int((first & 0xC0) >> 6)
	if nLenLen == 0 || nLenLen > 3 {
		return nil, 0, ErrG2BadLengthWidth
	}
	nTypeLen := int((first & 0x38) >> 3)
	typeLen := nTypeLen + 1
	if typeLen < 1 || typeLen > MaxG2TypeLen {
		return nil, 0, ErrG2BadTypeLen
	}
	compound := first&0x04 != 0
	bigEndian := first&0x02 != 0

	if len(data) < 1+nLenLen+typeLen {
		return nil, 0, ErrG2Truncated
	}
	var length uint32
	if bigEndian {
		for i := 0; i < nLenLen; i++ {
			length = length<<8 | uint32(data[1+i])
		}
	} else {
		for i := 0; i < nLenLen; i++ {
			length |= uint32(data[1+i]) << uint(i*8)
		}
	}
	if length > MaxG2Length {
		return nil, 0, ErrG2LengthTooLarge
	}
	typeStart := 1 + nLenLen
	typeEnd := typeStart + typeLen
	total := typeEnd + int(length)
	if len(data) < total {
		return nil, 0, ErrG2Truncated
	}

	pkt := &G2Packet{
		Type:      string(data[typeStart:typeEnd]),
		Compound:  compound,
		BigEndian: bigEndian,
	}

	payload := data[typeEnd:total]

	if compound {
		// Parse children.
		off := 0
		for off < len(payload) {
			child, n, err := decodeG2Packet(payload[off:])
			if err != nil {
				return nil, 0, fmt.Errorf("%w: %v", ErrG2BadCompound, err)
			}
			if n <= 0 {
				return nil, 0, ErrG2BadCompound
			}
			pkt.Children = append(pkt.Children, child)
			off += n
		}
		pkt.Payload = nil
	} else {
		pkt.Payload = cloneBytes(payload)
	}

	return pkt, total, nil
}

// EncodeG2Packet encodes p (or *p) to bytes.
func EncodeG2Packet(v any) ([]byte, error) {
	switch x := v.(type) {
	case *G2Packet:
		if x == nil {
			return nil, errors.New("gnutella: nil G2 packet")
		}
		return encodeG2Packet(x)
	case G2Packet:
		cp := x
		return encodeG2Packet(&cp)
	default:
		return nil, fmt.Errorf("gnutella: unsupported G2 packet value %T", v)
	}
}

// DecodeG2Packet decodes one packet from data (bytes, string, or
// io.Reader). Trailing bytes are rejected.
func DecodeG2Packet(v any) (*G2Packet, error) {
	var data []byte
	switch x := v.(type) {
	case []byte:
		data = x
	case string:
		data = []byte(x)
	case io.Reader:
		b, err := io.ReadAll(x)
		if err != nil {
			return nil, err
		}
		data = b
	default:
		return nil, fmt.Errorf("gnutella: unsupported G2 input %T", v)
	}
	pkt, n, err := decodeG2Packet(data)
	if err != nil {
		return nil, err
	}
	if n != len(data) {
		return nil, ErrG2Trailing
	}
	return pkt, nil
}

// DecodeG2PacketAt decodes one packet starting at off within data,
// returning the packet, bytes consumed, and error.
func DecodeG2PacketAt(data []byte, off int) (*G2Packet, int, error) {
	if off < 0 || off > len(data) {
		return nil, 0, ErrG2Truncated
	}
	pkt, n, err := decodeG2Packet(data[off:])
	if err != nil {
		return nil, 0, err
	}
	return pkt, n, nil
}

// Encode is a method convenience.
func (p *G2Packet) Encode() ([]byte, error) {
	return EncodeG2Packet(p)
}

// DecodeInto decodes data into p.
func (p *G2Packet) DecodeInto(data []byte) error {
	got, err := DecodeG2Packet(data)
	if err != nil {
		return err
	}
	*p = *got
	return nil
}


