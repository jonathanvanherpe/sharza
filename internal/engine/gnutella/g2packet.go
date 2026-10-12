// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Gnutella2 tree packets. The G2 wire format is a small tree: every
// packet has a one-byte header, an optional length field, a type name
// of one to eight ASCII characters, then its payload. A packet marked
// compound carries a concatenation of sub-packets in the same format
// instead of opaque bytes.
//
// This is the framing the KHL host-cache exchange needs, not a general
// G2 stack. It is written from the published format at g2.doxu.org and
// Shareaza's G2Packet.{h,cpp}; no Shareaza code is copied.
//
// The header byte, most significant bits first:
//
//	bits 7-6  length-field size, 1..3 bytes (the wire field is never 0)
//	bits 5-3  type-name length minus one, so a name is 1..8 characters
//	bit  2    compound: the payload is a concatenation of sub-packets
//	bit  1    big-endian: the length field and multi-byte fields are BE
//
// Shareaza writes a little-endian packet and treats a set big-endian
// bit as "swap these bytes", so a decoder must honour it per packet,
// including for the length field itself.

import (
	"errors"
	"fmt"
)

// g2Type is a G2 packet type name: one to eight ASCII characters.
type g2Type string

// The G2 types this client speaks. KHLR is the one-packet request a
// "ukhl:" endpoint is asked; KHLA is its answer. KHL is the same list
// delivered over a connected G2 session. NH (neighbour hub) and CH
// (cached hub) are the entries inside them, NA (node address), HS (hub
// status), V (vendor) and TS (timestamp) are their fields.
const (
	g2TypeKHL  g2Type = "KHL"
	g2TypeKHLA g2Type = "KHLA"
	g2TypeKHLR g2Type = "KHLR"
	g2TypeNH   g2Type = "NH"
	g2TypeCH   g2Type = "CH"
	g2TypeNA   g2Type = "NA"
	g2TypeHS   g2Type = "HS"
	g2TypeV    g2Type = "V"
	g2TypeTS   g2Type = "TS"
	g2TypeYOU  g2Type = "YOU"
)

const (
	g2FlagCompound  = 0x04
	g2FlagBigEndian = 0x02

	// g2MaxTypeLen is the longest type name the three-bit field holds.
	g2MaxTypeLen = 8

	// g2MaxPayload is the largest payload a three-byte length field can
	// describe (2^24-1).
	g2MaxPayload = 0xFFFFFF
)

// ErrG2Packet reports a byte string that is not a well-formed G2 packet.
var ErrG2Packet = errors.New("gnutella: malformed g2 packet")

// g2Packet is one decoded G2 tree packet. For a compound packet,
// Children are the whole sub-packets and Tail is the payload after the
// last one: some writers (Shareaza's KHLA builder among them) follow
// their sub-packets with a bare address, and only the tail can recover
// it without guessing. For a leaf, Data is the payload.
type g2Packet struct {
	Type     g2Type
	Compound bool
	Data     []byte
	Children []*g2Packet
	Tail     []byte
}

// child returns the first sub-packet of the given type, or nil.
func (p *g2Packet) child(t g2Type) *g2Packet {
	for _, c := range p.Children {
		if c.Type == t {
			return c
		}
	}
	return nil
}

// appendTo appends p's encoding to dst and returns the extended slice.
func (p *g2Packet) appendTo(dst []byte) []byte {
	var payload []byte
	if p.Compound {
		for _, c := range p.Children {
			payload = c.appendTo(payload)
		}
	} else {
		payload = p.Data
	}

	typeLen := len(p.Type)
	if typeLen < 1 {
		typeLen = 1 // an unnamed packet cannot be framed; use a NUL name
	}
	if typeLen > g2MaxTypeLen {
		typeLen = g2MaxTypeLen
	}
	lenLen := 1
	if len(payload) > 0xFF {
		lenLen = 2
		if len(payload) > 0xFFFF {
			lenLen = 3
		}
	}

	b0 := byte(lenLen<<6) | byte((typeLen-1)<<3)
	if p.Compound {
		b0 |= g2FlagCompound
	}
	dst = append(dst, b0)
	n := len(payload)
	for i := 0; i < lenLen; i++ {
		dst = append(dst, byte(n>>(8*i)))
	}
	typ := p.Type
	if len(typ) > typeLen {
		typ = typ[:typeLen]
	}
	dst = append(dst, typ...)
	return append(dst, payload...)
}

// marshal returns the wire encoding of p, without any datagram header.
func (p *g2Packet) marshal() []byte {
	return p.appendTo(nil)
}

// decodeG2Packet decodes the first packet in data, returning it and the
// number of bytes it consumed. A truncated packet is an error; a
// compound packet stops at the first byte that does not begin a whole
// sub-packet, leaving the remainder in Raw.
func decodeG2Packet(data []byte) (*g2Packet, int, error) {
	if len(data) < 1 {
		return nil, 0, fmt.Errorf("%w: empty", ErrG2Packet)
	}
	b0 := data[0]
	lenLen := int(b0>>6) & 0x03
	typeLen := int(b0>>3)&0x07 + 1
	flags := b0 & 0x07
	header := 1 + lenLen + typeLen
	if len(data) < header {
		return nil, 0, fmt.Errorf("%w: header needs %d bytes, have %d", ErrG2Packet, header, len(data))
	}

	var n int
	if flags&g2FlagBigEndian != 0 {
		for i := 0; i < lenLen; i++ {
			n = n<<8 | int(data[1+i])
		}
	} else {
		for i := 0; i < lenLen; i++ {
			n |= int(data[1+i]) << (8 * i)
		}
	}
	if n > g2MaxPayload {
		return nil, 0, fmt.Errorf("%w: payload length %d out of range", ErrG2Packet, n)
	}
	if len(data) < header+n {
		return nil, 0, fmt.Errorf("%w: payload needs %d bytes, have %d", ErrG2Packet, n, len(data)-header)
	}

	p := &g2Packet{
		Type:     g2Type(data[1+lenLen : header]),
		Compound: flags&g2FlagCompound != 0,
	}
	payload := data[header : header+n]
	if p.Compound {
		pos := 0
		for pos < len(payload) {
			if payload[pos] == 0 {
				break // Shareaza treats a zero byte as end of sub-packets
			}
			c, m, err := decodeG2Packet(payload[pos:])
			if err != nil || m <= 0 {
				break // remainder is not a sub-packet; keep it in Tail
			}
			p.Children = append(p.Children, c)
			pos += m
		}
		p.Tail = payload[pos:]
	} else {
		p.Data = payload
	}
	return p, header + n, nil
}
