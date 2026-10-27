// SPDX-License-Identifier: GPL-3.0-or-later

// Package gnutella implements the Gnutella 0.6 TCP handshake and the
// binary message framing (descriptor headers, PING/PONG liveness), plus
// the Gnutella2 tree-structured packet codec.
//
// The G2 codec here covers only the framing: a variable-width type tag,
// a compound flag, a big/little-endian length flag, and a payload. No
// packet-type constants or semantic decoders are defined in this slice;
// the type tag stays an opaque byte slice.
package gnutella

import (
	"errors"
	"fmt"
)

// G2Packet is one node in a Gnutella2 tree-structured packet.
type G2Packet struct {
	Type []byte
	TypeTag []byte
	Tag []byte

	Compound bool
	IsCompound bool

	BigEndian bool
	BigEndianLength bool

	Payload []byte
	Data []byte

	Children []G2Packet
}

func (p G2Packet) typeBytes() []byte {
	for _, c := range [][]byte{p.Type, p.TypeTag, p.Tag} {
		if c != nil {
			return c
		}
	}
	return nil
}

func (p G2Packet) compoundFlag() bool {
	return p.Compound || p.IsCompound
}

func (p G2Packet) bigEndianFlag() bool {
	return p.BigEndian || p.BigEndianLength
}

func (p G2Packet) payloadBytes() []byte {
	if p.Payload != nil {
		return p.Payload
	}
	return p.Data
}

func (p *G2Packet) setAliases() {
	if p.Type == nil {
		p.Type = p.TypeTag
	}
	if p.Type == nil {
		p.Type = p.Tag
	}
	if p.TypeTag == nil {
		p.TypeTag = p.Type
	}
	if p.Tag == nil {
		p.Tag = p.Type
	}
	if p.Compound {
		p.IsCompound = true
	}
	if p.IsCompound {
		p.Compound = true
	}
	if p.BigEndian {
		p.BigEndianLength = true
	}
	if p.BigEndianLength {
		p.BigEndian = true
	}
	if p.Payload == nil {
		p.Payload = p.Data
	}
	if p.Data == nil {
		p.Data = p.Payload
	}
}

func (p G2Packet) Encode() ([]byte, error) {
	typeTag := p.typeBytes()
	if len(typeTag) < 1 || len(typeTag) > 8 {
		return nil, fmt.Errorf("gnutella: g2 packet type tag must be 1-8 bytes, got %d", len(typeTag))
	}

	compound := p.compoundFlag()
	bigEndian := p.bigEndianFlag()

	var payload []byte
	if compound && len(p.Children) > 0 {
		var buf []byte
		for i := range p.Children {
			b, err := p.Children[i].Encode()
			if err != nil {
				return nil, err
			}
			buf = append(buf, b...)
		}
		payload = buf
	} else {
		payload = p.payloadBytes()
	}
	if payload == nil {
		payload = []byte{}
	}
	if len(payload) > 0xFFFFFF {
		return nil, errors.New("gnutella: g2 packet payload exceeds 0xFFFFFF")
	}

	nLenLen := 1
	if len(payload) > 0xFF {
		nLenLen = 2
	}
	if len(payload) > 0xFFFF {
		nLenLen = 3
	}

	first := byte((nLenLen << 6) | ((len(typeTag) - 1) << 3))
	if compound {
		first |= 0x04
	}
	if bigEndian {
		first |= 0x02
	}

	out := make([]byte, 0, 1+nLenLen+len(typeTag)+len(payload))
	out = append(out, first)
	if bigEndian {
		for i := nLenLen - 1; i >= 0; i-- {
			out = append(out, byte(len(payload)>>(8*i)))
		}
	} else {
		for i := 0; i < nLenLen; i++ {
			out = append(out, byte(len(payload)>>(8*i)))
		}
	}
	out = append(out, typeTag...)
	out = append(out, payload...)
	return out, nil
}

func DecodeG2Packet(b []byte) (G2Packet, []byte, error) {
	if len(b) == 0 {
		return G2Packet{}, b, errors.New("gnutella: truncated g2 packet: empty input")
	}

	first := b[0]
	nLenLen := int((first & 0xC0) >> 6)
	typeLen := int((first&0x38)>>3) + 1
	compound := first&0x04 != 0
	bigEndian := first&0x02 != 0

	if nLenLen < 1 || nLenLen > 3 {
		return G2Packet{}, b, fmt.Errorf("gnutella: invalid g2 length width %d", nLenLen)
	}
	if len(b) < 1+nLenLen+typeLen {
		return G2Packet{}, b, errors.New("gnutella: truncated g2 packet header")
	}

	off := 1
	length := 0
	if bigEndian {
		for i := 0; i < nLenLen; i++ {
			length = (length << 8) | int(b[off+i])
		}
	} else {
		for i := 0; i < nLenLen; i++ {
			length = length | (int(b[off+i]) << (8 * i))
		}
	}
	off += nLenLen

	if length > 0xFFFFFF {
		return G2Packet{}, b, errors.New("gnutella: g2 packet payload exceeds 0xFFFFFF")
	}
	if off+typeLen > len(b) {
		return G2Packet{}, b, errors.New("gnutella: truncated g2 packet type tag")
	}
	typeTag := append([]byte(nil), b[off:off+typeLen]...)
	off += typeLen

	if off+length > len(b) {
		return G2Packet{}, b, errors.New("gnutella: truncated g2 packet payload")
	}
	payload := append([]byte(nil), b[off:off+length]...)
	off += length

	trailing := b[off:]

	var children []G2Packet
	if compound {
		rem := payload
		for len(rem) > 0 {
			if rem[0] == 0 {
				rem = rem[1:]
				break
			}
			child, rest, err := DecodeG2Packet(rem)
			if err != nil {
				return G2Packet{}, b, err
			}
			children = append(children, child)
			rem = rest
		}
	}

	pkt := G2Packet{
		Type:            typeTag,
		TypeTag:         append([]byte(nil), typeTag...),
		Tag:             append([]byte(nil), typeTag...),
		Compound:        compound,
		IsCompound:      compound,
		BigEndian:       bigEndian,
		BigEndianLength: bigEndian,
		Payload:         payload,
		Data:            append([]byte(nil), payload...),
		Children:        children,
	}
	pkt.setAliases()
	return pkt, trailing, nil
}
