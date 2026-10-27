// SPDX-License-Identifier: GPL-3.0-or-later

// Package gnutella implements the Gnutella 0.6 TCP handshake and the
// binary message framing (descriptor headers, PING/PONG liveness) plus
// the Gnutella2 tree-structured packet codec.
//
// G2Packet encodes a single node of the G2 tree packet format used by
// Shareaza and compatible peers. The format is a single leading control
// byte followed by a 1-3 byte length, a 1-8 byte type tag and the
// payload. Compound packets carry further packets in their payload.
package gnutella

import (
	"errors"
	"fmt"
)

// G2Packet is one node of a G2 tree-structured packet.
//
// Type is the opaque 1-8 byte type tag. Compound reports whether the
// payload is a sequence of child packets. BigEndian selects big-endian
// encoding for the length field (little-endian otherwise). Payload holds
// the raw payload bytes; for compound packets Children holds the
// decoded children and Payload is their concatenation.
type G2Packet struct {
	Type      []byte
	Compound  bool
	BigEndian bool
	Payload   []byte
	Children  []G2Packet
}

// Sentinel errors returned by the codec.
var (
	ErrG2Truncated = errors.New("gnutella: truncated G2 packet")
	ErrG2Malformed = errors.New("gnutella: malformed G2 packet")
)

// Encode serialises p into the Shareaza G2 wire format.
func (p G2Packet) Encode() ([]byte, error) {
	if len(p.Type) < 1 || len(p.Type) > 8 {
		return nil, fmt.Errorf("%w: type tag length %d, want 1..8", ErrG2Malformed, len(p.Type))
	}

	var payload []byte
	if p.Compound {
		for i := range p.Children {
			b, err := p.Children[i].Encode()
			if err != nil {
				return nil, err
			}
			payload = append(payload, b...)
		}
	} else {
		payload = p.Payload
	}

	if len(payload) > 0xFFFFFF {
		return nil, fmt.Errorf("%w: payload length %d exceeds 0xFFFFFF", ErrG2Malformed, len(payload))
	}

	// Minimal length encoding: 1 byte up to 255, 2 up to 65535, 3 beyond.
	nLenLen := 1
	if len(payload) > 0xFF {
		nLenLen = 2
		if len(payload) > 0xFFFF {
			nLenLen = 3
		}
	}

	first := byte(nLenLen<<6) | byte((len(p.Type)-1)<<3)
	if p.Compound {
		first |= 0x04
	}
	if p.BigEndian {
		first |= 0x02
	}

	out := make([]byte, 0, 1+nLenLen+len(p.Type)+len(payload))
	out = append(out, first)
	if p.BigEndian {
		for i := nLenLen - 1; i >= 0; i-- {
			out = append(out, byte(len(payload)>>uint(8*i)))
		}
	} else {
		for i := 0; i < nLenLen; i++ {
			out = append(out, byte(len(payload)>>uint(8*i)))
		}
	}
	out = append(out, p.Type...)
	out = append(out, payload...)
	return out, nil
}

// DecodeG2Packet parses one packet from b and returns the packet, the
// unconsumed trailing bytes, and any error.
func DecodeG2Packet(b []byte) (G2Packet, []byte, error) {
	if len(b) == 0 {
		return G2Packet{}, nil, ErrG2Truncated
	}
	first := b[0]
	nLenLen := int((first & 0xC0) >> 6)
	typeLen := int((first&0x38)>>3) + 1
	compound := first&0x04 != 0
	bigEndian := first&0x02 != 0

	if nLenLen < 1 || nLenLen > 3 {
		return G2Packet{}, nil, fmt.Errorf("%w: length width %d, want 1..3", ErrG2Malformed, nLenLen)
	}

	off := 1
	if off+nLenLen+typeLen > len(b) {
		return G2Packet{}, nil, ErrG2Truncated
	}

	var payloadLen int
	if bigEndian {
		for i := 0; i < nLenLen; i++ {
			payloadLen = (payloadLen << 8) | int(b[off+i])
		}
	} else {
		for i := 0; i < nLenLen; i++ {
			payloadLen |= int(b[off+i]) << uint(8*i)
		}
	}
	off += nLenLen
	if payloadLen > 0xFFFFFF {
		return G2Packet{}, nil, fmt.Errorf("%w: payload length %d exceeds 0xFFFFFF", ErrG2Malformed, payloadLen)
	}

	typeTag := make([]byte, typeLen)
	copy(typeTag, b[off:off+typeLen])
	off += typeLen

	if off+payloadLen > len(b) {
		return G2Packet{}, nil, ErrG2Truncated
	}
	payload := make([]byte, payloadLen)
	copy(payload, b[off:off+payloadLen])
	off += payloadLen

	pkt := G2Packet{
		Type:      typeTag,
		Compound:  compound,
		BigEndian: bigEndian,
		Payload:   payload,
	}
	if compound {
		children, err := decodeG2Children(payload)
		if err != nil {
			return G2Packet{}, nil, err
		}
		pkt.Children = children
	}
	return pkt, b[off:], nil
}

// decodeG2Children parses a compound payload into its child packets.
func decodeG2Children(payload []byte) ([]G2Packet, error) {
	var children []G2Packet
	i := 0
	for i < len(payload) {
		if payload[i] == 0 {
			// Terminator; stop parsing.
			break
		}
		child, rest, err := DecodeG2Packet(payload[i:])
		if err != nil {
			return nil, err
		}
		consumed := len(payload[i:]) - len(rest)
		if consumed == 0 {
			return nil, ErrG2Truncated
		}
		children = append(children, child)
		i += consumed
	}
	return children, nil
}
