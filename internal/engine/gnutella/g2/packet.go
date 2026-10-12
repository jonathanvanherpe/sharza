// SPDX-License-Identifier: GPL-3.0-or-later

// Package g2 implements the Gnutella2 tree packet codec: the framing every
// other G2 item is built on.
//
// The wire format is the control-byte framing of the published Gnutella2
// specification (g2.doxu.org, "Packet Structure"), cross-checked against
// Shareaza's G2Packet.cpp, the reference implementation. Each packet is:
//
//	control byte | length field | name | body
//
// The control byte packs the width of the length field (two bits), the width
// of the name minus one (three bits) and flag bits. The compound flag (0x04)
// marks a packet whose body begins with child packets; the big-endian flag
// (0x02) selects big-endian for the packet's length field. A leaf without the
// compound flag has the whole body as its payload. A compound packet's child
// list may be followed by a zero control byte and then a payload; the child
// bytes and the terminator count toward the parent's declared length.
//
// The task brief for this item described "hashed 4-char type codes" and a
// parent flag in the high bit of a big-endian 32-bit length, with 4-byte
// aligned children. None of that is in the specification or the reference:
// names are 1 to 8 raw bytes, the flags live in the control byte, and children
// are packed with no alignment. The published format is implemented here;
// docs/handoff.md records the deviation, as it did for the Gnutella 1
// handshake brief.
package g2

import (
	"errors"
	"fmt"
)

const (
	// MaxNameLen is the longest packet name the format can encode. The name
	// length field in the control byte is three bits, so names are 1 to 8
	// bytes inclusive and there is no unnamed packet.
	MaxNameLen = 8

	// MaxPacketSize is the largest body the length field can encode. The
	// length width is two bits, so a length field is at most three bytes and
	// the largest value is 0xFFFFFF.
	MaxPacketSize = 0xFFFFFF

	// maxLenLen is the widest length field the control byte can encode.
	maxLenLen = 3

	// Control-byte flag bits. The low three bits are reserved for flags; the
	// remaining bit (0x01) is reserved and ignored, as Shareaza ignores it.
	flagCompound  = 0x04
	flagBigEndian = 0x02
)

// Sentinel errors. Parse wraps them with %w, so callers can test with
// errors.Is.
var (
	// ErrZeroControl reports a zero control byte where a packet was
	// expected. Zero is the end-of-stream marker and never starts a packet.
	ErrZeroControl = errors.New("g2: zero control byte")

	// ErrTruncated reports input that ends before the packet it declares:
	// a header, a length field or a body shorter than the control byte
	// promised.
	ErrTruncated = errors.New("g2: truncated packet")

	// ErrTooLong reports a body larger than MaxPacketSize. Parse cannot hit
	// this (a three-byte length field tops out at MaxPacketSize); Marshal can,
	// for a packet assembled in memory.
	ErrTooLong = errors.New("g2: packet body exceeds maximum size")

	// ErrTrailingData reports input that continues past the declared packet.
	ErrTrailingData = errors.New("g2: trailing data after packet")

	// ErrBadAlignment reports a compound packet whose children do not tile its
	// declared body: a child overruns the body, or nonzero bytes remain that
	// cannot start a child.
	ErrBadAlignment = errors.New("g2: compound children do not fill the packet body")

	// ErrBadName reports a packet name that is not 1 to MaxNameLen bytes.
	ErrBadName = errors.New("g2: packet name must be 1 to 8 bytes")
)

// Packet is one node of a Gnutella2 packet tree.
//
// Type is the 1-to-8-byte packet name. Compound reports the control byte's
// compound flag; a compound packet carries Child packets at the start of its
// body. BigEndian reports the control byte's big-endian flag for this
// packet's own length field. Payload is the bytes after any children and the
// zero terminator that separates them. Children is empty for a leaf.
type Packet struct {
	Type      string
	Compound  bool
	BigEndian bool
	Payload   []byte
	Children  []*Packet
}

// Parse decodes exactly one packet from b. Bytes after the packet are rejected
// with ErrTrailingData, because this is a single-packet codec: a caller that
// streams several packets must split the stream first, using the byte count
// Parse wins back through ParseFrom.
//
// Parse never panics and never reads outside b. Malformed input is rejected
// with ErrZeroControl, ErrTruncated, ErrTooLong, ErrTrailingData or
// ErrBadAlignment.
func Parse(b []byte) (*Packet, error) {
	p, n, err := ParseFrom(b)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, fmt.Errorf("%w: %d bytes after a %d-byte packet", ErrTrailingData, len(b)-n, n)
	}
	return p, nil
}

// ParseFrom decodes one packet from the start of b and returns the number of
// bytes it consumed. Unlike Parse it tolerates trailing bytes, which is what a
// stream reader needs to advance to the next packet.
func ParseFrom(b []byte) (*Packet, int, error) {
	return parse(b)
}

// Marshal encodes p as a single packet. The body length is recomputed from the
// children and payload, and the length field is written in the minimum width
// that holds it, with at least one byte so the control byte is never zero.
func (p *Packet) Marshal() ([]byte, error) {
	return p.appendTo(nil)
}

// appendTo appends the wire encoding of p to dst.
func (p *Packet) appendTo(dst []byte) ([]byte, error) {
	if len(p.Type) < 1 || len(p.Type) > MaxNameLen {
		return nil, fmt.Errorf("%w: %d bytes", ErrBadName, len(p.Type))
	}

	var body []byte
	if p.Compound {
		var err error
		for _, c := range p.Children {
			if c == nil {
				return nil, fmt.Errorf("%w: nil child of %q", ErrBadAlignment, p.Type)
			}
			if body, err = c.appendTo(body); err != nil {
				return nil, err
			}
		}
		if len(p.Payload) > 0 {
			// The zero control byte separates the child list from a payload.
			body = append(body, 0x00)
			body = append(body, p.Payload...)
		}
	} else {
		if len(p.Children) > 0 {
			return nil, fmt.Errorf("%w: leaf %q has %d children", ErrBadAlignment, p.Type, len(p.Children))
		}
		body = p.Payload
	}

	if len(body) > MaxPacketSize {
		return nil, fmt.Errorf("%w: body is %d bytes", ErrTooLong, len(body))
	}

	var flags byte
	if p.Compound {
		flags |= flagCompound
	}
	if p.BigEndian {
		flags |= flagBigEndian
	}
	width := lengthWidth(uint32(len(body)))
	ctrl := byte(width<<6) | byte((len(p.Type)-1)<<3) | flags

	dst = append(dst, ctrl)
	dst = appendLength(dst, uint32(len(body)), width, p.BigEndian)
	dst = append(dst, p.Type...)
	dst = append(dst, body...)
	return dst, nil
}

// String returns a one-line description for logs and test failures.
func (p *Packet) String() string {
	if p == nil {
		return "<nil g2 packet>"
	}
	return fmt.Sprintf("%q{compound=%t be=%t payload=%d children=%d}",
		p.Type, p.Compound, p.BigEndian, len(p.Payload), len(p.Children))
}

// parse decodes one packet from b and returns the bytes consumed. The caller
// owns the exact-consumption policy: Parse rejects trailing bytes, a compound
// parent bounds its children by slicing.
func parse(b []byte) (*Packet, int, error) {
	if len(b) < 1 {
		return nil, 0, ErrTruncated
	}
	ctrl := b[0]
	if ctrl == 0 {
		return nil, 0, ErrZeroControl
	}

	lenLen := int(ctrl>>6) & 0x03
	nameLen := int(ctrl>>3)&0x07 + 1
	compound := ctrl&flagCompound != 0
	bigEndian := ctrl&flagBigEndian != 0

	header := 1 + lenLen + nameLen
	if len(b) < header {
		return nil, 0, fmt.Errorf("%w: header needs %d bytes of %d", ErrTruncated, header, len(b))
	}

	length, err := decodeLength(b[1:1+lenLen], bigEndian)
	if err != nil {
		return nil, 0, err
	}
	if length > MaxPacketSize {
		return nil, 0, fmt.Errorf("%w: declared length %d", ErrTooLong, length)
	}

	total := header + int(length)
	if len(b) < total {
		return nil, 0, fmt.Errorf("%w: body needs %d bytes of %d", ErrTruncated, length, len(b)-header)
	}

	p := &Packet{
		Type:      string(b[1+lenLen : header]),
		Compound:  compound,
		BigEndian: bigEndian,
	}
	body := b[header:total]
	if compound {
		children, payload, err := parseChildren(body)
		if err != nil {
			return nil, 0, err
		}
		p.Children = children
		p.Payload = payload
	} else {
		p.Payload = cloneBytes(body)
	}
	return p, total, nil
}

// parseChildren decodes the child list that starts a compound packet's body.
// Children are packed with no alignment; a zero control byte ends the list and
// the bytes after it are the parent's payload. Any other leftover bytes that
// cannot form a child are a framing error.
func parseChildren(body []byte) ([]*Packet, []byte, error) {
	if len(body) == 0 {
		return nil, nil, nil
	}
	var children []*Packet
	pos := 0
	for pos < len(body) {
		if body[pos] == 0 {
			return children, cloneBytes(body[pos+1:]), nil
		}
		child, n, err := parse(body[pos:])
		if err != nil {
			// The parent's declared length already fixed how many bytes its
			// body owns, so a child that will not fit is a misalignment, not
			// a truncated packet.
			return nil, nil, fmt.Errorf("%w: child at offset %d: %v", ErrBadAlignment, pos, err)
		}
		if n < 1 || pos+n > len(body) {
			return nil, nil, fmt.Errorf("%w: child at offset %d overruns body", ErrBadAlignment, pos)
		}
		children = append(children, child)
		pos += n
	}
	// The children tiled the body exactly, so there is no payload.
	return children, nil, nil
}

// lengthWidth returns the number of bytes Marshal needs for a body of n bytes.
// It is never zero: Shareaza always writes at least one length byte, and doing
// the same keeps a zero-length packet's control byte nonzero.
func lengthWidth(n uint32) int {
	switch {
	case n <= 0xFF:
		return 1
	case n <= 0xFFFF:
		return 2
	default:
		return 3
	}
}

// appendLength appends an n-byte length field to dst in the requested byte
// order. width is 0 to maxLenLen; width 0 writes nothing.
func appendLength(dst []byte, n uint32, width int, bigEndian bool) []byte {
	var tmp [maxLenLen]byte
	if bigEndian {
		for i := width - 1; i >= 0; i-- {
			tmp[i] = byte(n)
			n >>= 8
		}
	} else {
		for i := 0; i < width; i++ {
			tmp[i] = byte(n)
			n >>= 8
		}
	}
	return append(dst, tmp[:width]...)
}

// decodeLength decodes a length field of len(b) bytes in the requested byte
// order. A zero-width field is a zero length.
func decodeLength(b []byte, bigEndian bool) (uint32, error) {
	switch len(b) {
	case 0:
		return 0, nil
	case 1:
		return uint32(b[0]), nil
	case 2:
		if bigEndian {
			return uint32(b[0])<<8 | uint32(b[1]), nil
		}
		return uint32(b[1])<<8 | uint32(b[0]), nil
	case 3:
		if bigEndian {
			return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
		}
		return uint32(b[2])<<16 | uint32(b[1])<<8 | uint32(b[0]), nil
	default:
		return 0, fmt.Errorf("g2: length field width %d out of range", len(b))
	}
}

// cloneBytes returns a copy of b, or nil for an empty slice, so a parsed tree
// never aliases the caller's buffer.
func cloneBytes(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return append([]byte(nil), b...)
}
