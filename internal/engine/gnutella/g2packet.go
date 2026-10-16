// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella2 tree packet codec: how one packet is framed on the
// wire, how a compound packet's children are framed inside its payload,
// and nothing else. No socket, no hub topology, no KHL semantics and no
// query handling; this file turns a G2Packet tree into bytes and back.
//
// The wire format is Shareaza's, read as the byte-level oracle in
// CG2Packet::ToBuffer, ::New(BYTE*), ::WritePacket, ::ReadPacket,
// ::SkipCompound and ::ReadBuffer (G2Packet.cpp), and read as the
// documented format in the published specification at
// g2.doxu.org/wiki/Packet_Structure. The two agree:
//
//	control (1 byte) | length (0..3 bytes) | type (1..8 bytes) | children and/or payload
//
// The control byte is | Len_Len<<6 | (Name_Len-1)<<3 | CF | BE |:
//
//	Len_Len		2 bits, the length field's byte count (0..3)
//	Name_Len-1	3 bits, the type name's byte count minus one (0..7)
//	CF	0x04	the compound flag: children follow the header
//	BE	0x02	big-endian: the length field is big-endian
//	--	0x01	reserved, never set by Shareaza
//
// A zero control byte is not a packet: it is the end-of-packet-stream
// marker, which is what terminates a compound packet's child list.
//
// Decisions this file makes where the sources leave a choice, each one
// recorded because a later slice will stand on it:
//
//   - The encoder writes Shareaza's length-of-length, which is never
//     zero: a zero-length packet gets a one-byte zero length field
//     ("48 00 50 49" for /PI). The specification prefers omitting the
//     length field entirely (Len_Len 0) for zero-length marker packets,
//     and the decoder accepts that; re-encoding normalises it to
//     Shareaza's form, which is what every live G2 peer emits.
//
//   - A packet's own BE bit governs its own length field. The
//     specification says the length is in the byte order of the root
//     packet, and Shareaza's WritePacket stamps the parent's BE bit into
//     every child's control byte, so in any conformant tree the two are
//     the same thing. Honouring the packet's own bit is what keeps
//     EncodeG2Packet context-free: encoding a child on its own and
//     encoding it inside its parent produce the same bytes, and a tree
//     whose flags disagree is preserved exactly rather than silently
//     reinterpreted.
//
//   - The encoder emits the zero control byte that ends a child list
//     only when a payload actually follows it ("children and/or
//     payload": a terminator with nothing after it is, per the
//     specification, "valid, but unnecessary"). Decode therefore
//     accepts three forms the encoder never emits and normalises each on
//     re-encode: Len_Len 0, a trailing child-stream terminator, and the
//     reserved control bit. Each has a test.
//
//   - AppendTo panics on a packet that cannot be represented: an
//     invalid type name, children on a packet without the compound flag,
//     or a body over the 0xFFFFFF the 3-byte length field can hold.
//     Those are programming errors, and Shareaza treats them as
//     assertions too (WritePacket ASSERTs the type length and the
//     length bound). A packet that came out of DecodeG2Packet always
//     encodes: decode rejects everything encode would refuse.

import (
	"bytes"
	"errors"
	"fmt"
)

// G2Type is a Gnutella2 packet type name: the wire bytes of a packet's
// name field, in wire order. Type names are 1 to 8 bytes, case
// sensitive, and may not contain a null byte (specification,
// "Namespace Considerations"); len(t) is therefore the name length the
// control byte encodes as Name_Len-1.
type G2Type string

// Packet type names this engine knows. Names are the wire bytes, so
// G2TypePing is "PI", not "PING": Shareaza's G2_PACKET_PING is
// MAKE_G2_PACKET('P','I',0,0,0,0,0,0) (G2Packet.h:130) and the
// specification documents the packet as /PI.
const (
	G2TypePing         G2Type = "PI"
	G2TypePong         G2Type = "PO"
	G2TypeKHL          G2Type = "KHL"  // known hub list
	G2TypeKHLRequest   G2Type = "KHLR" // known hub list request (ukhl:)
	G2TypeKHLAnswer    G2Type = "KHLA" // known hub list answer
	G2TypeNeighbourHub G2Type = "NH"   // one hub entry of a KHL
	G2TypeHubStatus    G2Type = "HS"   // leaf count and leaf limit
	G2TypeCachedHub    G2Type = "CH"   // one cached hub of a KHL
	G2TypeVendor       G2Type = "V"    // four-character vendor code
	G2TypeTimestamp    G2Type = "TS"
	G2TypeTo           G2Type = "TO" // recipient GUID of a routed packet
)

const (
	// g2FlagCompound marks a packet whose payload begins with a
	// sequence of framed child packets.
	g2FlagCompound = 0x04

	// g2FlagBigEndian marks a packet whose length field is
	// big-endian. Everything else multi-byte follows the flag too,
	// but that is payload semantics, not framing.
	g2FlagBigEndian = 0x02

	// g2FlagReserved is the third control bit. The specification
	// reserves it, Shareaza never sets it, and we neither set it nor
	// keep it: decode accepts it for interoperability with whatever
	// might, and re-encoding drops it.
	g2FlagReserved = 0x01

	// g2MaxTypeLen is the type name length the 3 name-length bits
	// allow (Name_Len-1 is 0..7).
	g2MaxTypeLen = 8

	// g2MaxPayloadLen is the largest body the 3-byte length field
	// can express. Shareaza ASSERTs the same bound in WritePacket.
	g2MaxPayloadLen = 0xFFFFFF

	// g2MaxDepth bounds nesting when decoding. Every level costs a
	// stack frame, and a hostile 64 kB stream of compound packets
	// each wrapping one child would otherwise nest tens of thousands
	// deep. Real G2 trees are shallow: a KHL is two levels (KHL,
	// NH, HS), and the deepest query structure is a handful.
	g2MaxDepth = 64
)

// Decode/encode failures. They are wrapped with detail where useful.
var (
	// ErrG2Empty is returned when there is nothing to decode.
	ErrG2Empty = errors.New("gnutella: empty g2 input")

	// ErrG2EndOfStream is returned when the input begins with a zero
	// control byte. That byte is the packet stream terminator, not a
	// packet; a compound child list ends on it, a single-packet
	// decode refuses it.
	ErrG2EndOfStream = errors.New("gnutella: zero g2 control byte marks the end of a packet stream")

	// ErrG2Truncated is returned when the header, the length field,
	// the type name or the body runs past the end of the input.
	ErrG2Truncated = errors.New("gnutella: truncated g2 packet")

	// ErrG2BadType is returned for a type name a packet may not
	// carry: empty, longer than 8 bytes, or containing a null byte.
	ErrG2BadType = errors.New("gnutella: invalid g2 type name")

	// ErrG2Depth is returned when a compound packet nests deeper
	// than g2MaxDepth.
	ErrG2Depth = errors.New("gnutella: g2 packet tree nested too deeply")

	// ErrG2Oversized is returned (as a panic) when a packet's body
	// is larger than the 3-byte length field can carry.
	ErrG2Oversized = errors.New("gnutella: g2 packet body exceeds maximum")

	// ErrG2ChildrenWithoutCompound is returned (as a panic) when a
	// packet carries children without the compound flag. Encoding it
	// would silently drop them.
	ErrG2ChildrenWithoutCompound = errors.New("gnutella: g2 packet has children but the compound flag is clear")
)

// G2Packet is one Gnutella2 tree packet. A packet has a type name, a
// body that is either opaque payload, framed children, or children
// followed by a zero control byte and then payload, and the two framing
// flags.
//
// A decoded packet never aliases the input: every payload it retains is
// copied.
type G2Packet struct {
	// Type is the packet's name, 1 to 8 bytes.
	Type G2Type

	// Compound reports whether Payload begins with framed children.
	// It is read from the wire even on a zero-length packet, where
	// the specification says it is ignored.
	Compound bool

	// BigEndian reports whether this packet's length field is
	// big-endian. See the file comment for why it is the packet's
	// own flag and not the root's.
	BigEndian bool

	// Payload is the packet's payload: opaque bytes when Compound
	// is false, and when Compound is true whatever followed the
	// child stream. It is nil when there is none.
	Payload []byte

	// Children are the framed child packets of a compound packet,
	// nil when there are none.
	Children []*G2Packet
}

// EncodeG2Packet returns p's wire encoding. It panics if p cannot be
// represented; see AppendTo.
func EncodeG2Packet(p *G2Packet) []byte {
	return p.AppendTo(nil)
}

// AppendTo appends p's wire encoding to dst and returns the extended
// slice. The encoding is Shareaza's ToBuffer, byte for byte.
//
// It panics if p cannot be represented on the wire: an invalid type
// name, children without the compound flag, or a body larger than
// 0xFFFFFF. Those are programming errors, not data errors -- a packet
// that came out of DecodeG2Packet always encodes.
func (p *G2Packet) AppendTo(dst []byte) []byte {
	if err := p.check(); err != nil {
		panic(err)
	}

	body := p.body()
	if len(body) > g2MaxPayloadLen {
		panic(fmt.Errorf("%w: %q carries %d bytes", ErrG2Oversized, string(p.Type), len(body)))
	}

	// Shareaza never writes a zero length-of-length: ToBuffer starts
	// at 1 and grows it, so a zero-length packet still carries a
	// zero length byte.
	lenLen := 1
	switch {
	case len(body) > 0xFFFF:
		lenLen = 3
	case len(body) > 0xFF:
		lenLen = 2
	}

	control := byte(lenLen<<6) | byte((len(p.Type)-1)<<3)
	if p.Compound {
		control |= g2FlagCompound
	}
	if p.BigEndian {
		control |= g2FlagBigEndian
	}
	dst = append(dst, control)

	if p.BigEndian {
		for i := lenLen - 1; i >= 0; i-- {
			dst = append(dst, byte(uint(len(body))>>uint(8*i)))
		}
	} else {
		for i := 0; i < lenLen; i++ {
			dst = append(dst, byte(uint(len(body))>>uint(8*i)))
		}
	}

	dst = append(dst, p.Type...)
	return append(dst, body...)
}

// body is p's payload as it goes on the wire. For a compound packet it
// is the children's encodings, and, if a payload follows them, the zero
// control byte that ends the child stream and then the payload --
// exactly how Shareaza's CreateKHLPacket builds an NH entry
// (G2Neighbour.cpp:856-908): children, one 0x00, then the address.
//
// The terminator is written whenever a compound packet has payload, and
// not only when it has children too: without it a childless compound
// payload that happens to look like a framed packet would decode as
// children, so the terminator is what makes the encoding round-trip.
func (p *G2Packet) body() []byte {
	if !p.Compound {
		return p.Payload
	}
	var body []byte
	for _, child := range p.Children {
		body = child.AppendTo(body)
	}
	if len(p.Payload) > 0 {
		body = append(body, 0x00)
		body = append(body, p.Payload...)
	}
	return body
}

// check reports whether p can be represented on the wire at all.
func (p *G2Packet) check() error {
	if len(p.Type) == 0 || len(p.Type) > g2MaxTypeLen {
		return fmt.Errorf("%w: %q has %d bytes, want 1..%d",
			ErrG2BadType, string(p.Type), len(p.Type), g2MaxTypeLen)
	}
	for i := 0; i < len(p.Type); i++ {
		if p.Type[i] == 0 {
			return fmt.Errorf("%w: %q contains a null byte", ErrG2BadType, string(p.Type))
		}
	}
	if !p.Compound && len(p.Children) > 0 {
		return fmt.Errorf("%w: %q", ErrG2ChildrenWithoutCompound, string(p.Type))
	}
	return nil
}

// DecodeG2Packet decodes one packet from the front of b and returns it
// with the number of bytes it consumed. Trailing bytes are not an
// error: they are the next packet in a stream, and the caller decides.
//
// The packet is decoded exactly as Shareaza's ReadBuffer accepts one: a
// zero control byte is ErrG2EndOfStream (it ends a stream, it is not a
// packet), a body that runs past the end of b is ErrG2Truncated, and a
// compound packet's children must parse, because the specification
// says the compound bit "MUST be checked when decoding every packet".
func DecodeG2Packet(b []byte) (*G2Packet, int, error) {
	p, n, err := decodeG2Packet(b, 0)
	if err != nil {
		return nil, 0, err
	}
	return p, n, nil
}

// decodeG2Packet is the recursive worker. depth is the nesting level of
// this packet, counted from the root.
func decodeG2Packet(b []byte, depth int) (*G2Packet, int, error) {
	if depth >= g2MaxDepth {
		return nil, 0, fmt.Errorf("%w: %d levels", ErrG2Depth, depth)
	}
	if len(b) == 0 {
		return nil, 0, ErrG2Empty
	}

	control := b[0]
	if control == 0 {
		return nil, 0, ErrG2EndOfStream
	}

	lenLen := int(control&0xC0) >> 6
	typeLen := int(control&0x38)>>3 + 1
	compound := control&g2FlagCompound != 0
	bigEndian := control&g2FlagBigEndian != 0

	// The header needs the length field and the type name, both of
	// which follow the control byte.
	off := 1
	if lenLen+typeLen > len(b)-off {
		return nil, 0, fmt.Errorf("%w: control byte 0x%02x needs %d length and %d type bytes, %d remain",
			ErrG2Truncated, control, lenLen, typeLen, len(b)-off)
	}

	length := uint32(0)
	if bigEndian {
		for i := 0; i < lenLen; i++ {
			length = length<<8 | uint32(b[off+i])
		}
	} else {
		for i := lenLen - 1; i >= 0; i-- {
			length = length<<8 | uint32(b[off+i])
		}
	}
	off += lenLen

	typ := G2Type(b[off : off+typeLen])
	off += typeLen
	for i := 0; i < len(typ); i++ {
		if typ[i] == 0 {
			return nil, 0, fmt.Errorf("%w: %q contains a null byte", ErrG2BadType, string(typ))
		}
	}

	if length > uint32(len(b)-off) {
		return nil, 0, fmt.Errorf("%w: %q declares %d body bytes, %d remain",
			ErrG2Truncated, string(typ), length, len(b)-off)
	}
	body := b[off : off+int(length)]
	off += int(length)

	p := &G2Packet{Type: typ, Compound: compound, BigEndian: bigEndian}
	if compound {
		children, rest, err := decodeG2Children(body, depth)
		if err != nil {
			return nil, 0, fmt.Errorf("gnutella: g2 %q child list: %w", string(typ), err)
		}
		p.Children = children
		if len(rest) > 0 {
			p.Payload = bytes.Clone(rest)
		}
	} else if len(body) > 0 {
		// Not compound: the body is opaque payload, whatever it
		// looks like. A payload that starts with a plausible
		// control byte is not children unless CF says so.
		p.Payload = bytes.Clone(body)
	}
	return p, off, nil
}

// DecodeG2Children parses body, the payload of a compound packet, and
// returns its child packets and whatever followed the child stream. It
// is the reader form of a compound payload: the same walk as Shareaza's
// SkipCompound, which stops at a zero control byte (consumed) or at
// the end of the payload, leaving the rest for the caller to read as
// the packet's payload.
func DecodeG2Children(body []byte) ([]*G2Packet, []byte, error) {
	children, rest, err := decodeG2Children(body, 0)
	if err != nil {
		return nil, nil, err
	}
	if len(rest) == 0 {
		return children, nil, nil
	}
	return children, bytes.Clone(rest), nil
}

func decodeG2Children(body []byte, depth int) ([]*G2Packet, []byte, error) {
	var children []*G2Packet
	off := 0
	for off < len(body) {
		if body[off] == 0 {
			// End of the child stream. The terminator is
			// consumed; the payload, if any, follows it.
			off++
			break
		}
		child, n, err := decodeG2Packet(body[off:], depth+1)
		if err != nil {
			return nil, nil, fmt.Errorf("child %d: %w", len(children), err)
		}
		children = append(children, child)
		off += n
	}
	return children, body[off:], nil
}
