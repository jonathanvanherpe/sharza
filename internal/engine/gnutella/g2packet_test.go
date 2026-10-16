// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"errors"
	"reflect"
	"strings"
	"testing"
)

// g2GUID returns a fresh 16-byte GUID for a /TO payload.
func g2GUID() []byte {
	return []byte{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
		0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x00,
	}
}

// g2KHLWire is the wire form of g2KHLTree, derived byte for byte from
// Shareaza's CG2Neighbour::CreateKHLPacket (G2Neighbour.cpp:854-926),
// taking the no-vendor, IPv4 branch for one neighbour and appending the
// timestamp:
//
//	54 1b 4b 48 4c                          /KHL, compound, 27 body bytes
//	  4c 0f 4e 48                           /NH, compound, 15 body bytes
//	    48 04 48 53 00 2a 01 00             /HS leaf count 42, leaf limit 256 (big-endian)
//	    00                                  child-stream terminator
//	    01 02 03 04 18 ca                   1.2.3.4:6346 (IPv4 little-endian, port big-endian)
//	  48 04 54 53 65 3f 2e 00               /TS 1708957184 (big-endian)
//
// The NH entry is the interesting one: children, then the 0x00 that ends
// the child stream, then six bytes of address payload -- the shape the
// qualifier `if (nLength > nAddressInfoLength) pPacket->WriteByte(0)`
// exists to produce.
var g2KHLWire = []byte{
	0x54, 0x1b, 0x4b, 0x48, 0x4c,
	0x4c, 0x0f, 0x4e, 0x48,
	0x48, 0x04, 0x48, 0x53, 0x00, 0x2a, 0x01, 0x00,
	0x00,
	0x01, 0x02, 0x03, 0x04, 0x18, 0xca,
	0x48, 0x04, 0x54, 0x53, 0x65, 0x3f, 0x2e, 0x00,
}

// g2KHLTree is the G2Packet tree g2KHLWire encodes.
func g2KHLTree() *G2Packet {
	return &G2Packet{
		Type:     G2TypeKHL,
		Compound: true,
		Children: []*G2Packet{
			{
				Type:     G2TypeNeighbourHub,
				Compound: true,
				Children: []*G2Packet{
					{Type: G2TypeHubStatus, Payload: []byte{0x00, 0x2a, 0x01, 0x00}},
				},
				// The no-vendor branch writes an explicit zero
				// byte after the children; that is the child-stream
				// terminator, so the payload is the address alone.
				Payload: []byte{0x01, 0x02, 0x03, 0x04, 0x18, 0xca},
			},
			{Type: G2TypeTimestamp, Payload: []byte{0x65, 0x3f, 0x2e, 0x00}},
		},
	}
}

// The byte-exact vectors: encode must produce exactly these bytes, decode
// must reproduce the tree, and re-encoding must reproduce the bytes.
func TestG2WireVectors(t *testing.T) {
	tests := []struct {
		name string
		pkt  *G2Packet
		wire []byte
	}{
		{
			// Shareaza's G2_PACKET_PING is MAKE_G2_PACKET('P','I',
			// 0,0,0,0,0,0) (G2Packet.h:130) and the specification
			// documents /PI, so the type is two bytes, not four.
			// ToBuffer: typeLen-1=1, length 0, no flags.
			name: "ping",
			pkt:  &G2Packet{Type: G2TypePing},
			wire: []byte{0x48, 0x00, 0x50, 0x49},
		},
		{
			name: "pong",
			pkt:  &G2Packet{Type: G2TypePong},
			wire: []byte{0x48, 0x00, 0x50, 0x4f},
		},
		{
			// The /TO header is pinned by Shareaza's GetTo,
			// which tests the child's raw bytes: control 0x48,
			// length 0x10, 'T', 'O', then the GUID
			// (G2Packet.cpp:325-329).
			name: "to with guid",
			pkt:  &G2Packet{Type: G2TypeTo, Payload: g2GUID()},
			wire: append([]byte{0x48, 0x10, 0x54, 0x4f}, g2GUID()...),
		},
		{
			name: "khl tree",
			pkt:  g2KHLTree(),
			wire: g2KHLWire,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := EncodeG2Packet(tt.pkt)
			if !bytes.Equal(got, tt.wire) {
				t.Fatalf("EncodeG2Packet =\n% x\nwant\n% x", got, tt.wire)
			}

			back, n, err := DecodeG2Packet(tt.wire)
			if err != nil {
				t.Fatalf("DecodeG2Packet: %v", err)
			}
			if n != len(tt.wire) {
				t.Errorf("consumed %d bytes, want %d", n, len(tt.wire))
			}
			if !reflect.DeepEqual(back, tt.pkt) {
				t.Errorf("decoded\n%+v\nwant\n%+v", back, tt.pkt)
			}
			if again := EncodeG2Packet(back); !bytes.Equal(again, tt.wire) {
				t.Errorf("re-encoded\n% x\nwant\n% x", again, tt.wire)
			}
		})
	}
}

func TestG2RoundTripSizes(t *testing.T) {
	// Each size lands on a different length-of-length, and the control
	// byte must say so: 1 byte up to 0xFF, 2 up to 0xFFFF, 3 beyond.
	tests := []struct {
		size   int
		lenLen byte
	}{
		{0, 1},
		{1, 1},
		{0xFF, 1},
		{0x100, 2},
		{0xFFFF, 2},
		{0x10000, 3},
	}

	for _, tt := range tests {
		var payload []byte
		if tt.size > 0 {
			payload = bytes.Repeat([]byte{0xA5}, tt.size)
		}
		pkt := &G2Packet{Type: G2TypeKHLRequest, Payload: payload}

		wire := EncodeG2Packet(pkt)
		// Type "KHLR" is four bytes, so typeLen-1 is 3.
		if want := tt.lenLen<<6 | 3<<3; wire[0] != want {
			t.Errorf("size %d: control byte 0x%02x, want 0x%02x", tt.size, wire[0], want)
		}

		back, n, err := DecodeG2Packet(wire)
		if err != nil {
			t.Fatalf("size %d: DecodeG2Packet: %v", tt.size, err)
		}
		if n != len(wire) {
			t.Errorf("size %d: consumed %d of %d bytes", tt.size, n, len(wire))
		}
		if !reflect.DeepEqual(back, pkt) {
			t.Errorf("size %d: round trip changed the packet:\n%+v\n%+v", tt.size, back, pkt)
		}
	}
}

// The length field follows the packet's BE flag, and the two orders must
// be distinguishable or this proves nothing.
func TestG2LengthFieldByteOrder(t *testing.T) {
	payload := bytes.Repeat([]byte{0x5A}, 0x123)

	le := EncodeG2Packet(&G2Packet{Type: G2TypeTimestamp, Payload: payload})
	be := EncodeG2Packet(&G2Packet{Type: G2TypeTimestamp, BigEndian: true, Payload: payload})

	// control | length | type: lenLen 2, type "TS", BE clear/set.
	if want := []byte{0x88, 0x23, 0x01, 0x54, 0x53}; !bytes.Equal(le[:5], want) {
		t.Errorf("little-endian header = % x, want % x", le[:5], want)
	}
	if want := []byte{0x8a, 0x01, 0x23, 0x54, 0x53}; !bytes.Equal(be[:5], want) {
		t.Errorf("big-endian header = % x, want % x", be[:5], want)
	}
	if bytes.Equal(le[:2], be[:2]) {
		t.Fatal("the two byte orders look alike; the test proves nothing")
	}

	for name, wire := range map[string][]byte{"little-endian": le, "big-endian": be} {
		back, n, err := DecodeG2Packet(wire)
		if err != nil {
			t.Fatalf("%s: DecodeG2Packet: %v", name, err)
		}
		if n != len(wire) {
			t.Errorf("%s: consumed %d of %d bytes", name, n, len(wire))
		}
		if !bytes.Equal(back.Payload, payload) {
			t.Errorf("%s: payload changed under round trip", name)
		}
	}
}

// The type length is Name_Len-1 in the control byte, for every legal
// name length from 1 to 8.
func TestG2TypeNameLengths(t *testing.T) {
	for n := 1; n <= g2MaxTypeLen; n++ {
		pkt := &G2Packet{Type: G2Type(strings.Repeat("A", n))}
		wire := EncodeG2Packet(pkt)
		if want := byte(1<<6) | byte((n-1)<<3); wire[0] != want {
			t.Errorf("type %d bytes: control byte 0x%02x, want 0x%02x", n, wire[0], want)
		}
		back, _, err := DecodeG2Packet(wire)
		if err != nil {
			t.Fatalf("type %d bytes: DecodeG2Packet: %v", n, err)
		}
		if back.Type != pkt.Type {
			t.Errorf("type %d bytes: round trip gave %q", n, string(back.Type))
		}
	}
}

func TestG2DecodeErrors(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty input", nil, ErrG2Empty},
		{"end of stream marker", []byte{0x00}, ErrG2EndOfStream},
		{"header cut off", []byte{0x48}, ErrG2Truncated},
		{"type cut off", []byte{0x48, 0x00}, ErrG2Truncated},
		{"body cut off", []byte{0x48, 0x05, 0x50, 0x49}, ErrG2Truncated},
		{"two-byte length cut off", []byte{0x88, 0x23, 0x54}, ErrG2Truncated},
		{"child cut off", []byte{0x4c, 0x0f, 0x4e, 0x48, 0x48}, ErrG2Truncated},
		{"type with a null byte", []byte{0x48, 0x00, 0x00, 0x50}, ErrG2BadType},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, n, err := DecodeG2Packet(tt.in)
			if err == nil {
				t.Fatalf("DecodeG2Packet(% x) = %+v, nil error", tt.in, p)
			}
			if !errors.Is(err, tt.want) {
				t.Errorf("error = %v, want %v", err, tt.want)
			}
			if p != nil || n != 0 {
				t.Errorf("failed decode returned packet %+v and %d bytes", p, n)
			}
		})
	}
}

func TestG2EncodePanics(t *testing.T) {
	tests := []struct {
		name string
		pkt  *G2Packet
		want error
	}{
		{"empty type", &G2Packet{}, ErrG2BadType},
		{"nine-byte type", &G2Packet{Type: "TOOLONGEST"}, ErrG2BadType},
		{"type with a null byte", &G2Packet{Type: G2Type("A\x00B")}, ErrG2BadType},
		{
			"children without the compound flag",
			&G2Packet{Type: G2TypeKHL, Children: []*G2Packet{{Type: G2TypePing}}},
			ErrG2ChildrenWithoutCompound,
		},
		{
			"body over three length bytes",
			&G2Packet{Type: G2TypeKHL, Payload: make([]byte, g2MaxPayloadLen+1)},
			ErrG2Oversized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			defer func() {
				r := recover()
				if r == nil {
					t.Fatal("EncodeG2Packet did not panic")
				}
				err, ok := r.(error)
				if !ok {
					t.Fatalf("panic value %v (%T) is not an error", r, r)
				}
				if !errors.Is(err, tt.want) {
					t.Errorf("panic = %v, want %v", err, tt.want)
				}
			}()
			EncodeG2Packet(tt.pkt)
		})
	}
}

// DecodeG2Children is the compound-payload reader: it mirrors Shareaza's
// SkipCompound, stopping at a zero control byte (consumed) or the end of
// the payload.
func TestG2DecodeChildren(t *testing.T) {
	pi := EncodeG2Packet(&G2Packet{Type: G2TypePing})

	t.Run("children then terminator then payload", func(t *testing.T) {
		body := append(append(append([]byte{}, pi...), 0x00), 0xaa, 0xbb)
		children, rest, err := DecodeG2Children(body)
		if err != nil {
			t.Fatalf("DecodeG2Children: %v", err)
		}
		if len(children) != 1 || children[0].Type != G2TypePing {
			t.Fatalf("children = %+v, want one PI", children)
		}
		if !bytes.Equal(rest, []byte{0xaa, 0xbb}) {
			t.Errorf("rest = % x, want aa bb", rest)
		}
	})

	t.Run("children to the end", func(t *testing.T) {
		children, rest, err := DecodeG2Children(pi)
		if err != nil {
			t.Fatalf("DecodeG2Children: %v", err)
		}
		if len(children) != 1 {
			t.Fatalf("children = %+v, want one", children)
		}
		if rest != nil {
			t.Errorf("rest = % x, want none", rest)
		}
	})

	t.Run("empty payload", func(t *testing.T) {
		children, rest, err := DecodeG2Children(nil)
		if err != nil {
			t.Fatalf("DecodeG2Children: %v", err)
		}
		if children != nil || rest != nil {
			t.Errorf("children = %+v, rest = % x, want none of either", children, rest)
		}
	})

	t.Run("leading terminator leaves the payload", func(t *testing.T) {
		children, rest, err := DecodeG2Children([]byte{0x00, 0xaa})
		if err != nil {
			t.Fatalf("DecodeG2Children: %v", err)
		}
		if len(children) != 0 {
			t.Errorf("children = %+v, want none", children)
		}
		if !bytes.Equal(rest, []byte{0xaa}) {
			t.Errorf("rest = % x, want aa", rest)
		}
	})

	t.Run("malformed child", func(t *testing.T) {
		if _, _, err := DecodeG2Children([]byte{0x48}); err == nil {
			t.Error("DecodeG2Children(0x48) = nil error, want truncated child")
		}
	})
}

// A compound flag makes the payload a child list; without it the payload
// is opaque even when it looks exactly like a framed packet.
func TestG2NonCompoundPayloadIsOpaque(t *testing.T) {
	payload := []byte{0x48, 0x00, 0x50, 0x49, 0x00}
	pkt := &G2Packet{Type: G2TypeTo, Payload: payload}

	back, _, err := DecodeG2Packet(EncodeG2Packet(pkt))
	if err != nil {
		t.Fatalf("DecodeG2Packet: %v", err)
	}
	if back.Children != nil {
		t.Errorf("non-compound payload became children: %+v", back.Children)
	}
	if !bytes.Equal(back.Payload, payload) {
		t.Errorf("payload = % x, want % x", back.Payload, payload)
	}
}

// Decode accepts three forms the specification permits and the encoder
// never emits; re-encoding normalises each to Shareaza's form. Every one
// is pinned here so the normalisation is a decision, not an accident.
func TestG2DecodeNormalisesSpecForms(t *testing.T) {
	tests := []struct {
		name string
		in   []byte
		want []byte
	}{
		{
			// Len_Len 0 is the specification's most compact
			// zero-length marker packet; Shareaza writes a zero
			// length byte instead.
			name: "zero length-of-length",
			in:   []byte{0x08, 0x50, 0x49},
			want: []byte{0x48, 0x00, 0x50, 0x49},
		},
		{
			// A child-stream terminator with nothing after it
			// is "valid, but unnecessary".
			name: "trailing child terminator",
			in:   []byte{0x54, 0x05, 0x4b, 0x48, 0x4c, 0x48, 0x00, 0x50, 0x49, 0x00},
			want: []byte{0x54, 0x04, 0x4b, 0x48, 0x4c, 0x48, 0x00, 0x50, 0x49},
		},
		{
			// The same, for a compound packet with no children at
			// all and a payload of just the terminator.
			name: "terminator only",
			in:   []byte{0x44, 0x01, 0x53, 0x00},
			want: []byte{0x44, 0x00, 0x53},
		},
		{
			// The reserved control bit is not ours to set or to
			// keep; Shareaza never sets it either.
			name: "reserved control bit",
			in:   []byte{0x48 | g2FlagReserved, 0x00, 0x50, 0x49},
			want: []byte{0x48, 0x00, 0x50, 0x49},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, n, err := DecodeG2Packet(tt.in)
			if err != nil {
				t.Fatalf("DecodeG2Packet(% x): %v", tt.in, err)
			}
			if n != len(tt.in) {
				t.Errorf("consumed %d of %d bytes", n, len(tt.in))
			}
			if got := EncodeG2Packet(p); !bytes.Equal(got, tt.want) {
				t.Errorf("re-encoded = % x, want % x", got, tt.want)
			}

			// The normalised form decodes to the same tree and is
			// a fixed point, so the normalisation happens once.
			norm, _, err := DecodeG2Packet(tt.want)
			if err != nil {
				t.Fatalf("DecodeG2Packet(% x): %v", tt.want, err)
			}
			if !reflect.DeepEqual(p, norm) {
				t.Errorf("normalised decode differs:\n%+v\n%+v", norm, p)
			}
		})
	}
}

// A stream is a sequence of packets; a decode consumes exactly one and
// reports how many bytes that took.
func TestG2DecodeConsumedCount(t *testing.T) {
	first := EncodeG2Packet(g2KHLTree())
	second := EncodeG2Packet(&G2Packet{Type: G2TypePong})
	stream := append(append([]byte{}, first...), second...)

	p, n, err := DecodeG2Packet(stream)
	if err != nil {
		t.Fatalf("DecodeG2Packet(first): %v", err)
	}
	if n != len(first) {
		t.Errorf("consumed %d bytes, want %d (the first packet only)", n, len(first))
	}
	if !reflect.DeepEqual(p, g2KHLTree()) {
		t.Errorf("first packet = %+v, want the KHL tree", p)
	}

	q, m, err := DecodeG2Packet(stream[n:])
	if err != nil {
		t.Fatalf("DecodeG2Packet(second): %v", err)
	}
	if m != len(second) {
		t.Errorf("consumed %d bytes, want %d", m, len(second))
	}
	if q.Type != G2TypePong {
		t.Errorf("second packet is %q, want PO", string(q.Type))
	}
}

// A decoded packet owns its payload: reusing the input buffer afterwards
// must not change it.
func TestG2DecodedPayloadDoesNotAliasInput(t *testing.T) {
	wire := EncodeG2Packet(&G2Packet{Type: G2TypeKHLRequest, Payload: []byte{1, 2, 3}})
	p, _, err := DecodeG2Packet(wire)
	if err != nil {
		t.Fatalf("DecodeG2Packet: %v", err)
	}
	for i := range wire {
		wire[i] = 0xFF
	}
	if !bytes.Equal(p.Payload, []byte{1, 2, 3}) {
		t.Errorf("payload = % x, want 01 02 03 (it aliases the input)", p.Payload)
	}
}

// Nesting is bounded, so a hostile stream cannot recurse without end.
func TestG2MaxDepth(t *testing.T) {
	nest := func(levels int) *G2Packet {
		p := &G2Packet{Type: G2TypePing}
		for i := 1; i < levels; i++ {
			p = &G2Packet{Type: G2TypeKHL, Compound: true, Children: []*G2Packet{p}}
		}
		return p
	}

	if _, _, err := DecodeG2Packet(EncodeG2Packet(nest(g2MaxDepth))); err != nil {
		t.Errorf("depth %d rejected: %v", g2MaxDepth, err)
	}
	if _, _, err := DecodeG2Packet(EncodeG2Packet(nest(g2MaxDepth + 1))); !errors.Is(err, ErrG2Depth) {
		t.Errorf("depth %d error = %v, want ErrG2Depth", g2MaxDepth+1, err)
	}
}

// Fuzzing feeds arbitrary bytes to the decoder. It must never panic, and
// a packet that decodes must re-encode, re-decode to the same tree, and
// settle on the same bytes -- encode(decode(.)) is idempotent.
//
// Byte-exactness of the encoding itself is pinned by TestG2WireVectors
// and TestG2DecodeNormalisesSpecForms, because decode deliberately
// accepts forms the encoder normalises.
func FuzzDecodeG2Packet(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0x48})
	f.Add([]byte{0x48, 0x00, 0x50, 0x49})
	f.Add([]byte{0x08, 0x50, 0x49})
	f.Add([]byte{0x48 | g2FlagReserved, 0x00, 0x50, 0x49})
	f.Add(g2KHLWire)
	f.Add(append(append([]byte{}, g2KHLWire...), 0x00, 0xff))
	f.Add(bytes.Repeat([]byte{0xff}, 32))
	f.Add([]byte{0x4c, 0x0f, 0x4e, 0x48})

	f.Fuzz(func(t *testing.T, data []byte) {
		p, n, err := DecodeG2Packet(data)
		if err != nil {
			return
		}
		if n <= 0 || n > len(data) {
			t.Fatalf("consumed %d of %d bytes", n, len(data))
		}

		first := EncodeG2Packet(p)
		p2, n2, err := DecodeG2Packet(first)
		if err != nil {
			t.Fatalf("decoded % x, but its re-encoding % x does not decode: %v", data[:n], first, err)
		}
		if n2 != len(first) {
			t.Fatalf("re-encoding consumed %d of %d bytes", n2, len(first))
		}
		if !reflect.DeepEqual(p, p2) {
			t.Fatalf("round trip changed the packet:\n%+v\n%+v", p, p2)
		}
		if second := EncodeG2Packet(p2); !bytes.Equal(first, second) {
			t.Fatalf("encoding is not stable:\n% x\n% x", first, second)
		}
	})
}
