// SPDX-License-Identifier: GPL-3.0-or-later

package g2

import (
	"bytes"
	"errors"
	"testing"
)

// Pinned wire vectors. The bytes are written by hand from the g2.doxu.org
// "Packet Structure" specification and cross-checked against Shareaza's
// G2Packet.cpp (WritePacket / ToBuffer), so a change to the codec that
// disagrees with either client shows up here as a byte diff.

// leafPacket is /QKA, a leaf carrying a four-byte payload:
//
//	control  0x50  len_len=1, name_len-1=2 ("QKA"), flags=0
//	length   0x04
//	name     "QKA"
//	payload  DE AD BE EF
func leafPacket() []byte {
	return []byte{0x50, 0x04, 0x51, 0x4B, 0x41, 0xDE, 0xAD, 0xBE, 0xEF}
}

// parentPacket is /RELAY containing one /TO child and then a payload. It
// exercises a two-level tree and the zero terminator that separates the child
// list from the parent payload:
//
//	root control 0x64  len_len=1, name_len-1=4 ("RELAY"), compound
//	root length  0x16  (22 = 20-byte child + terminator + 1 payload byte)
//	root name    "RELAY"
//	child        0x48 0x10 "TO" + 16-byte payload 00..0f
//	terminator   0x00
//	payload      0xAA
func parentPacket() []byte {
	child := []byte{0x48, 0x10, 0x54, 0x4F}
	for i := 0; i < 16; i++ {
		child = append(child, byte(i))
	}
	root := []byte{0x64, 0x16, 0x52, 0x45, 0x4C, 0x41, 0x59}
	root = append(root, child...)
	root = append(root, 0x00, 0xAA)
	return root
}

// beLeafPacket is /PI with the big-endian flag set and a two-byte payload.
func beLeafPacket() []byte {
	return []byte{0x4A, 0x02, 0x50, 0x49, 0x01, 0x02}
}

// zeroCompoundPacket is /A with the compound flag set and a zero-length body.
func zeroCompoundPacket() []byte {
	return []byte{0x44, 0x00, 0x41}
}

func TestParseLeaf(t *testing.T) {
	p, err := Parse(leafPacket())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Type != "QKA" {
		t.Errorf("Type = %q, want QKA", p.Type)
	}
	if p.Compound {
		t.Errorf("Compound = true, want false")
	}
	if p.BigEndian {
		t.Errorf("BigEndian = true, want false")
	}
	if want := []byte{0xDE, 0xAD, 0xBE, 0xEF}; !bytes.Equal(p.Payload, want) {
		t.Errorf("Payload = %x, want %x", p.Payload, want)
	}
	if len(p.Children) != 0 {
		t.Errorf("Children = %d, want 0", len(p.Children))
	}
}

func TestParseTwoLevelParent(t *testing.T) {
	p, err := Parse(parentPacket())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if p.Type != "RELAY" {
		t.Errorf("root Type = %q, want RELAY", p.Type)
	}
	if !p.Compound {
		t.Errorf("root Compound = false, want true")
	}
	if len(p.Children) != 1 {
		t.Fatalf("root Children = %d, want 1", len(p.Children))
	}
	child := p.Children[0]
	if child.Type != "TO" {
		t.Errorf("child Type = %q, want TO", child.Type)
	}
	if child.Compound {
		t.Errorf("child Compound = true, want false")
	}
	want := make([]byte, 16)
	for i := range want {
		want[i] = byte(i)
	}
	if !bytes.Equal(child.Payload, want) {
		t.Errorf("child Payload = %x, want %x", child.Payload, want)
	}
	if !bytes.Equal(p.Payload, []byte{0xAA}) {
		t.Errorf("root Payload = %x, want AA", p.Payload)
	}
}

func TestParseBigEndianLeaf(t *testing.T) {
	p, err := Parse(beLeafPacket())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.BigEndian {
		t.Errorf("BigEndian = false, want true")
	}
	if p.Type != "PI" || !bytes.Equal(p.Payload, []byte{0x01, 0x02}) {
		t.Errorf("got %s, want PI with payload 0102", p)
	}
}

func TestParseZeroLengthCompound(t *testing.T) {
	p, err := Parse(zeroCompoundPacket())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if !p.Compound || len(p.Children) != 0 || len(p.Payload) != 0 {
		t.Errorf("got %s, want a compound packet with no children and no payload", p)
	}
}

func TestRoundTripIdentity(t *testing.T) {
	for _, v := range [][]byte{
		leafPacket(),
		parentPacket(),
		beLeafPacket(),
		zeroCompoundPacket(),
	} {
		p, err := Parse(v)
		if err != nil {
			t.Fatalf("Parse(%x): %v", v, err)
		}
		enc, err := p.Marshal()
		if err != nil {
			t.Fatalf("Marshal(%x): %v", v, err)
		}
		if !bytes.Equal(enc, v) {
			t.Errorf("round trip changed bytes:\n got %x\nwant %x", enc, v)
		}
	}
}

func TestLengthEncodingRoundTrip(t *testing.T) {
	values := []uint32{0x00, 0x12, 0xFF, 0x0102, 0xFFFF, 0x010203, MaxPacketSize}
	widths := map[uint32]int{
		0x00: 1, 0x12: 1, 0xFF: 1,
		0x0102: 2, 0xFFFF: 2,
		0x010203: 3, MaxPacketSize: 3,
	}
	for _, be := range []bool{false, true} {
		for _, v := range values {
			w := widths[v]
			enc := appendLength(nil, v, w, be)
			if len(enc) != w {
				t.Errorf("be=%t n=%#x: appendLength wrote %d bytes, want %d", be, v, len(enc), w)
			}
			got, err := decodeLength(enc, be)
			if err != nil {
				t.Fatalf("be=%t n=%#x: decodeLength: %v", be, v, err)
			}
			if got != v {
				t.Errorf("be=%t: round trip got %#x, want %#x", be, got, v)
			}
		}
	}
}

// TestParseMalformedRejected pins one vector per rejection class. Each case
// asserts the specific sentinel, not just "an error", so that dropping the
// guard that produces it turns the case red.
func TestParseMalformedRejected(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
		want error
	}{
		{"empty input", nil, ErrTruncated},
		{"zero control byte", []byte{0x00}, ErrZeroControl},
		{"length field overruns buffer", []byte{0xC8, 0xFF}, ErrTruncated},
		{"truncated body", []byte{0x48, 0x10, 0x50, 0x49}, ErrTruncated},
		{"over-long input", append(leafPacket(), 0x00), ErrTrailingData},
		// A compound body whose children do not tile it: a valid child is
		// followed by a stray 0xFF that cannot start a child.
		{"bad alignment", []byte{0x4C, 0x05, 0x41, 0x41, 0x48, 0x00, 0x54, 0x4F, 0xFF}, ErrBadAlignment},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p, err := Parse(c.in)
			if err == nil {
				t.Fatalf("Parse(%x) = %s, want error", c.in, p)
			}
			if !errors.Is(err, c.want) {
				t.Errorf("Parse(%x) error = %v, want %v", c.in, err, c.want)
			}
		})
	}
}

func TestParseFromConsumesOnePacket(t *testing.T) {
	// The stream seam: a caller with two packets back to back uses ParseFrom
	// to cut the first and advance. Parse, by contrast, is single-packet.
	leaf := leafPacket()
	stream := append(append([]byte{}, leaf...), parentPacket()...)

	p, n, err := ParseFrom(stream)
	if err != nil {
		t.Fatalf("ParseFrom: %v", err)
	}
	if n != len(leaf) {
		t.Errorf("ParseFrom consumed %d bytes, want %d", n, len(leaf))
	}
	if p.Type != "QKA" {
		t.Errorf("ParseFrom first packet = %s, want QKA", p)
	}
	if _, err := Parse(stream); !errors.Is(err, ErrTrailingData) {
		t.Errorf("Parse(stream) error = %v, want ErrTrailingData", err)
	}
}

func TestMarshalRejectsInvalid(t *testing.T) {
	cases := []struct {
		name string
		p    *Packet
		want error
	}{
		{"empty name", &Packet{}, ErrBadName},
		{"name too long", &Packet{Type: "123456789"}, ErrBadName},
		{"leaf with children", &Packet{Type: "X", Children: []*Packet{{Type: "Y"}}}, ErrBadAlignment},
		{"nil child", &Packet{Type: "X", Compound: true, Children: []*Packet{nil}}, ErrBadAlignment},
		{"body too long", &Packet{Type: "X", Payload: make([]byte, MaxPacketSize+1)}, ErrTooLong},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := c.p.Marshal(); !errors.Is(err, c.want) {
				t.Errorf("Marshal error = %v, want %v", err, c.want)
			}
		})
	}
}
