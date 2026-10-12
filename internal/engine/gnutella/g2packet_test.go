// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Unit tests for the G2 tree-packet framer. The golden vector is
// hand-assembled from the wire layout (a compound KHLA holding a
// compound CH holding an NA for 1.2.3.4:6346) so the encoder is checked
// against bytes, not against itself.

import (
	"bytes"
	"testing"
)

// goldenKHLA is a KHL answer naming 1.2.3.4:6346, byte for byte:
//
//	KHLA compound (14-byte payload)
//	  CH compound (10-byte payload)
//	    NA (6-byte payload): 01 02 03 04 | 18 CA
//
// The header byte is (length-field size << 6) | ((type length - 1) << 3)
// | compound, so KHLA is 0x5C, CH is 0x4C and NA is 0x48.
var goldenKHLA = []byte{
	0x5C, 0x0E, 'K', 'H', 'L', 'A',
	0x4C, 0x0A, 'C', 'H',
	0x48, 0x06, 'N', 'A',
	0x01, 0x02, 0x03, 0x04, 0x18, 0xCA,
}

// TestG2PacketGoldenKHLADecode decodes the hand-assembled answer and
// checks the tree the wire describes.
func TestG2PacketGoldenKHLADecode(t *testing.T) {
	p, n, err := decodeG2Packet(goldenKHLA)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(goldenKHLA) {
		t.Fatalf("consumed %d bytes, want %d", n, len(goldenKHLA))
	}
	if p.Type != g2TypeKHLA || !p.Compound {
		t.Fatalf("top packet = %q compound=%v, want KHLA compound", p.Type, p.Compound)
	}
	if len(p.Children) != 1 || p.Children[0].Type != g2TypeCH {
		t.Fatalf("children = %v, want one CH", p.Children)
	}
	na := p.Children[0].child(g2TypeNA)
	if na == nil {
		t.Fatal("CH has no NA sub-packet")
	}
	want := []byte{0x01, 0x02, 0x03, 0x04, 0x18, 0xCA}
	if !bytes.Equal(na.Data, want) {
		t.Fatalf("NA payload = % x, want % x", na.Data, want)
	}
}

// TestG2PacketGoldenKHLAEncode checks the encoder produces the same
// bytes the golden vector spells out.
func TestG2PacketGoldenKHLAEncode(t *testing.T) {
	p := &g2Packet{
		Type:     g2TypeKHLA,
		Compound: true,
		Children: []*g2Packet{{
			Type:     g2TypeCH,
			Compound: true,
			Children: []*g2Packet{{
				Type: g2TypeNA,
				Data: []byte{0x01, 0x02, 0x03, 0x04, 0x18, 0xCA},
			}},
		}},
	}
	if got := p.marshal(); !bytes.Equal(got, goldenKHLA) {
		t.Fatalf("marshal = % x, want % x", got, goldenKHLA)
	}
}

// TestG2PacketRoundTrip builds a tree with the fields a KHLA answer
// carries and checks it survives encode then decode.
func TestG2PacketRoundTrip(t *testing.T) {
	in := &g2Packet{
		Type:     g2TypeKHLA,
		Compound: true,
		Children: []*g2Packet{
			{Type: g2TypeCH, Compound: true, Children: []*g2Packet{
				{Type: g2TypeNA, Data: []byte{0x0A, 0x00, 0x00, 0x01, 0x18, 0xCA}},
				{Type: g2TypeTS, Data: []byte{0x00, 0x00, 0x00, 0x01}},
				{Type: g2TypeV, Data: []byte("SHAR")},
			}},
			{Type: g2TypeNH, Data: []byte{0x7F, 0x00, 0x00, 0x01, 0x18, 0xCB}},
		},
	}
	out, n, err := decodeG2Packet(in.marshal())
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(in.marshal()) {
		t.Fatalf("consumed %d, want %d", n, len(in.marshal()))
	}
	if len(out.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(out.Children))
	}
	ch := out.Children[0]
	if ch.Type != g2TypeCH || !ch.Compound || len(ch.Children) != 3 {
		t.Fatalf("first child = %+v, want compound CH with 3 sub-packets", ch)
	}
	if got := out.Children[1].Data; !bytes.Equal(got, []byte{0x7F, 0x00, 0x00, 0x01, 0x18, 0xCB}) {
		t.Fatalf("flat NH payload = % x", got)
	}
}

// TestG2PacketRejectsTruncated checks a packet whose declared length
// runs past the buffer is refused rather than read out of bounds.
func TestG2PacketRejectsTruncated(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   []byte
	}{
		{"empty", nil},
		{"header only", []byte{0x48}},
		{"short type", []byte{0x48, 0x06, 'N'}},
		{"short payload", append([]byte{0x48, 0x06, 'N', 'A'}, 0x01, 0x02)},
		{"two-byte length runs past", []byte{0x80, 0xFF, 0xFF, 'N', 'A'}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, _, err := decodeG2Packet(tc.in); err == nil {
				t.Fatalf("decode(% x) succeeded, want an error", tc.in)
			}
		})
	}
}

// TestG2PacketBigEndianLength checks the big-endian flag is honoured
// for the length field, which is the one place a decoder can get it
// wrong per packet.
func TestG2PacketBigEndianLength(t *testing.T) {
	// Header 0x9A = lenLen 2, typeLen 4, flags 0x02 (big-endian), so the
	// length bytes 0x01 0x02 mean 258, not 513.
	in := append([]byte{0x9A, 0x01, 0x02, 'K', 'H', 'L', 'A'}, make([]byte, 258)...)
	p, n, err := decodeG2Packet(in)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n != len(in) {
		t.Fatalf("consumed %d, want %d", n, len(in))
	}
	if len(p.Data) != 0x102 {
		t.Fatalf("payload length = %d, want 258", len(p.Data))
	}
}
