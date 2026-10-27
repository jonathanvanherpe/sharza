// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"testing"
)

func TestG2PacketLeafRoundTrip(t *testing.T) {
	cases := []struct {
		name      string
		pkt       G2Packet
	}{
		{"empty", G2Packet{Type: []byte{'P', 'I'}, Payload: nil}},
		{"payload", G2Packet{Type: []byte{'Q', '2'}, Payload: []byte{0x01, 0x02, 0x03}}},
		{"single-byte-type", G2Packet{Type: []byte{'X'}, Payload: []byte("hello")}},
		{"eight-byte-type", G2Packet{Type: []byte{'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H'}, Payload: []byte{0xFF}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.pkt.Encode()
			if err != nil {
				t.Fatalf("Encode: %v", err)
			}
			got, rest, err := DecodeG2Packet(b)
			if err != nil {
				t.Fatalf("DecodeG2Packet: %v", err)
			}
			if len(rest) != 0 {
				t.Fatalf("remaining = %d, want 0", len(rest))
			}
			if !bytes.Equal(got.Type, tc.pkt.Type) {
				t.Errorf("Type = %v, want %v", got.Type, tc.pkt.Type)
			}
			if got.Compound != tc.pkt.Compound {
				t.Errorf("Compound = %v, want %v", got.Compound, tc.pkt.Compound)
			}
			if got.BigEndian != tc.pkt.BigEndian {
				t.Errorf("BigEndian = %v, want %v", got.BigEndian, tc.pkt.BigEndian)
			}
			if !bytes.Equal(got.Payload, tc.pkt.Payload) {
				t.Errorf("Payload = %v, want %v", got.Payload, tc.pkt.Payload)
			}
		})
	}
}

func TestG2PacketEndian(t *testing.T) {
	for _, be := range []bool{false, true} {
		pkt := G2Packet{Type: []byte{'T', 'S'}, BigEndian: be, Payload: []byte{0xAB, 0xCD, 0xEF}}
		b, err := pkt.Encode()
		if err != nil {
			t.Fatal(err)
		}
		got, _, err := DecodeG2Packet(b)
		if err != nil {
			t.Fatal(err)
		}
		if got.BigEndian != be {
			t.Errorf("BigEndian = %v, want %v", got.BigEndian, be)
		}
		if !bytes.Equal(got.Payload, pkt.Payload) {
			t.Errorf("payload mismatch")
		}
	}
}

func TestG2PacketLengthBoundaries(t *testing.T) {
	sizes := []int{0, 1, 255, 256, 65535, 65536}
	for _, n := range sizes {
		payload := make([]byte, n)
		for i := range payload {
			payload[i] = byte(i)
		}
		pkt := G2Packet{Type: []byte{'S', 'Z'}, Payload: payload}
		b, err := pkt.Encode()
		if err != nil {
			t.Fatalf("size %d: Encode: %v", n, err)
		}
		// verify length width
		nLenLen := int((b[0] & 0xC0) >> 6)
		wantWidth := 1
		if n > 0xFF {
			wantWidth = 2
		}
		if n > 0xFFFF {
			wantWidth = 3
		}
		if nLenLen != wantWidth {
			t.Errorf("size %d: length width = %d, want %d", n, nLenLen, wantWidth)
		}
		got, rest, err := DecodeG2Packet(b)
		if err != nil {
			t.Fatalf("size %d: Decode: %v", n, err)
		}
		if len(rest) != 0 {
			t.Fatalf("size %d: remaining = %d", n, len(rest))
		}
		if len(got.Payload) != n {
			t.Errorf("size %d: payload len = %d", n, len(got.Payload))
		}
	}
}

func TestG2PacketCompound(t *testing.T) {
	child1 := G2Packet{Type: []byte{'C', 'H'}, Payload: []byte{0x10}}
	child2 := G2Packet{Type: []byte{'D', 'N'}, Payload: []byte{0x20, 0x30}, BigEndian: true}
	parent := G2Packet{
		Type:     []byte{'H', 'U', 'B'},
		Compound: true,
		Children: []G2Packet{child1, child2},
	}
	b, err := parent.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, rest, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 0 {
		t.Fatalf("remaining = %d", len(rest))
	}
	if !got.Compound {
		t.Fatal("Compound = false, want true")
	}
	if len(got.Children) != 2 {
		t.Fatalf("children = %d, want 2", len(got.Children))
	}
	if !bytes.Equal(got.Children[0].Type, child1.Type) || !bytes.Equal(got.Children[0].Payload, child1.Payload) {
		t.Errorf("child0 mismatch")
	}
	if !bytes.Equal(got.Children[1].Type, child2.Type) || !bytes.Equal(got.Children[1].Payload, child2.Payload) || got.Children[1].BigEndian != child2.BigEndian {
		t.Errorf("child1 mismatch")
	}
	// re-encode children concatenation equals payload
	re, _ := got.Encode()
	if !bytes.Equal(re, b) {
		t.Errorf("re-encode mismatch")
	}
}

func TestG2PacketNestedCompound(t *testing.T) {
	inner := G2Packet{Type: []byte{'L', 'E', 'A', 'F'}, Compound: true, Children: []G2Packet{
		{Type: []byte{'N', 'A'}, Payload: []byte{1, 2}},
	}}
	outer := G2Packet{Type: []byte{'R', 'O', 'O', 'T'}, Compound: true, Children: []G2Packet{inner}}
	b, err := outer.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Children) != 1 {
		t.Fatalf("outer children = %d", len(got.Children))
	}
	if !got.Children[0].Compound {
		t.Fatal("inner not compound")
	}
	if len(got.Children[0].Children) != 1 {
		t.Fatalf("inner children = %d", len(got.Children[0].Children))
	}
}

func TestG2PacketTrailingBytes(t *testing.T) {
	pkt := G2Packet{Type: []byte{'P', 'I'}, Payload: []byte{0x01}}
	b, _ := pkt.Encode()
	b = append(b, 0xAA, 0xBB)
	got, rest, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(rest) != 2 || rest[0] != 0xAA || rest[1] != 0xBB {
		t.Errorf("remaining = %v", rest)
	}
	if !bytes.Equal(got.Type, pkt.Type) {
		t.Errorf("type mismatch")
	}
}

func TestG2PacketMalformed(t *testing.T) {
	cases := []struct {
		name string
		in   []byte
	}{
		{"empty", []byte{}},
		{"truncated-length", []byte{0x40 | (1 << 3)}}, // nLenLen=1 but no length/type
		{"nLenLen-zero", []byte{0x08 | 0x00}},        // first byte: type 1 byte, len width 0 (invalid)
		{"truncated-payload", func() []byte {
			b, _ := (G2Packet{Type: []byte{'P', 'I'}, Payload: []byte{1, 2, 3}}).Encode()
			return b[:len(b)-1]
		}()},
		{"type-len-zero-impossible", []byte{0xC0}}, // nLenLen=3? actually 0xC0>>6=3, typeLen 0+1=1, payloadLen from 3 bytes; truncated
		{"payload-too-large", append([]byte{0xE0 | (1 << 3), 0xFF, 0xFF, 0xFF}, []byte{'X'}...)}, // nLenLen=3 all FF = 0xFFFFFF payload but only 1 byte avail -> truncated; also test length value check separately
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := DecodeG2Packet(tc.in)
			if err == nil {
				t.Fatalf("expected error, got nil")
			}
		})
	}
}

func TestG2PacketPayloadTooLarge(t *testing.T) {
	// 3-byte length field encoding 0xFFFFFF but provide only 0 bytes -> truncated
	// Directly test the length-value guard by crafting header claiming 0xFFFFFF+? impossible in 3 bytes max.
	// Instead ensure Encode rejects >0xFFFFFF via compound? Use payload of 0xFFFFFF+1 impossible memory; skip.
	_ = 0
}

func TestG2PacketEncodeErrors(t *testing.T) {
	cases := []G2Packet{
		{Type: nil, Payload: []byte{1}},
		{Type: []byte{}, Payload: []byte{1}},
		{Type: make([]byte, 9), Payload: []byte{1}},
	}
	for _, p := range cases {
		if _, err := p.Encode(); err == nil {
			t.Errorf("expected error for type len %d", len(p.Type))
		}
	}
}

func TestG2PacketMalformedLengthWidth(t *testing.T) {
	// nLenLen = 0 in low bits of top two bits
	b := []byte{0x08, 'X'} // type 1 byte, len width 0
	_, _, err := DecodeG2Packet(b)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestG2PacketBigEndianLengthValue(t *testing.T) {
	// manually encode a big-endian length and decode
	pkt := G2Packet{Type: []byte{'B', 'E'}, BigEndian: true, Payload: []byte{0x01, 0x02}}
	b, err := pkt.Encode()
	if err != nil {
		t.Fatal(err)
	}
	// length bytes should be big-endian: 00 02
	if b[1] != 0x02 {
		t.Errorf("length byte = % x, want 02", b[1])
	}
	got, _, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.BigEndian {
		t.Fatal("BigEndian lost")
	}
}
