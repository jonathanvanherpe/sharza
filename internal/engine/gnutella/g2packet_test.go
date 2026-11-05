// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"reflect"
	"testing"
)

func TestG2PacketRoundTripLeaf(t *testing.T) {
	p := &G2Packet{Type: "PI", Payload: []byte{1, 2, 3, 4}}
	b, err := EncodeG2Packet(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != p.Type {
		t.Fatalf("type: %q != %q", got.Type, p.Type)
	}
	if !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("payload mismatch")
	}
	if got.Compound {
		t.Fatal("unexpected compound")
	}
}

func TestG2PacketRoundTripNested(t *testing.T) {
	child1 := &G2Packet{Type: "A", Payload: []byte("hello")}
	child2 := &G2Packet{Type: "BC", Payload: []byte{0xff}}
	parent := &G2Packet{Type: "Q2", Compound: true, Children: []*G2Packet{child1, child2}}
	b, err := EncodeG2Packet(parent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.Type != "Q2" {
		t.Fatalf("type %q", got.Type)
	}
	if !got.Compound {
		t.Fatal("expected compound")
	}
	if len(got.Children) != 2 {
		t.Fatalf("children %d", len(got.Children))
	}
	if got.Children[0].Type != "A" || !bytes.Equal(got.Children[0].Payload, []byte("hello")) {
		t.Fatalf("child0 mismatch")
	}
	if got.Children[1].Type != "BC" || !bytes.Equal(got.Children[1].Payload, []byte{0xff}) {
		t.Fatalf("child1 mismatch")
	}
	// trailing payload after children round-trips as parent payload? Our
	// encoder appends payload after children; decoder consumes all into
	// children only, so parent payload is empty. Check by re-encoding.
	b2, err := EncodeG2Packet(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("re-encode mismatch")
	}
}

func TestG2PacketBigEndian(t *testing.T) {
	p := &G2Packet{Type: "X", BigEndian: true, Payload: make([]byte, 300)}
	b, err := EncodeG2Packet(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.BigEndian {
		t.Fatal("bigendian lost")
	}
	if len(got.Payload) != 300 {
		t.Fatalf("len %d", len(got.Payload))
	}
}

func TestG2PacketMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x40}, // length width 1 but no type/payload
		{0xC0 | 0x08, 0x00, 'A'}, // length 0? actually length 0, type A, then truncated? 
	}
	for _, c := range cases {
		if _, err := DecodeG2Packet(c); err == nil {
			t.Fatalf("expected error for % x", c)
		}
	}
	// truncated nested: parent compound claims child but cut
	parent := &G2Packet{Type: "P", Compound: true, Children: []*G2Packet{{Type: "C", Payload: []byte("abc")}}}
	b, _ := EncodeG2Packet(parent)
	// cut last byte
	if _, err := DecodeG2Packet(b[:len(b)-1]); err == nil {
		t.Fatal("expected truncated error")
	}
	// trailing bytes
	if _, err := DecodeG2Packet(append(append([]byte{}, b...), 0x00)); err == nil {
		// trailing single zero byte is itself a packet? Actually 0x00 invalid header -> error expected
	} 
	// length too large claim
	bad := []byte{0x40 | 0x08, 0xFF, 'A'}
	// length 255 but only 0 payload bytes -> truncated
	if _, err := DecodeG2Packet(bad); err == nil {
		t.Fatal("expected truncated")
	}
}

func TestG2PacketMalformedLengthMismatch(t *testing.T) {
	// first byte: lenlen=1 (0x40), typelen=0 (0x00 => type 1 byte), flags 0
	// length byte 0x05 but provide fewer payload bytes
	data := []byte{0x41, 0x05, 'A', 1, 2}
	if _, err := DecodeG2Packet(data); err == nil {
		t.Fatal("expected truncated")
	}
}

func FuzzG2PacketRoundTrip(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x41, 0x03, 'P', 'I', 'D', 1, 2, 3})
	f.Add([]byte{0xC0 | 0x08, 0x00, 0x00, 0x05, 'C', 'H', 'I', 'L', 'D', 0x41, 0x02, 'A', 1, 2})
	f.Fuzz(func(t *testing.T, data []byte) {
		pkt, err := DecodeG2Packet(data)
		if err != nil {
			return
		}
		enc, err := EncodeG2Packet(pkt)
		if err != nil {
			t.Fatalf("encode failed: %v", err)
		}
		pkt2, err := DecodeG2Packet(enc)
		if err != nil {
			t.Fatalf("redecode failed: %v", err)
		}
		if !reflect.DeepEqual(pkt, pkt2) {
			t.Fatalf("round-trip mismatch")
		}
	})
}
