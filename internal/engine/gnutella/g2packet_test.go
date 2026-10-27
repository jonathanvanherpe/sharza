// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"testing"
)

func TestG2PacketRoundTripLeaf(t *testing.T) {
	cases := []struct {
		name      string
		tag       []byte
		bigEndian bool
		payload   []byte
	}{
		{"short tag le empty", []byte("PI"), false, nil},
		{"short tag be", []byte("PI"), true, []byte{1, 2, 3}},
		{"8-byte tag", []byte("ABCDEFGH"), false, []byte("hello")},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := G2Packet{Type: c.tag, BigEndian: c.bigEndian, Payload: c.payload}
			b, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			got, trail, err := DecodeG2Packet(b)
			if err != nil {
				t.Fatal(err)
			}
			if len(trail) != 0 {
				t.Fatalf("trailing = %d", len(trail))
			}
			if !bytes.Equal(got.Type, c.tag) {
				t.Fatalf("tag mismatch")
			}
			if got.BigEndian != c.bigEndian {
				t.Fatalf("endian mismatch")
			}
			if !bytes.Equal(got.Payload, c.payload) {
				t.Fatalf("payload mismatch")
			}
		})
	}
}

func TestG2PacketEndianBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 255, 256, 65535, 65536} {
		for _, be := range []bool{false, true} {
			payload := make([]byte, n)
			for i := range payload {
				payload[i] = byte(i)
			}
			p := G2Packet{Type: []byte("T"), BigEndian: be, Payload: payload}
			b, err := p.Encode()
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := DecodeG2Packet(b)
			if err != nil {
				t.Fatal(err)
			}
			if len(got.Payload) != n {
				t.Fatalf("len %d got %d", n, len(got.Payload))
			}
			if got.BigEndian != be {
				t.Fatalf("endian")
			}
		}
	}
}

func TestG2PacketCompound(t *testing.T) {
	child1 := G2Packet{Type: []byte("A"), Payload: []byte{1}}
	child2 := G2Packet{Type: []byte("BC"), Payload: []byte{2, 3}}
	parent := G2Packet{Type: []byte("P"), Compound: true, Children: []G2Packet{child1, child2}}
	b, err := parent.Encode()
	if err != nil {
		t.Fatal(err)
	}
	got, trail, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(trail) != 0 {
		t.Fatal("trailing")
	}
	if !got.Compound {
		t.Fatal("not compound")
	}
	if len(got.Children) != 2 {
		t.Fatalf("children %d", len(got.Children))
	}
	if !bytes.Equal(got.Children[0].Type, []byte("A")) {
		t.Fatal("child0 type")
	}
	if !bytes.Equal(got.Children[1].Type, []byte("BC")) {
		t.Fatal("child1 type")
	}
}

func TestG2PacketTrailing(t *testing.T) {
	p := G2Packet{Type: []byte("T"), Payload: []byte{9}}
	b, _ := p.Encode()
	b = append(b, 0xAA, 0xBB)
	got, trail, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Payload) != 1 {
		t.Fatal("payload")
	}
	if !bytes.Equal(trail, []byte{0xAA, 0xBB}) {
		t.Fatalf("trail %v", trail)
	}
}

func TestG2PacketMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00}, // nLenLen 0
		{0x40}, // truncated header (need length+type)
		{0xC0, 0x00}, // nLenLen 3 but truncated
	}
	for _, c := range cases {
		_, _, err := DecodeG2Packet(c)
		if err == nil {
			t.Fatalf("expected error for %v", c)
		}
	}
	// payload too large claim: length bytes say more than available
	_, _, err := DecodeG2Packet([]byte{0x01, 0x05, 'T'})
	if err == nil {
		t.Fatal("expected truncated payload error")
	}
	// payload exceeds 0xFFFFFF impossible with 3 bytes? max exactly 0xFFFFFF; construct 4? nLenLen max3 so no. Test type tag length 0 impossible.
}

func TestG2PacketTypeTagBounds(t *testing.T) {
	p := G2Packet{Type: make([]byte, 0), Payload: nil}
	if _, err := p.Encode(); err == nil {
		t.Fatal("expected error empty tag")
	}
	p2 := G2Packet{Type: make([]byte, 9), Payload: nil}
	if _, err := p2.Encode(); err == nil {
		t.Fatal("expected error 9-byte tag")
	}
}
