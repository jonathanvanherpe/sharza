// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"reflect"
	"testing"
)

func TestG2PacketRoundTripLeaf(t *testing.T) {
	p := &G2Packet{Type: []byte("PI"), Payload: []byte{1, 2, 3, 4}}
	b, err := EncodeG2Packet(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Type, p.Type) {
		t.Fatalf("type: %x != %x", got.Type, p.Type)
	}
	if !bytes.Equal(got.Payload, p.Payload) {
		t.Fatalf("payload mismatch")
	}
	if got.Compound {
		t.Fatal("unexpected compound")
	}
	if got.BigEndian {
		t.Fatal("unexpected big-endian")
	}
}

func TestG2PacketRoundTripNested(t *testing.T) {
	child1 := &G2Packet{Type: []byte("A"), Payload: []byte("hello")}
	child2 := &G2Packet{Type: []byte("BC"), Payload: []byte{0xff}}
	parent := &G2Packet{Type: []byte("Q2"), Compound: true, Children: []*G2Packet{child1, child2}}
	b, err := EncodeG2Packet(parent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Type, []byte("Q2")) {
		t.Fatalf("type %x", got.Type)
	}
	if !got.Compound {
		t.Fatal("expected compound")
	}
	if len(got.Children) != 2 {
		t.Fatalf("children %d", len(got.Children))
	}
	if !bytes.Equal(got.Children[0].Type, []byte("A")) || !bytes.Equal(got.Children[0].Payload, []byte("hello")) {
		t.Fatalf("child0 mismatch")
	}
	if !bytes.Equal(got.Children[1].Type, []byte("BC")) || !bytes.Equal(got.Children[1].Payload, []byte{0xff}) {
		t.Fatalf("child1 mismatch")
	}
	// re-encode stability
	b2, err := EncodeG2Packet(got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatalf("re-encode mismatch")
	}
}

func TestG2PacketDeepNesting(t *testing.T) {
	inner := &G2Packet{Type: []byte("IN"), Payload: []byte{9}}
	mid := &G2Packet{Type: []byte("MD"), Compound: true, Children: []*G2Packet{inner}}
	outer := &G2Packet{Type: []byte("OU"), Compound: true, Children: []*G2Packet{mid}}
	b, err := EncodeG2Packet(outer)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Children) != 1 || len(got.Children[0].Children) != 1 {
		t.Fatalf("nesting lost")
	}
	if !bytes.Equal(got.Children[0].Children[0].Payload, []byte{9}) {
		t.Fatalf("inner payload lost")
	}
}

func TestG2PacketBigEndian(t *testing.T) {
	p := &G2Packet{Type: []byte("X"), BigEndian: true, Payload: make([]byte, 300)}
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
	// length bytes should be big-endian
	if b[1] != 0x01 || b[2] != 0x2c {
		t.Fatalf("not big-endian length: % x", b[1:3])
	}
}

func TestG2PacketLittleEndian(t *testing.T) {
	p := &G2Packet{Type: []byte("X"), BigEndian: false, Payload: make([]byte, 300)}
	b, err := EncodeG2Packet(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if got.BigEndian {
		t.Fatal("unexpected big-endian")
	}
	if b[1] != 0x2c || b[2] != 0x01 {
		t.Fatalf("not little-endian length: % x", b[1:3])
	}
}

func TestG2PacketLengthWidths(t *testing.T) {
	for _, n := range []int{1, 2, 255, 256, 65535, 65536, 0xFFFFFF} {
		if n > MaxG2Length {
			continue
		}
		payload := make([]byte, n)
		p := &G2Packet{Type: []byte("L"), Payload: payload}
		b, err := EncodeG2Packet(p)
		if err != nil {
			t.Fatalf("n=%d encode: %v", n, err)
		}
		// verify length width
		nLenLen := (b[0] & 0xC0) >> 6
		wantWidth := 1
		if n > 0xFF {
			wantWidth = 2
		}
		if n > 0xFFFF {
			wantWidth = 3
		}
		if int(nLenLen) != wantWidth {
			t.Fatalf("n=%d width %d want %d", n, nLenLen, wantWidth)
		}
		got, err := DecodeG2Packet(b)
		if err != nil {
			t.Fatalf("n=%d decode: %v", n, err)
		}
		if len(got.Payload) != n {
			t.Fatalf("n=%d got %d", n, len(got.Payload))
		}
	}
}

func TestG2PacketTypeLengths(t *testing.T) {
	for tl := 1; tl <= 8; tl++ {
		typ := make([]byte, tl)
		for i := range typ {
			typ[i] = byte('A' + i)
		}
		p := &G2Packet{Type: typ, Payload: []byte{7}}
		b, err := EncodeG2Packet(p)
		if err != nil {
			t.Fatalf("tl=%d encode: %v", tl, err)
		}
		nTypeLen := ((b[0] & 0x38) >> 3) + 1
		if int(nTypeLen) != tl {
			t.Fatalf("tl=%d encoded type len %d", tl, nTypeLen)
		}
		got, err := DecodeG2Packet(b)
		if err != nil {
			t.Fatalf("tl=%d decode: %v", tl, err)
		}
		if !bytes.Equal(got.Type, typ) {
			t.Fatalf("tl=%d type mismatch", tl)
		}
	}
}

func TestG2PacketBoundaryLength(t *testing.T) {
	// 1-byte max
	p := &G2Packet{Type: []byte("T"), Payload: make([]byte, 255)}
	b, _ := EncodeG2Packet(p)
	if (b[0]&0xC0)>>6 != 1 {
		t.Fatal("255 should be 1-byte length")
	}
	// 2-byte min
	p2 := &G2Packet{Type: []byte("T"), Payload: make([]byte, 256)}
	b2, _ := EncodeG2Packet(p2)
	if (b2[0]&0xC0)>>6 != 2 {
		t.Fatal("256 should be 2-byte length")
	}
	// 3-byte min
	p3 := &G2Packet{Type: []byte("T"), Payload: make([]byte, 65536)}
	b3, _ := EncodeG2Packet(p3)
	if (b3[0]&0xC0)>>6 != 3 {
		t.Fatal("65536 should be 3-byte length")
	}
}

func TestG2PacketMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x40},             // length width 1 but no type/payload
		{0x40 | 0x08, 0x05, 'A', 1, 2}, // truncated payload
		{0xC0 | 0x08, 0x00, 0x00, 0x05, 'C'}, // truncated
	}
	for _, c := range cases {
		if _, err := DecodeG2Packet(c); err == nil {
			t.Fatalf("expected error for % x", c)
		}
	}
	// truncated nested: parent compound claims child but cut
	parent := &G2Packet{Type: []byte("P"), Compound: true, Children: []*G2Packet{{Type: []byte("C"), Payload: []byte("abc")}}}
	b, _ := EncodeG2Packet(parent)
	if _, err := DecodeG2Packet(b[:len(b)-1]); err == nil {
		t.Fatal("expected truncated error")
	}
	// trailing bytes
	if _, err := DecodeG2Packet(append(append([]byte{}, b...), 0x41, 0x00, 'Z')); err == nil {
		// trailing zero header is invalid -> error expected; if no error fail
		t.Fatal("expected trailing error")
	}
	// length too large claim (width says 1 byte length 255 but only 0 payload)
	bad := []byte{0x40 | 0x08, 0xFF, 'A'}
	if _, err := DecodeG2Packet(bad); err == nil {
		t.Fatal("expected truncated")
	}
	// bad length width 0
	if _, err := DecodeG2Packet([]byte{0x08, 'A'}); err == nil {
		t.Fatal("expected bad length width")
	}
	// bad type len too big? encoded type len 7 => 8 ok; 8 impossible in 3 bits max 7.
}

func TestG2PacketMalformedLengthMismatch(t *testing.T) {
	data := []byte{0x41, 0x05, 'A', 1, 2}
	if _, err := DecodeG2Packet(data); err == nil {
		t.Fatal("expected truncated")
	}
}

func TestG2PacketMalformedCompound(t *testing.T) {
	// compound flag set but payload not valid children
	data := []byte{0x44, 0x02, 'P', 0x00, 0x00} // compound, len 2, type P, payload 00 00
	if _, err := DecodeG2Packet(data); err == nil {
		t.Fatal("expected compound parse error")
	}
}

func TestG2PacketTrailingRejected(t *testing.T) {
	b := []byte{0x41, 0x01, 'P', 42}
	if _, err := DecodeG2Packet(append(append([]byte{}, b...), b...)); err == nil {
		t.Fatal("expected trailing rejection")
	}
}

func TestG2PacketValueAndPointer(t *testing.T) {
	p := G2Packet{Type: []byte("V"), Payload: []byte{1}}
	b, err := EncodeG2Packet(p)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	b2, err := EncodeG2Packet(*got)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, b2) {
		t.Fatal("mismatch")
	}
}

func TestG2PacketReader(t *testing.T) {
	p := &G2Packet{Type: []byte("R"), Payload: []byte{5, 6}}
	b, _ := EncodeG2Packet(p)
	got, err := DecodeG2Packet(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, []byte{5, 6}) {
		t.Fatal("payload mismatch")
	}
}

func TestG2PacketEndiannessChild(t *testing.T) {
	child := &G2Packet{Type: []byte("C"), BigEndian: true, Payload: make([]byte, 300)}
	parent := &G2Packet{Type: []byte("P"), Compound: true, Children: []*G2Packet{child}, BigEndian: false}
	b, err := EncodeG2Packet(parent)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeG2Packet(b)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Children[0].BigEndian {
		t.Fatal("child bigendian lost")
	}
}

func FuzzDecodeG2Packet(f *testing.F) {
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
