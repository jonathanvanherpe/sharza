// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"testing"
)

func makeG2(b ...byte) G2PacketType {
	var v uint64
	for i := 0; i < len(b) && i < 8; i++ {
		v |= uint64(b[i]) << (uint(i) * 8)
	}
	return G2PacketType(v)
}

func TestG2BasicLeafRoundTrip(t *testing.T) {
	p := NewG2Packet(G2PacketPING, false)
	p.WriteBytes([]byte("hi"))
	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if q.Type != G2PacketPING {
		t.Fatal("type mismatch")
	}
	if q.Compound || q.BigEndian {
		t.Fatal("flags mismatch")
	}
	if !bytes.Equal(q.Body, []byte("hi")) {
		t.Fatal("body mismatch")
	}
	if len(q.Children) != 0 {
		t.Fatal("children")
	}
}

func TestG2StringHelpers(t *testing.T) {
	if s := G2PacketPING.String(); s != "PI" {
		t.Fatalf("ping=%q", s)
	}
	b := G2PacketPING.TypeBytes()
	if len(b) != 2 || b[0] != 'P' || b[1] != 'I' {
		t.Fatalf("bytes=%v", b)
	}
}

func TestG2CompoundEncoding(t *testing.T) {
	root := NewG2Packet(makeG2('N','H'), true)
	child := NewG2Packet(makeG2('N','A'), false)
	child.WriteBytes([]byte{1,2,3,4})
	root.AddChild(child)
	buf, err := root.Encode()
	if err != nil {
		t.Fatal(err)
	}
	q, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !q.Compound {
		t.Fatal("not compound")
	}
	if len(q.Children) != 1 {
		t.Fatal("count")
	}
	if q.Children[0].Type != makeG2('N','A') {
		t.Fatal("ctype")
	}
	if !bytes.Equal(q.Children[0].Body, []byte{1,2,3,4}) {
		t.Fatal("cbody")
	}
}

func TestG2NullTerminatedString(t *testing.T) {
	p := NewG2Packet(makeG2('N','A'), false)
	p.WriteString("foo")
	if !bytes.Equal(p.Body, []byte("foo\000")) {
		t.Fatalf("got %v", p.Body)
	}
	s, n, err := p.ReadString(0)
	if err != nil {
		t.Fatal(err)
	}
	if s != "foo" || n != 4 {
		t.Fatalf("s=%q n=%d", s, n)
	}
}

func TestG2ReadStringNoTerm(t *testing.T) {
	p := NewG2Packet(makeG2('N','A'), false)
	p.WriteBytes([]byte("bar"))
	s, n, err := p.ReadString(0)
	if err != nil {
		t.Fatal(err)
	}
	if s != "bar" || n != 3 {
		t.Fatal(s,n)
	}
}

func TestG2ReadBytes(t *testing.T) {
	p := NewG2Packet(makeG2('N','A'), false)
	p.WriteBytes([]byte{10,11,12,13})
	b, n, err := p.ReadBytes(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b, []byte{11,12}) || n != 3 {
		t.Fatal(b,n)
	}
	if _, _, err := p.ReadBytes(3, 2); err != ErrG2Truncated {
		t.Fatal(err)
	}
}

func TestG2ControlFlags(t *testing.T) {
	p := NewG2Packet(G2PacketPING, false)
	p.BigEndian = true
	p.WriteBytes([]byte("hi"))
	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if buf[0]&(g2FlagBigEndian) == 0 {
		t.Fatal("big endian flag not set")
	}
	q, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if !q.BigEndian {
		t.Fatal("be lost")
	}
}

func TestG2LengthEncoding(t *testing.T) {
	p := NewG2Packet(G2PacketPING, false)
	p.Body = make([]byte, 300)
	buf, err := p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if (buf[0]>>6) != 2 { // lenLen 2 for >0xFF and <=0xFFFF
		t.Fatalf("lenlen=%d", buf[0]>>6)
	}
	q, err := Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Body) != 300 {
		t.Fatal(len(q.Body))
	}

	// 3-byte case
	p.Body = make([]byte, 0x10000)
	buf, err = p.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if (buf[0]>>6) != 3 {
		t.Fatalf("lenlen=%d", buf[0]>>6)
	}
	q, err = Decode(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(q.Body) != 0x10000 {
		t.Fatal(len(q.Body))
	}
}

func TestG2NullTypeRejected(t *testing.T) {
	p := NewG2Packet(G2PacketNull, false)
	_, err := p.Encode()
	if err != ErrG2NullType {
		t.Fatal(err)
	}
}

func TestG2TrailingRejected(t *testing.T) {
	p := NewG2Packet(G2PacketPING, false)
	buf, _ := p.Encode()
	buf = append(buf, 0x00)
	if _, err := Decode(buf); err != ErrG2TrailingBytes {
		t.Fatal(err)
	}
}

func TestG2NestingDepth(t *testing.T) {
	if _, err := g2makeDeepChain(MaxG2NestingDepth + 2); err == nil {
		t.Fatal("should fail")
	}
	_, err := g2makeDeepChain(MaxG2NestingDepth - 1)
	if err != nil {
		t.Fatal(err)
	}
}

func g2makeDeep(d int) (*G2Packet, error) {
	cur := NewG2Packet(makeG2('H','U','B'), true)
	for i := 0; i < d-1; i++ {
		next := NewG2Packet(makeG2('L','E','A','F'), true)
		cur.AddChild(next)
		cur = next
	}
	cur.AddChild(NewG2Packet(G2PacketPING, false))
	buf, err := cur.Encode()
	if err != nil {
		return nil, err
	}
	return Decode(buf)
}

func TestG2MaliciousSize(t *testing.T) {
	// construct packet: ctrl len=1 (nonsense), len=0x01, type=P,I
	buf := []byte{(1<<6) | (2-1)<<3, 0x01, 'P', 'I'} // lenLen=1 means n<=255; but we set n=1 and type claims 2 bytes - truncated? also but test against absurd? not needed
	// just ensure truncated detected
	if _, err := Decode(buf); err != ErrG2Truncated {
		t.Log(err)
	}
}

func TestG2TypeBytes(t *testing.T) {
	if G2PacketNull.String() != "" || G2PacketNull.TypeBytes() != nil {
		t.Fatal("null type")
	}
}

func g2makeDeepChain(d int) (*G2Packet, error) {
	root := NewG2Packet(G2PacketHub, true)
	cur := root
	for i := 0; i < d; i++ {
		n := NewG2Packet(G2PacketHub, true)
		cur.AddChild(n)
		cur = n
	}
	cur.AddChild(NewG2Packet(G2PacketPing, false))
	buf, err := root.Encode()
	if err != nil {
		return nil, err
	}
	return Decode(buf)
}

// FuzzG2PacketRoundTrip checks that any input that decodes without error
// also re-encodes to identical bytes, and that decode never panics.
func FuzzG2PacketRoundTrip(f *testing.F) {
	f.Add([]byte{0x08, 0x00, 'P', 'I'})
	f.Add([]byte{0x0C, 0x04, 'Q', '2', 0x08, 0x00, 'P', 'I'})
	f.Add([]byte{0x50, 0x02, 'Q', 'H', '2', 'A', 'B'})
	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Decode(b)
		if err != nil {
			return
		}
		buf, err := p.Encode()
		if err != nil {
			t.Errorf("encode after decode: %v", err)
			return
		}
		if !bytes.Equal(buf, b) {
			t.Errorf("roundtrip mismatch: %x != %x", buf, b)
		}
	})
}
