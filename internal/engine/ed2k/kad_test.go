// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func TestKadPacketRoundTrip(t *testing.T) {
	cases := []struct {
		name    string
		proto   byte
		op      byte
		payload []byte
	}{
		{"bootstrap", ProtocolKad, KAD_BOOTSTRAP_REQ, nil},
		{"ping", ProtocolKad, KAD_PING, nil},
		{"pong", ProtocolKad, KAD_PONG, []byte{0x01, 0x02}},
		{"search", ProtocolKad, KAD_SEARCH_KEY_REQ, []byte{0xaa, 0xbb}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			p := KadPacket{Protocol: c.proto, Opcode: c.op, Payload: c.payload}
			b := p.Marshal()
			g, err := DecodeKadPacket(b)
			if err != nil {
				t.Fatal(err)
			}
			if g.Protocol != c.proto {
				t.Fatalf("protocol mismatch")
			}
			if g.Opcode != c.op || g.Op != c.op || g.Type != c.op {
				t.Fatalf("opcode mismatch")
			}
			if !bytes.Equal(g.Payload, c.payload) {
				t.Fatalf("payload mismatch")
			}
			if !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("re-encode mismatch")
			}
		})
	}
}

func TestKadPacketMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0xE4},
	}
	for i, c := range cases {
		if _, err := DecodeKadPacket(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
}

func TestKadBootstrapReqRoundTrip(t *testing.T) {
	c := KadContact{ID: bytes16(1), IP: [4]byte{1, 2, 3, 4}, UDPPort: 4672, TCPPort: 4661, Version: 9}
	r := KadBootstrapReq{Peer: c}
	b := r.Marshal()
	g, err := DecodeKadBootstrapReq(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Peer.ID != c.ID {
		t.Fatalf("peer id mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatalf("re-encode mismatch")
	}
	if _, err := DecodeKadBootstrapReq([]byte{}); err != nil {
		t.Fatal(err)
	}
	b2 := KadBootstrapReq{}.Marshal()
	if len(b2) != 0 {
		t.Fatalf("empty marshal len %d", len(b2))
	}
}

func TestKadBootstrapResRoundTrip(t *testing.T) {
	c1 := KadContact{ID: bytes16(2), IP: [4]byte{5, 6, 7, 8}, UDPPort: 1000, TCPPort: 1001, Version: 9}
	c2 := KadContact{ID: bytes16(3), IP: [4]byte{9, 10, 11, 12}, UDPPort: 2000, TCPPort: 2001, Version: 9}
	r := KadBootstrapRes{ID: bytes16(1), TCPPort: 4661, Version: 9, Contacts: []KadContact{c1, c2}}
	b := r.Marshal()
	g, err := DecodeKadBootstrapRes(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != r.ID {
		t.Fatalf("id mismatch")
	}
	if len(g.Contacts) != 2 {
		t.Fatalf("contact count %d", len(g.Contacts))
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatalf("re-encode mismatch")
	}
	if _, err := DecodeKadBootstrapRes([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
}

func TestKadPingPongRoundTrip(t *testing.T) {
	p := KadPing{}
	b := p.Marshal()
	if len(b) != 0 {
		t.Fatalf("ping not empty")
	}
	if _, err := DecodeKadPing(b); err != nil {
		t.Fatal(err)
	}
	pp := KadPong{}
	bb := pp.Marshal()
	if _, err := DecodeKadPong(bb); err != nil {
		t.Fatal(err)
	}
}

func TestKadSearchReqRoundTrip(t *testing.T) {
	key := bytes16(5)
	r := KadSearchReq{Key: key, StartPosition: 0x8000, Expression: []byte{0x01, 0x02, 0x03}}
	b := r.Marshal()
	g, err := DecodeKadSearchReq(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Key != key {
		t.Fatalf("key mismatch")
	}
	if g.StartPosition != 0x8000 {
		t.Fatalf("start mismatch")
	}
	if !bytes.Equal(g.Expression, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("expr mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatalf("re-encode mismatch")
	}
	if _, err := DecodeKadSearchReq([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
	r2 := KadSearchReq{Key: key, StartPosition: 1}
	b2 := r2.Marshal()
	g2, err := DecodeKadSearchReq(b2)
	if err != nil {
		t.Fatal(err)
	}
	if g2.Expression != nil {
		t.Fatalf("expected nil expr")
	}
	if !bytes.Equal(g2.Marshal(), b2) {
		t.Fatalf("re-encode mismatch 2")
	}
}

func TestKadSearchResRoundTrip(t *testing.T) {
	tag := Tag{Type: 0x03, Key: 0x01, Value: 42}
	res := KadSearchResult{Hash: bytes16(7), Tags: []Tag{tag}}
	r := KadSearchRes{Target: bytes16(9), Results: []KadSearchResult{res}}
	b := r.Marshal()
	g, err := DecodeKadSearchRes(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Target != r.Target {
		t.Fatalf("target mismatch")
	}
	if len(g.Results) != 1 {
		t.Fatalf("results count %d", len(g.Results))
	}
	if g.Results[0].Hash != res.Hash {
		t.Fatalf("hash mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatalf("re-encode mismatch")
	}
	if _, err := DecodeKadSearchRes([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
	if _, err := DecodeKadSearchRes(make([]byte, 18)); err != nil {
		t.Fatalf("count zero decode: %v", err)
	}
}

func TestKadContactRoundTrip(t *testing.T) {
	c := KadContact{ID: bytes16(1), IP: [4]byte{1, 2, 3, 4}, UDPPort: 4672, TCPPort: 4661, Version: 9}
	b := c.Marshal()
	g, err := DecodeKadContact(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.ID != c.ID {
		t.Fatalf("id mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatalf("re-encode mismatch")
	}
	if _, err := DecodeKadContact([]byte{0x01}); err == nil {
		t.Fatal("expected error")
	}
}

func FuzzKadPacket(f *testing.F) {
	f.Add([]byte{0xE4, KAD_BOOTSTRAP_REQ})
	f.Add([]byte{0xE4, KAD_PING})
	f.Fuzz(func(t *testing.T, data []byte) {
		p, err := DecodeKadPacket(data)
		if err != nil {
			return
		}
		b := p.Marshal()
		g, err := DecodeKadPacket(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func bytes16(v byte) [16]byte {
	var out [16]byte
	out[0] = v
	out[15] = v
	return out
}
