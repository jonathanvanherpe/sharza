// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
)

func TestEncodeDecodeNeighbourHubRoundTripIPv4(t *testing.T) {
	nh := NeighbourHub{
		NodeAddress: NodeAddress{IP: net.IPv4(127, 0, 0, 1), Port: 6346},
		HubStatus:   HubStatus{LeafCount: 7},
	}
	enc := EncodeNeighbourHub(nh)
	if len(enc) == 0 {
		t.Fatal("empty encode")
	}
	dec, err := DecodeNeighbourHub(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !dec.NodeAddress.IP.Equal(nh.NodeAddress.IP) {
		t.Errorf("ip mismatch: %v vs %v", dec.IP, nh.IP)
	}
	if dec.Port != nh.Port {
		t.Errorf("port: %d vs %d", dec.Port, nh.Port)
	}
	if dec.LeafCount != nh.LeafCount {
		t.Errorf("leaf count: %d vs %d", dec.LeafCount, nh.LeafCount)
	}
	enc2 := EncodeNeighbourHub(dec)
	if !bytes.Equal(enc, enc2) {
		t.Errorf("re-encode mismatch")
	}
}

func TestEncodeDecodeNeighbourHubRoundTripIPv6(t *testing.T) {
	ip := net.ParseIP("2001:db8::1")
	nh := NeighbourHub{
		NodeAddress: NodeAddress{IP: ip, Port: 6346},
		HubStatus:   HubStatus{LeafCount: 42},
	}
	enc := EncodeNeighbourHub(nh)
	dec, err := DecodeNeighbourHub(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !dec.IP.Equal(ip) {
		t.Errorf("ip mismatch")
	}
	if dec.Port != 6346 {
		t.Errorf("port %d", dec.Port)
	}
	if dec.LeafCount != 42 {
		t.Errorf("leaf %d", dec.LeafCount)
	}
}

func TestEncodeDecodeCachedHubRoundTrip(t *testing.T) {
	ch := CachedHub{
		NodeAddress: NodeAddress{IP: net.IPv4(192, 168, 1, 2), Port: 6347},
		HubStatus:   HubStatus{LeafCount: 3},
	}
	enc := EncodeCachedHub(ch)
	dec, err := DecodeCachedHub(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if !dec.IP.Equal(ch.IP) || dec.Port != ch.Port || dec.LeafCount != ch.LeafCount {
		t.Errorf("mismatch: %+v vs %+v", dec, ch)
	}
	enc2 := EncodeCachedHub(dec)
	if !bytes.Equal(enc, enc2) {
		t.Errorf("re-encode mismatch")
	}
}

func TestDecodeHubMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		{0x40},
	}
	for _, c := range cases {
		if _, err := DecodeNeighbourHub(c); err == nil {
			t.Errorf("NH: expected error for % x", c)
		}
		if _, err := DecodeCachedHub(c); err == nil {
			t.Errorf("CH: expected error for % x", c)
		}
	}
	nh := &G2Packet{Type: "XX", Compound: true, Children: []*G2Packet{
		{Type: "NA", Payload: make([]byte, 6)},
		{Type: "HS", Payload: []byte{0, 1}},
	}}
	b, _ := EncodeG2Packet(nh)
	if _, err := DecodeNeighbourHub(b); err == nil {
		t.Error("expected bad type error")
	}
	nh2 := &G2Packet{Type: "NH", Compound: true, Children: []*G2Packet{
		{Type: "HS", Payload: []byte{0, 1}},
	}}
	b2, _ := EncodeG2Packet(nh2)
	if _, err := DecodeNeighbourHub(b2); err == nil {
		t.Error("expected missing address error")
	}
	nh3 := &G2Packet{Type: "NH", Compound: true, Children: []*G2Packet{
		{Type: "NA", Payload: make([]byte, 5)},
	}}
	b3, _ := EncodeG2Packet(nh3)
	if _, err := DecodeNeighbourHub(b3); err == nil {
		t.Error("expected bad address error")
	}
	nh4 := &G2Packet{Type: "NH", Compound: true, Children: []*G2Packet{
		{Type: "NA", Payload: make([]byte, 6)},
		{Type: "HS", Payload: []byte{0}},
	}}
	b4, _ := EncodeG2Packet(nh4)
	if _, err := DecodeNeighbourHub(b4); err == nil {
		t.Error("expected bad status error")
	}
}

func TestNodeAddressRoundTrip(t *testing.T) {
	na := NodeAddress{IP: net.IPv4(10, 0, 0, 1), Port: 1234}
	enc := EncodeNodeAddress(na)
	dec, err := DecodeNodeAddress(enc)
	if err != nil {
		t.Fatal(err)
	}
	if !dec.IP.Equal(na.IP) || dec.Port != na.Port {
		t.Errorf("mismatch")
	}
	na6 := NodeAddress{IP: net.ParseIP("::1"), Port: 5678}
	enc6 := EncodeNodeAddress(na6)
	if len(enc6) != 18 {
		t.Fatalf("len %d", len(enc6))
	}
	dec6, err := DecodeNodeAddress(enc6)
	if err != nil {
		t.Fatal(err)
	}
	if !dec6.IP.Equal(na6.IP) || dec6.Port != na6.Port {
		t.Errorf("v6 mismatch")
	}
}

func TestHubStatusRoundTrip(t *testing.T) {
	hs := HubStatus{LeafCount: 0xABCD}
	enc := EncodeHubStatus(hs)
	if len(enc) != 2 {
		t.Fatalf("len %d", len(enc))
	}
	if binary.BigEndian.Uint16(enc) != 0xABCD {
		t.Fatal("not big-endian")
	}
	dec, err := DecodeHubStatus(enc)
	if err != nil {
		t.Fatal(err)
	}
	if dec.LeafCount != hs.LeafCount {
		t.Errorf("mismatch")
	}
}

func FuzzG2HubRoundTrip(f *testing.F) {
	nh := NeighbourHub{NodeAddress: NodeAddress{IP: net.IPv4(1, 2, 3, 4), Port: 5}, HubStatus: HubStatus{LeafCount: 6}}
	f.Add(EncodeNeighbourHub(nh))
	ch := CachedHub{NodeAddress: NodeAddress{IP: net.IPv4(5, 6, 7, 8), Port: 9}, HubStatus: HubStatus{LeafCount: 10}}
	f.Add(EncodeCachedHub(ch))
	f.Add([]byte{})
	f.Add(make([]byte, 6))

	f.Fuzz(func(t *testing.T, b []byte) {
		if h, err := DecodeNeighbourHub(b); err == nil {
			enc := EncodeNeighbourHub(h)
			h2, err2 := DecodeNeighbourHub(enc)
			if err2 != nil {
				t.Fatalf("re-decode NH failed: %v", err2)
			}
			if !hubEqual(h, h2) {
				t.Errorf("NH round-trip mismatch: %+v vs %+v", h, h2)
			}
		}
		if h, err := DecodeCachedHub(b); err == nil {
			enc := EncodeCachedHub(h)
			h2, err2 := DecodeCachedHub(enc)
			if err2 != nil {
				t.Fatalf("re-decode CH failed: %v", err2)
			}
			if !hubEqualCached(h, h2) {
				t.Errorf("CH round-trip mismatch: %+v vs %+v", h, h2)
			}
		}
	})
}

func hubEqual(a, b NeighbourHub) bool {
	return a.NodeAddress.IP.Equal(b.NodeAddress.IP) && a.NodeAddress.Port == b.NodeAddress.Port && a.HubStatus.LeafCount == b.HubStatus.LeafCount
}

func hubEqualCached(a, b CachedHub) bool {
	return a.NodeAddress.IP.Equal(b.NodeAddress.IP) && a.NodeAddress.Port == b.NodeAddress.Port && a.HubStatus.LeafCount == b.HubStatus.LeafCount
}
