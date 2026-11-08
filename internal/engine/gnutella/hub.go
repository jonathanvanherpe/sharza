// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
)

// NodeAddress is the NODE_ADDRESS child of a Gnutella2 hub compound:
// an IPv4 address (4 bytes) plus a 2-byte port (6 bytes total) or an
// IPv6 address (16 bytes) plus a 2-byte port (18 bytes total). The
// IPv4 address is stored on the wire in little-endian order and the
// port in big-endian order, matching Shareaza's NODE_ADDRESS; the Go
// side keeps the address in network order.
type NodeAddress struct {
	IP   net.IP
	Port uint16
}

// HubStatus is the HUB_STATUS child of a Gnutella2 hub compound: a
// single 2-byte big-endian leaf count.
type HubStatus struct {
	LeafCount uint16
}

// NeighbourHub is the Go representation of the Gnutella2 NEIGHBOUR_HUB
// (NH) compound packet: a neighbouring hub's node address plus its leaf
// count.
type NeighbourHub struct {
	NodeAddress
	HubStatus
}

// CachedHub is the Go representation of the Gnutella2 CACHED_HUB (CH)
// compound packet: a cached hub's node address plus its leaf count.
type CachedHub struct {
	NodeAddress
	HubStatus
}

var (
	ErrHubBadType        = errors.New("gnutella: bad hub packet type")
	ErrHubMissingAddress = errors.New("gnutella: missing node address")
	ErrHubBadAddress     = errors.New("gnutella: malformed node address")
	ErrHubBadStatus      = errors.New("gnutella: malformed hub status")
	ErrHubTruncated      = errors.New("gnutella: truncated hub packet")
)

func isNeighbourHubType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "NH" || t == "NEIGHBOUR_HUB"
}

func isCachedHubType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "CH" || t == "CACHED_HUB"
}

func isNodeAddressType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "NA" || t == "NODE_ADDRESS"
}

func isHubStatusType(t string) bool {
	t = strings.ToUpper(strings.TrimSpace(t))
	return t == "HS" || t == "HUB_STATUS"
}

// EncodeNodeAddress encodes a NodeAddress to its wire form (6 or 18
// bytes).
func EncodeNodeAddress(na NodeAddress) []byte {
	ip := na.IP
	if ip == nil {
		ip = net.IPv4zero
	}
	if v4 := ip.To4(); v4 != nil && len(ip) == 4 {
		out := make([]byte, 6)
		binary.LittleEndian.PutUint32(out[0:4],
			uint32(v4[0]) | uint32(v4[1])<<8 | uint32(v4[2])<<16 | uint32(v4[3])<<24)
		binary.BigEndian.PutUint16(out[4:6], na.Port)
		return out
	}
	v6 := ip.To16()
	if v6 == nil {
		v6 = net.IPv6zero.To16()
	}
	out := make([]byte, 18)
	copy(out[0:16], v6)
	binary.BigEndian.PutUint16(out[16:18], na.Port)
	return out
}

// DecodeNodeAddress decodes a NodeAddress from its wire form.
func DecodeNodeAddress(b []byte) (NodeAddress, error) {
	switch len(b) {
	case 6:
		v := binary.LittleEndian.Uint32(b[0:4])
		return NodeAddress{
			IP:   net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v)),
			Port: binary.BigEndian.Uint16(b[4:6]),
		}, nil
	case 18:
		ip := make(net.IP, 16)
		copy(ip, b[0:16])
		return NodeAddress{
			IP:   ip,
			Port: binary.BigEndian.Uint16(b[16:18]),
		}, nil
	default:
		return NodeAddress{}, fmt.Errorf("%w: got %d bytes", ErrHubBadAddress, len(b))
	}
}

// EncodeHubStatus encodes a HubStatus to its 2-byte big-endian form.
func EncodeHubStatus(hs HubStatus) []byte {
	out := make([]byte, 2)
	binary.BigEndian.PutUint16(out, hs.LeafCount)
	return out
}

// DecodeHubStatus decodes a 2-byte big-endian HubStatus.
func DecodeHubStatus(b []byte) (HubStatus, error) {
	if len(b) != 2 {
		return HubStatus{}, fmt.Errorf("%w: got %d bytes", ErrHubBadStatus, len(b))
	}
	return HubStatus{LeafCount: binary.BigEndian.Uint16(b)}, nil
}

// hubFromPacket extracts a hub's fields from a compound G2Packet.
func hubFromPacket(pkt *G2Packet, want func(string) bool) (NodeAddress, uint16, error) {
	if pkt == nil {
		return NodeAddress{}, 0, ErrHubTruncated
	}
	if !want(pkt.Type) {
		return NodeAddress{}, 0, fmt.Errorf("%w: %q", ErrHubBadType, pkt.Type)
	}

	var na NodeAddress
	haveNA := false
	var leaf uint16
	haveHS := false

	for _, c := range pkt.Children {
		if c == nil {
			continue
		}
		if isNodeAddressType(c.Type) {
			got, err := DecodeNodeAddress(c.Payload)
			if err != nil {
				return NodeAddress{}, 0, err
			}
			if !haveNA {
				na = got
				haveNA = true
			}
		} else if isHubStatusType(c.Type) {
			got, err := DecodeHubStatus(c.Payload)
			if err != nil {
				return NodeAddress{}, 0, err
			}
			if !haveHS {
				leaf = got.LeafCount
				haveHS = true
			}
		}
	}

	if !haveNA && len(pkt.Payload) > 0 {
		if len(pkt.Payload) >= 6 {
			got, err := DecodeNodeAddress(pkt.Payload[:6])
			if err == nil {
				na = got
				haveNA = true
			} else if len(pkt.Payload) >= 18 {
				got2, err2 := DecodeNodeAddress(pkt.Payload[:18])
				if err2 == nil {
					na = got2
					haveNA = true
				}
			}
		}
	}

	if !haveNA {
		return NodeAddress{}, 0, ErrHubMissingAddress
	}
	return na, leaf, nil
}

// encodeHub builds the compound packet bytes for a hub.
func encodeHub(typ string, na NodeAddress, leaf uint16) []byte {
	pkt := &G2Packet{Type: typ, Compound: true, Children: []*G2Packet{
		{Type: "NA", Payload: EncodeNodeAddress(na)},
		{Type: "HS", Payload: EncodeHubStatus(HubStatus{LeafCount: leaf})},
	}}
	b, err := EncodeG2Packet(pkt)
	if err != nil {
		return nil
	}
	return b
}

// EncodeNeighbourHub encodes a NeighbourHub (or *NeighbourHub, or a
// *G2Packet) to its wire form.
func EncodeNeighbourHub(v any) []byte {
	switch x := v.(type) {
	case NeighbourHub:
		return encodeHub("NH", x.NodeAddress, x.LeafCount)
	case *NeighbourHub:
		if x == nil {
			return nil
		}
		return encodeHub("NH", x.NodeAddress, x.LeafCount)
	case *G2Packet:
		na, leaf, err := hubFromPacket(x, isNeighbourHubType)
		if err != nil {
			return nil
		}
		return encodeHub("NH", na, leaf)
	default:
		return nil
	}
}

// DecodeNeighbourHub decodes a NeighbourHub from bytes, string, io.Reader
// or *G2Packet.
func DecodeNeighbourHub(v any) (NeighbourHub, error) {
	var pkt *G2Packet
	switch x := v.(type) {
	case *G2Packet:
		pkt = x
	case []byte:
		got, err := DecodeG2Packet(x)
		if err != nil {
			return NeighbourHub{}, err
		}
		pkt = got
	case string:
		got, err := DecodeG2Packet([]byte(x))
		if err != nil {
			return NeighbourHub{}, err
		}
		pkt = got
	case io.Reader:
		b, err := io.ReadAll(x)
		if err != nil {
			return NeighbourHub{}, err
		}
		got, err := DecodeG2Packet(b)
		if err != nil {
			return NeighbourHub{}, err
		}
		pkt = got
	default:
		return NeighbourHub{}, fmt.Errorf("gnutella: unsupported hub input %T", v)
	}
	na, leaf, err := hubFromPacket(pkt, isNeighbourHubType)
	if err != nil {
		return NeighbourHub{}, err
	}
	return NeighbourHub{NodeAddress: na, HubStatus: HubStatus{LeafCount: leaf}}, nil
}

// EncodeCachedHub encodes a CachedHub (or *CachedHub, or a *G2Packet) to
// its wire form.
func EncodeCachedHub(v any) []byte {
	switch x := v.(type) {
	case CachedHub:
		return encodeHub("CH", x.NodeAddress, x.LeafCount)
	case *CachedHub:
		if x == nil {
			return nil
		}
		return encodeHub("CH", x.NodeAddress, x.LeafCount)
	case *G2Packet:
		na, leaf, err := hubFromPacket(x, isCachedHubType)
		if err != nil {
			return nil
		}
		return encodeHub("CH", na, leaf)
	default:
		return nil
	}
}

// DecodeCachedHub decodes a CachedHub from bytes, string, io.Reader or
// *G2Packet.
func DecodeCachedHub(v any) (CachedHub, error) {
	var pkt *G2Packet
	switch x := v.(type) {
	case *G2Packet:
		pkt = x
	case []byte:
		got, err := DecodeG2Packet(x)
		if err != nil {
			return CachedHub{}, err
		}
		pkt = got
	case string:
		got, err := DecodeG2Packet([]byte(x))
		if err != nil {
			return CachedHub{}, err
		}
		pkt = got
	case io.Reader:
		b, err := io.ReadAll(x)
		if err != nil {
			return CachedHub{}, err
		}
		got, err := DecodeG2Packet(b)
		if err != nil {
			return CachedHub{}, err
		}
		pkt = got
	default:
		return CachedHub{}, fmt.Errorf("gnutella: unsupported hub input %T", v)
	}
	na, leaf, err := hubFromPacket(pkt, isCachedHubType)
	if err != nil {
		return CachedHub{}, err
	}
	return CachedHub{NodeAddress: na, HubStatus: HubStatus{LeafCount: leaf}}, nil
}

// Aliases for convenience / compatibility with alternate naming.
func EncodeNH(v any) []byte            { return EncodeNeighbourHub(v) }
func DecodeNH(v any) (NeighbourHub, error) { return DecodeNeighbourHub(v) }
func EncodeCH(v any) []byte            { return EncodeCachedHub(v) }
func DecodeCH(v any) (CachedHub, error)   { return DecodeCachedHub(v) }

// EncodeNeighbourHubPacket returns a *G2Packet compound for a NeighbourHub.
func EncodeNeighbourHubPacket(h NeighbourHub) *G2Packet {
	return &G2Packet{Type: "NH", Compound: true, Children: []*G2Packet{
		{Type: "NA", Payload: EncodeNodeAddress(h.NodeAddress)},
		{Type: "HS", Payload: EncodeHubStatus(h.HubStatus)},
	}}
}

// EncodeCachedHubPacket returns a *G2Packet compound for a CachedHub.
func EncodeCachedHubPacket(h CachedHub) *G2Packet {
	return &G2Packet{Type: "CH", Compound: true, Children: []*G2Packet{
		{Type: "NA", Payload: EncodeNodeAddress(h.NodeAddress)},
		{Type: "HS", Payload: EncodeHubStatus(h.HubStatus)},
	}}
}
