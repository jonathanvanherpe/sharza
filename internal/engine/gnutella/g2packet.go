// SPDX-License-Identifier: GPL-3.0-or-later

// G2 packet-tree codec, following Shareaza's CG2Packet (shareaza/G2Packet.cpp,
// shareaza/G2Packet.h) and the published G2 specification at g2.doxu.org.
//
// A G2 packet is: one control byte, a variable-length payload size, the
// packet type (1..8 ASCII bytes) and the payload. For a compound packet the
// payload is a run of sub-packets; for a leaf it is opaque bytes. G2 packet
// types are ASCII names carried in a 64-bit value with trailing-zero
// elision, so the type occupies only as many wire bytes as it has
// significant characters.

package gnutella

import (
	"encoding/binary"
	"errors"
)

// G2PacketType is a G2 packet type code: up to eight ASCII bytes packed
// little-endian, so the first character is the least significant byte. This
// mirrors Shareaza's G2_PACKET QWORD form and its G2_TYPE_LEN elision: the
// wire form is the low bytes up to and including the highest non-zero byte.
type G2PacketType uint64

// TypeBytes returns the packet type as ASCII bytes with trailing zero bytes
// elided. It returns nil for the null type.
func (t G2PacketType) TypeBytes() []byte {
	v := uint64(t)
	if v == 0 {
		return nil
	}
	n := 8
	for n > 1 && byte(v>>(uint(n-1)*8)) == 0 {
		n--
	}
	b := make([]byte, n)
	for i := 0; i < n; i++ {
		b[i] = byte(v >> (uint(i) * 8))
	}
	return b
}

// String returns the ASCII name of the packet type, or "" for the null type.
func (t G2PacketType) String() string {
	return string(t.TypeBytes())
}

// G2 packet type codes. The comment on each line is the wire ASCII name.
const (
	G2PacketNull G2PacketType = 0x0000000000000000 // 
	G2PacketBody G2PacketType = 0x0000000059444F42 // BODY
	G2PacketBogus G2PacketType = 0x0000005355474F42 // BOGUS
	G2PacketBrowseHost G2PacketType = 0x0000000000004842 // BH
	G2PacketBrowseProfile G2PacketType = 0x0000000000505542 // BUP
	G2PacketCachedHub G2PacketType = 0x0000000000004843 // CH
	G2PacketCachedSources G2PacketType = 0x0000000000435343 // CSC
	G2PacketChatAccept G2PacketType = 0x0000545045434341 // ACCEPT
	G2PacketChatAction G2PacketType = 0x0000000000544341 // ACT
	G2PacketChatAnswer G2PacketType = 0x00534E4154414843 // CHATANS
	G2PacketChatAway G2PacketType = 0x0000000059415741 // AWAY
	G2PacketChatDeny G2PacketType = 0x00000000594E4544 // DENY
	G2PacketChatMessage G2PacketType = 0x0000000047534D43 // CMSG
	G2PacketChatRequest G2PacketType = 0x0051455254414843 // CHATREQ
	G2PacketCollection G2PacketType = 0x005443454C4C4F43 // COLLECT
	G2PacketComment G2PacketType = 0x00000000004D4F43 // COM
	G2PacketCrawlAns G2PacketType = 0x0000414C57415243 // CRAWLA
	G2PacketCrawlReq G2PacketType = 0x0000524C57415243 // CRAWLR
	G2PacketCrawlRExt G2PacketType = 0x0000000054584552 // REXT
	G2PacketCrawlRGps G2PacketType = 0x0000000053504752 // RGPS
	G2PacketCrawlRLeaf G2PacketType = 0x0000004641454C52 // RLEAF
	G2PacketCrawlRName G2PacketType = 0x000000454D414E52 // RNAME
	G2PacketDescriptiveName G2PacketType = 0x0000000000004E44 // DN
	G2PacketDiscovery G2PacketType = 0x0000000000534944 // DIS
	G2PacketDiscoveryAns G2PacketType = 0x0000004143534944 // DISCA
	G2PacketDiscoveryHub G2PacketType = 0x0000004843534944 // DISCH
	G2PacketDiscoveryLog G2PacketType = 0x0000004C43534944 // DISCL
	G2PacketDiscoveryReq G2PacketType = 0x0000005243534944 // DISCR
	G2PacketFiles G2PacketType = 0x00000053454C4946 // FILES
	G2PacketFromAddress G2PacketType = 0x0000000000005246 // FR
	G2PacketFW G2PacketType = 0x0000000000005746 // FW
	G2PacketG1 G2PacketType = 0x0000000000003147 // G1
	G2PacketGPS G2PacketType = 0x0000000000535047 // GPS
	G2PacketGroupID G2PacketType = 0x0000000000000047 // G
	G2PacketHAW G2PacketType = 0x0000000000574148 // HAW
	G2PacketHit G2PacketType = 0x0000000000324851 // QH2
	G2PacketHitDescriptor G2PacketType = 0x0000000000000048 // H
	G2PacketHitGroup G2PacketType = 0x0000000000004748 // HG
	G2PacketHitWrap G2PacketType = 0x0000000000314851 // QH1
	G2PacketHitAlt G2PacketType = 0x0000000000544C41 // ALT
	G2PacketHitCreationTime G2PacketType = 0x0000000000005443 // CT
	G2PacketHorizon G2PacketType = 0x0000000000000053 // S
	G2PacketHub G2PacketType = 0x0000000000425548 // HUB
	G2PacketHubStatus G2PacketType = 0x0000000000005348 // HS
	G2PacketInterest G2PacketType = 0x0000000000000049 // I
	G2PacketKHL G2PacketType = 0x00000000004C484B // KHL
	G2PacketKHLAns G2PacketType = 0x00000000414C484B // KHLA
	G2PacketKHLReq G2PacketType = 0x00000000524C484B // KHLR
	G2PacketLeaf G2PacketType = 0x000000004641454C // LEAF
	G2PacketLibraryStatus G2PacketType = 0x000000000000534C // LS
	G2PacketLNI G2PacketType = 0x0000000000494E4C // LNI
	G2PacketMetadata G2PacketType = 0x000000000000444D // MD
	G2PacketNAME G2PacketType = 0x00000000454D414E // NAME
	G2PacketNeighbourHub G2PacketType = 0x000000000000484E // NH
	G2PacketNeighbourLeaf G2PacketType = 0x0000000000004C4E // NL
	G2PacketNick G2PacketType = 0x000000004B43494E // NICK
	G2PacketNodeAddress G2PacketType = 0x000000000000414E // NA
	G2PacketNodeGUID G2PacketType = 0x0000000000005547 // GU
	G2PacketNodeInfo G2PacketType = 0x000000000000494E // NI
	G2PacketObjectID G2PacketType = 0x0000000000004449 // ID
	G2PacketPART G2PacketType = 0x0000000054524150 // PART
	G2PacketPeerBusy G2PacketType = 0x0000000059535542 // BUSY
	G2PacketPeerChat G2PacketType = 0x0000000000484350 // PCH
	G2PacketPeerFirewalled G2PacketType = 0x0000000000005746 // FW
	G2PacketPeerStatus G2PacketType = 0x0000000000005353 // SS
	G2PacketPeerUnstable G2PacketType = 0x0000004154534E55 // UNSTA
	G2PacketPhysicalFolder G2PacketType = 0x0000000000004650 // PF
	G2PacketPing G2PacketType = 0x0000000000004950 // PI
	G2PacketPong G2PacketType = 0x0000000000004F50 // PO
	G2PacketPreviewURL G2PacketType = 0x0000000000555650 // PVU
	G2PacketProfile G2PacketType = 0x000000004F525055 // UPRO
	G2PacketProfileAvatar G2PacketType = 0x525456414F525055 // UPROAVTR
	G2PacketProfileChallenge G2PacketType = 0x000000434F525055 // UPROC
	G2PacketProfileDelivery G2PacketType = 0x000000444F525055 // UPROD
	G2PacketPush G2PacketType = 0x0000000048535550 // PUSH
	G2PacketQHT G2PacketType = 0x0000000000544851 // QHT
	G2PacketQKY G2PacketType = 0x0000000000594B51 // QKY
	G2PacketQUERY G2PacketType = 0x0000000000003251 // Q2
	G2PacketQueryAck G2PacketType = 0x0000000000004151 // QA
	G2PacketQueryAddress G2PacketType = 0x0000000000414E51 // QNA
	G2PacketQueryCached G2PacketType = 0x0000444548434143 // CACHED
	G2PacketQueryDone G2PacketType = 0x0000000000000044 // D
	G2PacketQueryKey G2PacketType = 0x0000000000004B51 // QK
	G2PacketQueryKeyAns G2PacketType = 0x0000000000414B51 // QKA
	G2PacketQueryKeyReq G2PacketType = 0x0000000000524B51 // QKR
	G2PacketQueryRefresh G2PacketType = 0x0000000000464552 // REF
	G2PacketQuerySearch G2PacketType = 0x0000000000000053 // S
	G2PacketQueryWrap G2PacketType = 0x0000000000003151 // Q1
	G2PacketRelay G2PacketType = 0x00000059414C4552 // RELAY
	G2PacketRequestAddress G2PacketType = 0x0000000000414E52 // RNA
	G2PacketRetryAfter G2PacketType = 0x0000000000004152 // RA
	G2PacketSelf G2PacketType = 0x00000000464C4553 // SELF
	G2PacketSendAddress G2PacketType = 0x0000000000414E53 // SNA
	G2PacketSIZE G2PacketType = 0x0000000000005A53 // SZ
	G2PacketSizeRestriction G2PacketType = 0x0000000000525A53 // SZR
	G2PacketTimestamp G2PacketType = 0x0000000000005354 // TS
	G2PacketTO G2PacketType = 0x0000000000004F54 // TO
	G2PacketUDP G2PacketType = 0x0000000000504455 // UDP
	G2PacketURL G2PacketType = 0x00000000004C5255 // URL
	G2PacketURN G2PacketType = 0x00000000004E5255 // URN
	G2PacketUserGUID G2PacketType = 0x4449554752455355 // USERGUID
	G2PacketVendor G2PacketType = 0x0000000000000056 // V
	G2PacketVersion G2PacketType = 0x0000000000005643 // CV
	G2PacketVirtualFolder G2PacketType = 0x0000000000004656 // VF
	G2PacketXML G2PacketType = 0x00000000004C4D58 // XML
)

// Control-byte flag bits (G2Packet.h).
const (
	g2FlagBigEndian = 0x02
	g2FlagCompound  = 0x04
)

// Limits chosen for this codec.
const (
	// MaxG2PayloadSize caps a single packet's payload. G2 payloads are
	// small; the largest routine ones (a KHL block, a QH2 hit) are tens
	// of kilobytes. The cap is well below the 3-byte length field's
	// 0xFFFFFF ceiling so the size field is always representable.
	MaxG2PayloadSize = 8 << 20

	// MaxG2NestingDepth caps compound recursion so a hostile packet
	// cannot drive unbounded recursion.
	MaxG2NestingDepth = 32
)

// Codec errors. Every function in this file reports malformed input through
// one of these rather than panicking.
var (
	ErrG2Truncated     = errors.New("g2packet: truncated packet")
	ErrG2AbsurdLength  = errors.New("g2packet: payload length exceeds maximum")
	ErrG2BadControl    = errors.New("g2packet: invalid control byte")
	ErrG2NonCanonical  = errors.New("g2packet: non-canonical packet encoding")
	ErrG2NullType      = errors.New("g2packet: null packet type")
	ErrG2NestingDepth  = errors.New("g2packet: maximum nesting depth exceeded")
	ErrG2LeafChildren  = errors.New("g2packet: non-compound packet has child packets")
	ErrG2BodyCompound  = errors.New("g2packet: compound packet has a leaf body")
	ErrG2TrailingBytes = errors.New("g2packet: trailing bytes after packet")
)

// G2Packet is one node of a G2 packet tree. A node is either a leaf, holding
// raw payload bytes in Body, or compound, holding sub-packets in Children.
// The two are mutually exclusive.
type G2Packet struct {
	Type      G2PacketType
	Compound  bool
	BigEndian bool

	// Body is the raw payload of a leaf packet.
	Body []byte

	// Children are the sub-packets of a compound packet.
	Children []*G2Packet
}

// NewG2Packet returns an empty packet of the given type.
func NewG2Packet(typ G2PacketType, compound bool) *G2Packet {
	return &G2Packet{Type: typ, Compound: compound}
}

// AddChild appends a sub-packet to a compound packet.
func (p *G2Packet) AddChild(c *G2Packet) {
	p.Children = append(p.Children, c)
}

// WriteString appends s to the leaf body followed by a NUL terminator. G2
// strings embedded in payloads are null-terminated.
func (p *G2Packet) WriteString(s string) {
	p.Body = append(p.Body, s...)
	p.Body = append(p.Body, 0)
}

// WriteBytes appends raw bytes to the leaf body.
func (p *G2Packet) WriteBytes(b []byte) {
	p.Body = append(p.Body, b...)
}

// ReadBytes returns n bytes of the leaf body starting at off, along with the
// offset just past them. It reports ErrG2Truncated when the body is short.
func (p *G2Packet) ReadBytes(off, n int) ([]byte, int, error) {
	if off < 0 || n < 0 || off+n > len(p.Body) {
		return nil, off, ErrG2Truncated
	}
	return p.Body[off : off+n], off + n, nil
}

// ReadString reads a NUL-terminated string from the leaf body starting at
// off, returning the string and the offset just past the terminator. When no
// terminator is present the remainder of the body is returned, matching a
// lenient read of the final field of a payload.
func (p *G2Packet) ReadString(off int) (string, int, error) {
	if off < 0 || off > len(p.Body) {
		return "", off, ErrG2Truncated
	}
	rest := p.Body[off:]
	for i, b := range rest {
		if b == 0 {
			return string(rest[:i]), off + i + 1, nil
		}
	}
	return string(rest), len(p.Body), nil
}

// Encode serialises the packet tree to its wire form.
func (p *G2Packet) Encode() ([]byte, error) {
	return p.encode(0)
}

func (p *G2Packet) encode(depth int) ([]byte, error) {
	if depth > MaxG2NestingDepth {
		return nil, ErrG2NestingDepth
	}
	typeBytes := p.Type.TypeBytes()
	if len(typeBytes) == 0 {
		return nil, ErrG2NullType
	}

	var payload []byte
	var flags byte
	if p.BigEndian {
		flags |= g2FlagBigEndian
	}
	if p.Compound {
		if len(p.Body) != 0 {
			return nil, ErrG2BodyCompound
		}
		flags |= g2FlagCompound
		for _, c := range p.Children {
			if c == nil {
				return nil, ErrG2NullType
			}
			cb, err := c.encode(depth + 1)
			if err != nil {
				return nil, err
			}
			payload = append(payload, cb...)
		}
	} else {
		if len(p.Children) != 0 {
			return nil, ErrG2LeafChildren
		}
		payload = p.Body
	}

	n := len(payload)
	if n > MaxG2PayloadSize {
		return nil, ErrG2AbsurdLength
	}
	lenLen := 1
	switch {
	case n > 0xFFFF:
		lenLen = 3
	case n > 0xFF:
		lenLen = 2
	}

	out := make([]byte, 0, 1+lenLen+len(typeBytes)+len(payload))
	ctrl := flags | byte(lenLen<<6) | byte((len(typeBytes)-1)<<3)
	out = append(out, ctrl)

	switch lenLen {
	case 1:
		out = append(out, byte(n))
	case 2:
		var b [2]byte
		if p.BigEndian {
			binary.BigEndian.PutUint16(b[:], uint16(n))
		} else {
			binary.LittleEndian.PutUint16(b[:], uint16(n))
		}
		out = append(out, b[:]...)
	case 3:
		if p.BigEndian {
			out = append(out, byte(n>>16), byte(n>>8), byte(n))
		} else {
			out = append(out, byte(n), byte(n>>8), byte(n>>16))
		}
	}
	out = append(out, typeBytes...)
	out = append(out, payload...)
	return out, nil

}

// Decode parses exactly one packet tree from b. It reports ErrG2TrailingBytes
// when b holds more than the single tree.
func Decode(b []byte) (*G2Packet, error) {
	p, n, err := decodePacket(b, 0)
	if err != nil {
		return nil, err
	}
	if n != len(b) {
		return nil, ErrG2TrailingBytes
	}
	return p, nil
}

// decodePacket parses one packet from the front of b and returns it with the
// number of bytes consumed.
func decodePacket(b []byte, depth int) (*G2Packet, int, error) {
	if depth > MaxG2NestingDepth {
		return nil, 0, ErrG2NestingDepth
	}
	if len(b) < 1 {
		return nil, 0, ErrG2Truncated
	}
	ctrl := b[0]
	if ctrl&0x01 != 0 {
		// Reserved bit must be clear.
		return nil, 0, ErrG2BadControl
	}
	lenLen := int(ctrl >> 6)
	typeLen := int(ctrl>>3)&0x07 + 1
	bigEndian := ctrl&g2FlagBigEndian != 0
	compound := ctrl&g2FlagCompound != 0

	if lenLen == 0 {
		return nil, 0, ErrG2BadControl
	}
	off := 1
	if off+lenLen > len(b) {
		return nil, 0, ErrG2Truncated
	}
	var payloadLen int
	if bigEndian {
		for i := 0; i < lenLen; i++ {
			payloadLen = payloadLen<<8 | int(b[off+i])
		}
	} else {
		for i := lenLen - 1; i >= 0; i-- {
			payloadLen = payloadLen<<8 | int(b[off+i])
		}
	}
	off += lenLen

	if payloadLen > MaxG2PayloadSize {
		return nil, 0, ErrG2AbsurdLength
	}
	// The size field must use the minimum number of bytes for the value,
	// otherwise the encoding is not canonically re-emittable.
	switch {
	case payloadLen > 0xFFFF:
		if lenLen != 3 {
			return nil, 0, ErrG2NonCanonical
		}
	case payloadLen > 0xFF:
		if lenLen != 2 {
			return nil, 0, ErrG2NonCanonical
		}
	default:
		if lenLen != 1 {
			return nil, 0, ErrG2NonCanonical
		}
	}

	if off+typeLen > len(b) {
		return nil, 0, ErrG2Truncated
	}
	var typ uint64
	for i := 0; i < typeLen; i++ {
		typ |= uint64(b[off+i]) << (uint(i) * 8)
	}
	if b[off+typeLen-1] == 0 {
		// The most significant type byte must be non-zero, or the type
		// is not in the canonical elided form.
		return nil, 0, ErrG2NonCanonical
	}
	off += typeLen

	if off+payloadLen > len(b) {
		return nil, 0, ErrG2Truncated
	}
	payload := b[off : off+payloadLen]
	off += payloadLen

	p := &G2Packet{Type: G2PacketType(typ), Compound: compound, BigEndian: bigEndian}
	if compound {
		rest := payload
		for len(rest) > 0 {
			child, cn, err := decodePacket(rest, depth+1)
			if err != nil {
				return nil, 0, err
			}
			p.Children = append(p.Children, child)
			rest = rest[cn:]
		}
	} else {
		if len(payload) > 0 {
			p.Body = append([]byte(nil), payload...)
		}
	}
	return p, off, nil
}

// Common G2 packet type aliases for convenience and compatibility.
const (
	G2PacketQH2 G2PacketType = G2PacketHit
	G2PacketH   G2PacketType = G2PacketHitDescriptor
	G2PacketNA  G2PacketType = G2PacketNodeAddress
	G2PacketGU  G2PacketType = G2PacketNodeGUID
	G2PacketNAMEalias G2PacketType = G2PacketNAME // NA/NAME semantics
	G2PacketCT  G2PacketType = G2PacketHitCreationTime
	G2PacketKHLA G2PacketType = G2PacketKHLAns
	G2PacketKHLR G2PacketType = G2PacketKHLReq
	G2PacketLEAFalias G2PacketType = G2PacketLeaf
	G2PacketCS  G2PacketType = G2PacketCachedSources
	G2PacketPARTalias G2PacketType = G2PacketPART
	G2PacketBODY G2PacketType = G2PacketBody
	G2PacketG1alias G2PacketType = G2PacketG1
	G2PacketPINGalias G2PacketType = G2PacketPing
	QH2 = G2PacketHit
	H   = G2PacketHitDescriptor
	NA  = G2PacketNodeAddress
	GU  = G2PacketNodeGUID
	NAME = G2PacketNAME
	CT  = G2PacketHitCreationTime
	KHL = G2PacketKHL
	KHLR = G2PacketKHLReq
	KHLA = G2PacketKHLAns
	LNI = G2PacketLNI
	HUB = G2PacketHub
	LEAF = G2PacketLeaf
	CS  = G2PacketCachedSources
	PART = G2PacketPART
	BODY = G2PacketBody
	G1  = G2PacketG1
)

// Additional short aliases.
const (
	G2PacketPING G2PacketType = G2PacketPing
	G2PacketPONG G2PacketType = G2PacketPong
	G2PacketQUERYalias G2PacketType = G2PacketQUERY
	G2PacketHUBalias   G2PacketType = G2PacketHub
)
