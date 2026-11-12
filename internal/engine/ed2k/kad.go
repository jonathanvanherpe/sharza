// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Core Kad opcodes. Values follow eMule's opcodes.h (KADEMLIA2_*).
const (
	KAD_BOOTSTRAP_REQ     byte = 0x01
	KAD_BOOTSTRAP_RES     byte = 0x09
	KAD_PING              byte = 0x60
	KAD_PONG              byte = 0x61
	KAD_SEARCH_KEY_REQ    byte = 0x33
	KAD_SEARCH_SOURCE_REQ byte = 0x34
	KAD_SEARCH_NOTES_REQ  byte = 0x35
	KAD_SEARCH_REQ        byte = KAD_SEARCH_KEY_REQ
	KAD_SEARCH_RES        byte = 0x3B
)

const (
	KAD_BOOTSTRAP_REQ_V0    byte = 0x00
	KAD_BOOTSTRAP_RES_V0    byte = 0x08
	KAD_SEARCH_REQ_V1       byte = 0x30
	KAD_SEARCH_RES_V1       byte = 0x38
	KAD_SEARCH_NOTES_REQ_V1 byte = 0x32
)

const (
	OpKadBootstrapReq     = KAD_BOOTSTRAP_REQ
	OpKadBootstrapRes     = KAD_BOOTSTRAP_RES
	OpKadPing             = KAD_PING
	OpKadPong             = KAD_PONG
	OpKadSearchKeyReq     = KAD_SEARCH_KEY_REQ
	OpKadSearchSourceReq  = KAD_SEARCH_SOURCE_REQ
	OpKadSearchNotesReq   = KAD_SEARCH_NOTES_REQ
	OpKadSearchReq        = KAD_SEARCH_REQ
	OpKadSearchRes        = KAD_SEARCH_RES
)

const (
	OP_KAD_BOOTSTRAP_REQ     = KAD_BOOTSTRAP_REQ
	OP_KAD_BOOTSTRAP_RES     = KAD_BOOTSTRAP_RES
	OP_KAD_PING              = KAD_PING
	OP_KAD_PONG              = KAD_PONG
	OP_KAD_SEARCH_KEY_REQ    = KAD_SEARCH_KEY_REQ
	OP_KAD_SEARCH_SOURCE_REQ = KAD_SEARCH_SOURCE_REQ
	OP_KAD_SEARCH_NOTES_REQ  = KAD_SEARCH_NOTES_REQ
	OP_KAD_SEARCH_REQ        = KAD_SEARCH_REQ
	OP_KAD_SEARCH_RES        = KAD_SEARCH_RES
)

const (
	KADEMLIA2_BOOTSTRAP_REQ     = KAD_BOOTSTRAP_REQ
	KADEMLIA2_BOOTSTRAP_RES     = KAD_BOOTSTRAP_RES
	KADEMLIA2_PING              = KAD_PING
	KADEMLIA2_PONG              = KAD_PONG
	KADEMLIA2_SEARCH_KEY_REQ    = KAD_SEARCH_KEY_REQ
	KADEMLIA2_SEARCH_SOURCE_REQ = KAD_SEARCH_SOURCE_REQ
	KADEMLIA2_SEARCH_NOTES_REQ  = KAD_SEARCH_NOTES_REQ
	KADEMLIA2_SEARCH_RES        = KAD_SEARCH_RES
)

var (
	ErrKadPacket       = errors.New("ed2k: malformed kad packet")
	ErrKadTruncated    = errors.New("ed2k: truncated kad packet")
	ErrKadBootstrapReq = errors.New("ed2k: malformed kad bootstrap request")
	ErrKadBootstrapRes = errors.New("ed2k: malformed kad bootstrap response")
	ErrKadPing         = errors.New("ed2k: malformed kad ping")
	ErrKadPong         = errors.New("ed2k: malformed kad pong")
	ErrKadSearchReq    = errors.New("ed2k: malformed kad search request")
	ErrKadSearchRes    = errors.New("ed2k: malformed kad search response")
	ErrKadContact      = errors.New("ed2k: malformed kad contact")
	ErrKadSearchResult = errors.New("ed2k: malformed kad search result")
)

// KadPacket
type KadPacket struct {
	Protocol byte
	Opcode   byte
	Op       byte
	Type     byte
	Payload  []byte
	Data     []byte
	Body     []byte
}

func (p KadPacket) protocol() byte {
	if p.Protocol != 0 {
		return p.Protocol
	}
	return ProtocolKad
}
func (p KadPacket) opcode() byte {
	if p.Opcode != 0 {
		return p.Opcode
	}
	if p.Op != 0 {
		return p.Op
	}
	return p.Type
}
func (p KadPacket) payload() []byte {
	if p.Payload != nil {
		return p.Payload
	}
	if p.Data != nil {
		return p.Data
	}
	if p.Body != nil {
		return p.Body
	}
	return []byte{}
}
func (p KadPacket) Marshal() []byte {
	out := make([]byte, 2+len(p.payload()))
	out[0] = p.protocol()
	out[1] = p.opcode()
	copy(out[2:], p.payload())
	return out
}
func (p KadPacket) Encode() []byte { return p.Marshal() }
func (p KadPacket) Bytes() []byte  { return p.Marshal() }
func (p KadPacket) MarshalBinary() ([]byte, error) { return p.Marshal(), nil }
func (p KadPacket) AppendTo(dst []byte) []byte { return append(dst, p.Marshal()...) }
func DecodeKadPacket(b []byte) (KadPacket, error) {
	if len(b) < 2 {
		return KadPacket{}, fmt.Errorf("%w: %w", ErrKadPacket, ErrKadTruncated)
	}
	payload := make([]byte, len(b)-2)
	copy(payload, b[2:])
	cp := cloneBytes(payload)
	return KadPacket{Protocol: b[0], Opcode: b[1], Op: b[1], Type: b[1], Payload: payload, Data: cp, Body: cloneBytes(payload)}, nil
}
func ParseKadPacket(b []byte) (KadPacket, error) { return DecodeKadPacket(b) }
func (p *KadPacket) Unmarshal(b []byte) error {
	g, err := DecodeKadPacket(b)
	if err != nil {
		return err
	}
	*p = g
	return nil
}
func (p *KadPacket) Decode(b []byte) error { return p.Unmarshal(b) }

// KadContact
type KadContact struct {
	ID      [16]byte
	GUID    [16]byte
	Hash    [16]byte
	IP      [4]byte
	IPUint  uint32
	UDPPort uint16
	UDP     uint16
	TCPPort uint16
	TCP     uint16
	Port    uint16
	Version byte
	Ver     byte
}

func (c KadContact) idBytes() [16]byte {
	if c.ID != ([16]byte{}) {
		return c.ID
	}
	if c.GUID != ([16]byte{}) {
		return c.GUID
	}
	return c.Hash
}
func (c KadContact) ipBytes() [4]byte {
	if c.IP != ([4]byte{}) {
		return c.IP
	}
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], c.IPUint)
	return out
}
func (c KadContact) udpPort() uint16 {
	if c.UDPPort != 0 {
		return c.UDPPort
	}
	if c.UDP != 0 {
		return c.UDP
	}
	return c.Port
}
func (c KadContact) tcpPort() uint16 {
	if c.TCPPort != 0 {
		return c.TCPPort
	}
	if c.TCP != 0 {
		return c.TCP
	}
	return c.Port
}
func (c KadContact) versionByte() byte {
	if c.Version != 0 {
		return c.Version
	}
	return c.Ver
}
func (c KadContact) Marshal() []byte {
	out := make([]byte, 25)
	id := c.idBytes()
	copy(out[0:16], id[:])
	ip := c.ipBytes()
	copy(out[16:20], ip[:])
	binary.LittleEndian.PutUint16(out[20:22], c.udpPort())
	binary.LittleEndian.PutUint16(out[22:24], c.tcpPort())
	out[24] = c.versionByte()
	return out
}
func (c KadContact) Encode() []byte { return c.Marshal() }
func (c KadContact) Bytes() []byte  { return c.Marshal() }
func (c KadContact) MarshalBinary() ([]byte, error) { return c.Marshal(), nil }
func DecodeKadContact(b []byte) (KadContact, error) {
	if len(b) < 25 {
		return KadContact{}, fmt.Errorf("%w: %w", ErrKadContact, ErrKadTruncated)
	}
	var c KadContact
	copy(c.ID[:], b[0:16])
	c.GUID = c.ID
	c.Hash = c.ID
	copy(c.IP[:], b[16:20])
	c.IPUint = binary.LittleEndian.Uint32(b[16:20])
	c.UDPPort = binary.LittleEndian.Uint16(b[20:22])
	c.UDP = c.UDPPort
	c.TCPPort = binary.LittleEndian.Uint16(b[22:24])
	c.TCP = c.TCPPort
	c.Port = c.TCPPort
	c.Version = b[24]
	c.Ver = b[24]
	return c, nil
}
func ParseKadContact(b []byte) (KadContact, error) { return DecodeKadContact(b) }
func (c *KadContact) Unmarshal(b []byte) error {
	g, err := DecodeKadContact(b)
	if err != nil {
		return err
	}
	*c = g
	return nil
}
func (c *KadContact) Decode(b []byte) error { return c.Unmarshal(b) }

// KadBootstrapReq
type KadBootstrapReq struct {
	Peer    KadContact
	Sender  KadContact
	Self    KadContact
	From    KadContact
	Local   KadContact
	Data    []byte
	Payload []byte
	Body    []byte
}
func (r KadBootstrapReq) peer() (KadContact, bool) {
	for _, c := range []KadContact{r.Peer, r.Sender, r.Self, r.From, r.Local} {
		if c != (KadContact{}) {
			return c, true
		}
	}
	return KadContact{}, false
}
func (r KadBootstrapReq) data() []byte {
	if r.Payload != nil {
		return r.Payload
	}
	if r.Data != nil {
		return r.Data
	}
	return r.Body
}
func (r KadBootstrapReq) Marshal() []byte {
	if c, ok := r.peer(); ok {
		return c.Marshal()
	}
	if d := r.data(); d != nil {
		out := make([]byte, len(d))
		copy(out, d)
		return out
	}
	return []byte{}
}
func (r KadBootstrapReq) Encode() []byte { return r.Marshal() }
func (r KadBootstrapReq) Bytes() []byte  { return r.Marshal() }
func (r KadBootstrapReq) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }
func DecodeKadBootstrapReq(b []byte) (KadBootstrapReq, error) {
	r := KadBootstrapReq{}
	if len(b) == 0 {
		return r, nil
	}
	if len(b) == 25 {
		c, err := DecodeKadContact(b)
		if err != nil {
			return KadBootstrapReq{}, fmt.Errorf("%w: %w", ErrKadBootstrapReq, err)
		}
		r.Peer = c
		r.Sender = c
		r.Self = c
		r.From = c
		r.Local = c
		return r, nil
	}
	cp := cloneBytes(b)
	r.Data = cp
	r.Payload = cloneBytes(cp)
	r.Body = cloneBytes(cp)
	return r, nil
}
func ParseKadBootstrapReq(b []byte) (KadBootstrapReq, error) { return DecodeKadBootstrapReq(b) }
func (r *KadBootstrapReq) Unmarshal(b []byte) error {
	g, err := DecodeKadBootstrapReq(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}
func (r *KadBootstrapReq) Decode(b []byte) error { return r.Unmarshal(b) }

// KadBootstrapRes
type KadBootstrapRes struct {
	ID          [16]byte
	ResponderID [16]byte
	Responder   [16]byte
	TCPPort     uint16
	Port        uint16
	TCP         uint16
	Version     byte
	Ver         byte
	Count       uint16
	Contacts    []KadContact
	Peers       []KadContact
	Nodes       []KadContact
}
func (r KadBootstrapRes) idBytes() [16]byte {
	for _, id := range []([16]byte){r.ID, r.ResponderID, r.Responder} {
		if id != ([16]byte{}) {
			return id
		}
	}
	return [16]byte{}
}
func (r KadBootstrapRes) tcpPort() uint16 {
	if r.TCPPort != 0 {
		return r.TCPPort
	}
	if r.Port != 0 {
		return r.Port
	}
	return r.TCP
}
func (r KadBootstrapRes) versionByte() byte {
	if r.Version != 0 {
		return r.Version
	}
	return r.Ver
}
func (r KadBootstrapRes) contacts() []KadContact {
	if r.Contacts != nil {
		return r.Contacts
	}
	if r.Peers != nil {
		return r.Peers
	}
	return r.Nodes
}
func (r KadBootstrapRes) Marshal() []byte {
	contacts := r.contacts()
	count := r.Count
	if contacts != nil {
		count = uint16(len(contacts))
	}
	out := make([]byte, 16+2+1+2)
	id := r.idBytes()
	copy(out[0:16], id[:])
	binary.LittleEndian.PutUint16(out[16:18], r.tcpPort())
	out[18] = r.versionByte()
	binary.LittleEndian.PutUint16(out[19:21], count)
	for _, c := range contacts {
		out = append(out, c.Marshal()...)
	}
	return out
}
func (r KadBootstrapRes) Encode() []byte { return r.Marshal() }
func (r KadBootstrapRes) Bytes() []byte  { return r.Marshal() }
func (r KadBootstrapRes) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }
func DecodeKadBootstrapRes(b []byte) (KadBootstrapRes, error) {
	if len(b) < 21 {
		return KadBootstrapRes{}, fmt.Errorf("%w: %w", ErrKadBootstrapRes, ErrKadTruncated)
	}
	r := KadBootstrapRes{}
	copy(r.ID[:], b[0:16])
	r.ResponderID = r.ID
	r.Responder = r.ID
	r.TCPPort = binary.LittleEndian.Uint16(b[16:18])
	r.Port = r.TCPPort
	r.TCP = r.TCPPort
	r.Version = b[18]
	r.Ver = r.Version
	count := binary.LittleEndian.Uint16(b[19:21])
	r.Count = count
	off := 21
	if off+int(count)*25 > len(b) {
		return KadBootstrapRes{}, fmt.Errorf("%w: %w", ErrKadBootstrapRes, ErrKadTruncated)
	}
	contacts := make([]KadContact, 0, count)
	for i := 0; i < int(count); i++ {
		c, err := DecodeKadContact(b[off:])
		if err != nil {
			return KadBootstrapRes{}, fmt.Errorf("%w: %w", ErrKadBootstrapRes, err)
		}
		contacts = append(contacts, c)
		off += 25
	}
	if off != len(b) {
		return KadBootstrapRes{}, fmt.Errorf("%w: %w", ErrKadBootstrapRes, ErrFrameTrailing)
	}
	r.Contacts = contacts
	r.Peers = cloneContacts(contacts)
	r.Nodes = cloneContacts(contacts)
	r.Count = uint16(len(contacts))
	return r, nil
}
func ParseKadBootstrapRes(b []byte) (KadBootstrapRes, error) { return DecodeKadBootstrapRes(b) }
func (r *KadBootstrapRes) Unmarshal(b []byte) error {
	g, err := DecodeKadBootstrapRes(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}
func (r *KadBootstrapRes) Decode(b []byte) error { return r.Unmarshal(b) }

// KadPing
type KadPing struct {
	Data    []byte
	Payload []byte
	Body    []byte
}
func (p KadPing) data() []byte {
	if p.Payload != nil {
		return p.Payload
	}
	if p.Data != nil {
		return p.Data
	}
	return p.Body
}
func (p KadPing) Marshal() []byte {
	if d := p.data(); d != nil {
		out := make([]byte, len(d))
		copy(out, d)
		return out
	}
	return []byte{}
}
func (p KadPing) Encode() []byte { return p.Marshal() }
func (p KadPing) Bytes() []byte  { return p.Marshal() }
func (p KadPing) MarshalBinary() ([]byte, error) { return p.Marshal(), nil }
func DecodeKadPing(b []byte) (KadPing, error) {
	cp := cloneBytes(b)
	return KadPing{Data: cp, Payload: cloneBytes(cp), Body: cloneBytes(cp)}, nil
}
func ParseKadPing(b []byte) (KadPing, error) { return DecodeKadPing(b) }
func (p *KadPing) Unmarshal(b []byte) error {
	g, err := DecodeKadPing(b)
	if err != nil {
		return err
	}
	*p = g
	return nil
}
func (p *KadPing) Decode(b []byte) error { return p.Unmarshal(b) }

// KadPong
type KadPong struct {
	Data    []byte
	Payload []byte
	Body    []byte
}
func (p KadPong) data() []byte {
	if p.Payload != nil {
		return p.Payload
	}
	if p.Data != nil {
		return p.Data
	}
	return p.Body
}
func (p KadPong) Marshal() []byte {
	if d := p.data(); d != nil {
		out := make([]byte, len(d))
		copy(out, d)
		return out
	}
	return []byte{}
}
func (p KadPong) Encode() []byte { return p.Marshal() }
func (p KadPong) Bytes() []byte  { return p.Marshal() }
func (p KadPong) MarshalBinary() ([]byte, error) { return p.Marshal(), nil }
func DecodeKadPong(b []byte) (KadPong, error) {
	cp := cloneBytes(b)
	return KadPong{Data: cp, Payload: cloneBytes(cp), Body: cloneBytes(cp)}, nil
}
func ParseKadPong(b []byte) (KadPong, error) { return DecodeKadPong(b) }
func (p *KadPong) Unmarshal(b []byte) error {
	g, err := DecodeKadPong(b)
	if err != nil {
		return err
	}
	*p = g
	return nil
}
func (p *KadPong) Decode(b []byte) error { return p.Unmarshal(b) }

// KadSearchReq
type KadSearchReq struct {
	Key           [16]byte
	Hash          [16]byte
	Keyword       [16]byte
	Target        [16]byte
	StartPosition uint16
	Start         uint16
	Position      uint16
	Expression    []byte
	SearchExpression []byte
	Tree          []byte
	Data          []byte
	Payload       []byte
	Body          []byte
}
func (r KadSearchReq) keyBytes() [16]byte {
	for _, k := range []([16]byte){r.Key, r.Hash, r.Keyword, r.Target} {
		if k != ([16]byte{}) {
			return k
		}
	}
	return [16]byte{}
}
func (r KadSearchReq) startPos() uint16 {
	if r.StartPosition != 0 {
		return r.StartPosition
	}
	if r.Start != 0 {
		return r.Start
	}
	return r.Position
}
func (r KadSearchReq) expression() []byte {
	if r.Expression != nil {
		return r.Expression
	}
	if r.SearchExpression != nil {
		return r.SearchExpression
	}
	if r.Tree != nil {
		return r.Tree
	}
	if r.Payload != nil {
		return r.Payload
	}
	if r.Data != nil {
		return r.Data
	}
	return r.Body
}
func (r KadSearchReq) Marshal() []byte {
	out := make([]byte, 16+2)
	key := r.keyBytes()
	copy(out[0:16], key[:])
	binary.LittleEndian.PutUint16(out[16:18], r.startPos())
	if expr := r.expression(); expr != nil {
		out = append(out, expr...)
	}
	return out
}
func (r KadSearchReq) Encode() []byte { return r.Marshal() }
func (r KadSearchReq) Bytes() []byte  { return r.Marshal() }
func (r KadSearchReq) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }
func DecodeKadSearchReq(b []byte) (KadSearchReq, error) {
	if len(b) < 18 {
		return KadSearchReq{}, fmt.Errorf("%w: %w", ErrKadSearchReq, ErrKadTruncated)
	}
	r := KadSearchReq{}
	copy(r.Key[:], b[0:16])
	r.Hash = r.Key
	r.Keyword = r.Key
	r.Target = r.Key
	r.StartPosition = binary.LittleEndian.Uint16(b[16:18])
	r.Start = r.StartPosition
	r.Position = r.StartPosition
	expr := cloneBytes(b[18:])
	r.Expression = expr
	r.SearchExpression = cloneBytes(expr)
	r.Tree = cloneBytes(expr)
	r.Data = cloneBytes(expr)
	r.Payload = cloneBytes(expr)
	r.Body = cloneBytes(expr)
	if len(b) == 18 {
		r.Expression = nil
		r.SearchExpression = nil
		r.Tree = nil
		r.Data = nil
		r.Payload = nil
		r.Body = nil
	}
	return r, nil
}
func ParseKadSearchReq(b []byte) (KadSearchReq, error) { return DecodeKadSearchReq(b) }
func (r *KadSearchReq) Unmarshal(b []byte) error {
	g, err := DecodeKadSearchReq(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}
func (r *KadSearchReq) Decode(b []byte) error { return r.Unmarshal(b) }

// KadSearchResult
type KadSearchResult struct {
	Hash     [16]byte
	FileHash [16]byte
	Tags     []Tag
	TagList  []Tag
	TagSet   []Tag
}
func (s KadSearchResult) hashBytes() [16]byte {
	if s.Hash != ([16]byte{}) {
		return s.Hash
	}
	return s.FileHash
}
func (s KadSearchResult) tags() []Tag {
	if s.Tags != nil {
		return s.Tags
	}
	if s.TagList != nil {
		return s.TagList
	}
	return s.TagSet
}
func (s KadSearchResult) Marshal() []byte {
	tags := s.tags()
	out := make([]byte, 16+1)
	h := s.hashBytes()
	copy(out[0:16], h[:])
	out[16] = byte(len(tags))
	for _, t := range tags {
		out = append(out, t.Marshal()...)
	}
	return out
}
func (s KadSearchResult) Encode() []byte { return s.Marshal() }
func (s KadSearchResult) Bytes() []byte  { return s.Marshal() }
func (s KadSearchResult) MarshalBinary() ([]byte, error) { return s.Marshal(), nil }
func DecodeKadSearchResult(b []byte) (KadSearchResult, int, error) {
	if len(b) < 17 {
		return KadSearchResult{}, 0, fmt.Errorf("%w: %w", ErrKadSearchResult, ErrKadTruncated)
	}
	s := KadSearchResult{}
	copy(s.Hash[:], b[0:16])
	s.FileHash = s.Hash
	tc := int(b[16])
	off := 17
	tags := make([]Tag, 0, tc)
	for i := 0; i < tc; i++ {
		tag, consumed, err := DecodeTag(b[off:])
		if err != nil {
			return KadSearchResult{}, off, fmt.Errorf("%w: %w", ErrKadSearchResult, err)
		}
		tags = append(tags, tag)
		off += consumed
	}
	s.Tags = tags
	s.TagList = cloneTags(tags)
	s.TagSet = cloneTags(tags)
	return s, off, nil
}
func ParseKadSearchResult(b []byte) (KadSearchResult, int, error) { return DecodeKadSearchResult(b) }
func (s *KadSearchResult) Unmarshal(b []byte) error {
	g, _, err := DecodeKadSearchResult(b)
	if err != nil {
		return err
	}
	*s = g
	return nil
}
func (s *KadSearchResult) Decode(b []byte) error { return s.Unmarshal(b) }

// KadSearchRes
type KadSearchRes struct {
	Target  [16]byte
	Key     [16]byte
	Hash    [16]byte
	Count   uint16
	Results []KadSearchResult
	Files   []KadSearchResult
	Entries []KadSearchResult
}
func (r KadSearchRes) targetBytes() [16]byte {
	for _, t := range []([16]byte){r.Target, r.Key, r.Hash} {
		if t != ([16]byte{}) {
			return t
		}
	}
	return [16]byte{}
}
func (r KadSearchRes) results() []KadSearchResult {
	if r.Results != nil {
		return r.Results
	}
	if r.Files != nil {
		return r.Files
	}
	return r.Entries
}
func (r KadSearchRes) Marshal() []byte {
	results := r.results()
	count := r.Count
	if results != nil {
		count = uint16(len(results))
	}
	out := make([]byte, 16+2)
	t := r.targetBytes()
	copy(out[0:16], t[:])
	binary.LittleEndian.PutUint16(out[16:18], count)
	for _, res := range results {
		out = append(out, res.Marshal()...)
	}
	return out
}
func (r KadSearchRes) Encode() []byte { return r.Marshal() }
func (r KadSearchRes) Bytes() []byte  { return r.Marshal() }
func (r KadSearchRes) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }
func DecodeKadSearchRes(b []byte) (KadSearchRes, error) {
	if len(b) < 18 {
		return KadSearchRes{}, fmt.Errorf("%w: %w", ErrKadSearchRes, ErrKadTruncated)
	}
	r := KadSearchRes{}
	copy(r.Target[:], b[0:16])
	r.Key = r.Target
	r.Hash = r.Target
	count := binary.LittleEndian.Uint16(b[16:18])
	r.Count = count
	off := 18
	results := make([]KadSearchResult, 0, count)
	for i := 0; i < int(count); i++ {
		res, consumed, err := DecodeKadSearchResult(b[off:])
		if err != nil {
			return KadSearchRes{}, fmt.Errorf("%w: %w", ErrKadSearchRes, err)
		}
		results = append(results, res)
		off += consumed
	}
	if off != len(b) {
		return KadSearchRes{}, fmt.Errorf("%w: %w", ErrKadSearchRes, ErrFrameTrailing)
	}
	r.Results = results
	r.Files = cloneSearchResults(results)
	r.Entries = cloneSearchResults(results)
	r.Count = uint16(len(results))
	return r, nil
}
func ParseKadSearchRes(b []byte) (KadSearchRes, error) { return DecodeKadSearchRes(b) }
func (r *KadSearchRes) Unmarshal(b []byte) error {
	g, err := DecodeKadSearchRes(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}
func (r *KadSearchRes) Decode(b []byte) error { return r.Unmarshal(b) }

// helpers
func cloneContacts(in []KadContact) []KadContact {
	if in == nil {
		return nil
	}
	out := make([]KadContact, len(in))
	copy(out, in)
	return out
}
func cloneSearchResults(in []KadSearchResult) []KadSearchResult {
	if in == nil {
		return nil
	}
	out := make([]KadSearchResult, len(in))
	copy(out, in)
	for i := range out {
		out[i].Tags = cloneTags(out[i].Tags)
		out[i].TagList = cloneTags(out[i].TagList)
		out[i].TagSet = cloneTags(out[i].TagSet)
	}
	return out
}

// Type aliases for naming flexibility.
type (
	KadUDP            = KadPacket
	KadDatagram       = KadPacket
	KadHeader         = KadPacket
	KadPacketHeader   = KadPacket
	UDPPacket         = KadPacket
	KadPeer           = KadContact
	KadNode           = KadContact
	KadBootstrapRequest  = KadBootstrapReq
	KadBootstrapResponse = KadBootstrapRes
	BootstrapReq         = KadBootstrapReq
	BootstrapRes         = KadBootstrapRes
	BootstrapRequest     = KadBootstrapReq
	BootstrapResponse    = KadBootstrapRes
	KadSearchKeyReq      = KadSearchReq
	KadSearchKeyRequest  = KadSearchReq
	KadSearchRequest     = KadSearchReq
	KadSearchResponse    = KadSearchRes
	SearchReq            = KadSearchReq
	SearchRes            = KadSearchRes
	SearchRequest        = KadSearchReq
	SearchResponse       = KadSearchRes
)
