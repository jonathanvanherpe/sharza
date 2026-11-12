// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This first slice covers only the TCP packet framing and the core opcodes
// OP_REJECT, OP_SERVERMESSAGE and OP_OFFERFILES. There is no networking,
// server login, Kad routing, obfuscation or AICH here yet.
//
// The TCP frame follows Shareaza's EDPacket / ED2K_TCP_HEADER layout:
//
//	+----------+----------+----------+----------------+
//	| protocol |  size    | opcode   | payload        |
//	| 1 byte   | 4 bytes  | 1 byte   | size-1 bytes   |
//	+----------+----------+----------+----------------+
//
// protocol is the protocol byte (0xE3 = eDonkey, 0xC5 = eMule, ...).
// size is the little-endian length of everything after the size field,
// i.e. opcode (1 byte) plus payload (size-1 bytes). Total frame size is
// size + 5 bytes.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Protocol bytes.
const (
	ProtocolEDonkey byte = 0xE3
	ProtocolEMule   byte = 0xC5
	ProtocolKad     byte = 0xE4
)

// Core opcodes. Values follow Shareaza's EDPacket.h (ED2K_S2C_* / ED2K_C2S_*).
const (
	OP_REJECT        byte = 0x05 // ED2K_S2C_REJECTED
	OP_SERVERMESSAGE byte = 0x38 // ED2K_S2C_SERVERMESSAGE
	OP_OFFERFILES    byte = 0x15 // ED2K_C2S_OFFERFILES
)

// CamelCase aliases for the opcodes, in case callers prefer them.
const (
	OpReject        = OP_REJECT
	OpServerMessage = OP_SERVERMESSAGE
	OpOfferFiles    = OP_OFFERFILES
)

// MaxFrameSize caps the size field a frame may declare, bounding
// allocations in fuzz and malformed-input paths.
const MaxFrameSize = 1 << 20

// Sentinel errors.
var (
	ErrFrameTruncated = errors.New("ed2k: truncated frame")
	ErrFrameBadSize   = errors.New("ed2k: invalid frame size")
	ErrFrameTooLarge  = errors.New("ed2k: frame too large")
	ErrFrameTrailing  = errors.New("ed2k: trailing bytes after frame")

	ErrRejectPayload     = errors.New("ed2k: reject payload must be empty")
	ErrServerMessage     = errors.New("ed2k: malformed server message")
	ErrOfferFiles        = errors.New("ed2k: malformed offer files")
	ErrTag               = errors.New("ed2k: malformed tag")
)

// Frame is an ed2k TCP packet frame.
type Frame struct {
	Protocol byte
	Size     uint32
	Length   uint32

	Opcode byte
	Type   byte
	Op     byte

	Payload []byte
	Data    []byte
	Body    []byte
}

// cloneBytes returns a copy of b (nil stays nil).
func cloneBytes(b []byte) []byte {
	if b == nil {
		return nil
	}
	out := make([]byte, len(b))
	copy(out, b)
	return out
}

// normalized extracts the effective protocol, opcode and payload from a Frame,
// honouring the alias fields.
func (f Frame) normalized() (byte, byte, []byte) {
	proto := f.Protocol
	if proto == 0 {
		proto = ProtocolEDonkey
	}
	op := f.Opcode
	if op == 0 {
		op = f.Type
	}
	if op == 0 {
		op = f.Op
	}
	payload := f.Payload
	if payload == nil {
		payload = f.Data
	}
	if payload == nil {
		payload = f.Body
	}
	if payload == nil {
		payload = []byte{}
	}
	return proto, op, payload
}

// Marshal encodes the frame to its on-wire bytes.
func (f Frame) Marshal() []byte {
	proto, op, payload := f.normalized()
	size := uint32(1 + len(payload))
	out := make([]byte, 6+len(payload))
	out[0] = proto
	binary.LittleEndian.PutUint32(out[1:5], size)
	out[5] = op
	copy(out[6:], payload)
	return out
}

// Encode is an alias for Marshal.
func (f Frame) Encode() []byte { return f.Marshal() }

// Bytes is an alias for Marshal.
func (f Frame) Bytes() []byte { return f.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (f Frame) MarshalBinary() ([]byte, error) { return f.Marshal(), nil }

// AppendTo appends the frame encoding to dst.
func (f Frame) AppendTo(dst []byte) []byte {
	return append(dst, f.Marshal()...)
}

// DecodeFrame parses one frame from b. Trailing bytes after the frame are
// rejected.
func DecodeFrame(b []byte) (Frame, error) {
	if len(b) < 6 {
		return Frame{}, fmt.Errorf("%w: need 6 bytes, got %d", ErrFrameTruncated, len(b))
	}
	proto := b[0]
	size := binary.LittleEndian.Uint32(b[1:5])
	if size < 1 {
		return Frame{}, ErrFrameBadSize
	}
	if size > MaxFrameSize {
		return Frame{}, ErrFrameTooLarge
	}
	if len(b) != int(size)+5 {
		if len(b) < int(size)+5 {
			return Frame{}, fmt.Errorf("%w: need %d bytes, got %d", ErrFrameTruncated, int(size)+5, len(b))
		}
		return Frame{}, ErrFrameTrailing
	}
	op := b[5]
	payload := make([]byte, int(size)-1)
	copy(payload, b[6:])
	cp := cloneBytes(payload)
	f := Frame{
		Protocol: proto,
		Size:     size,
		Length:   size,
		Opcode:   op,
		Type:     op,
		Op:       op,
		Payload:  payload,
		Data:     cp,
		Body:     cloneBytes(payload),
	}
	return f, nil
}

// Decode is an alias for DecodeFrame.
func Decode(b []byte) (Frame, error) { return DecodeFrame(b) }

// UnmarshalFrame is an alias for DecodeFrame.
func UnmarshalFrame(b []byte) (Frame, error) { return DecodeFrame(b) }

// ParseFrame is an alias for DecodeFrame.
func ParseFrame(b []byte) (Frame, error) { return DecodeFrame(b) }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (f *Frame) Unmarshal(b []byte) error {
	g, err := DecodeFrame(b)
	if err != nil {
		return err
	}
	*f = g
	return nil
}

// Decode is a method form of DecodeFrame.
func (f *Frame) Decode(b []byte) error { return f.Unmarshal(b) }

// ReadFrame reads one frame from r.
func ReadFrame(r io.Reader) (Frame, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, err
	}
	size := binary.LittleEndian.Uint32(hdr[1:5])
	if size < 1 {
		return Frame{}, ErrFrameBadSize
	}
	if size > MaxFrameSize {
		return Frame{}, ErrFrameTooLarge
	}
	rest := make([]byte, size)
	if _, err := io.ReadFull(r, rest); err != nil {
		return Frame{}, err
	}
	buf := make([]byte, 5+size)
	buf[0] = hdr[0]
	copy(buf[1:5], hdr[1:5])
	copy(buf[5:], rest)
	f, err := DecodeFrame(buf)
	if err != nil {
		return Frame{}, err
	}
	// detect trailing bytes
	var one [1]byte
	n, err := r.Read(one[:])
	if n > 0 {
		return Frame{}, ErrFrameTrailing
	}
	if err != nil && err != io.EOF {
		return Frame{}, err
	}
	return f, nil
}

// Top-level encode/decode helpers.
func EncodeFrame(f Frame) []byte { return f.Marshal() }
func MarshalFrame(f Frame) []byte { return f.Marshal() }

// OpcodeName returns a human-readable name for an opcode.
func OpcodeName(op byte) string {
	switch op {
	case OP_REJECT:
		return "OP_REJECT"
	case OP_SERVERMESSAGE:
		return "OP_SERVERMESSAGE"
	case OP_OFFERFILES:
		return "OP_OFFERFILES"
	case OP_LOGINREQUEST:
		return "OP_LOGINREQUEST"
	case OP_GETSERVERLIST:
		return "OP_GETSERVERLIST"
	case OP_IDCHANGE:
		return "OP_IDCHANGE"
	case OP_SERVERLIST:
		return "OP_SERVERLIST"
	default:
		return fmt.Sprintf("0x%02X", op)
	}
}

// String renders the frame.
func (f Frame) String() string {
	_, op, payload := f.normalized()
	return fmt.Sprintf("ed2k.Frame{Protocol:0x%02X, Size:%d, Opcode:%s, Payload:%d bytes}",
		f.Protocol, 1+len(payload), OpcodeName(op), len(payload))
}

// --- Reject (OP_REJECT) ---

// Reject is the payload of OP_REJECT (empty).
type Reject struct{}

// Marshal encodes a Reject payload (empty).
func (Reject) Marshal() []byte { return []byte{} }

// Encode is an alias.
func (Reject) Encode() []byte { return []byte{} }

// DecodeReject parses a Reject payload.
func DecodeReject(b []byte) (Reject, error) {
	if len(b) != 0 {
		return Reject{}, ErrRejectPayload
	}
	return Reject{}, nil
}

// ParseReject is an alias.
func ParseReject(b []byte) (Reject, error) { return DecodeReject(b) }

// Unmarshal implements BinaryUnmarshaler.
func (r *Reject) Unmarshal(b []byte) error {
	_, err := DecodeReject(b)
	return err
}

// --- ServerMessage (OP_SERVERMESSAGE) ---

// ServerMessage is the payload of OP_SERVERMESSAGE: <len u16><message>.
type ServerMessage struct {
	Message string
	Text    string

	Data    []byte
	Body    []byte
	Payload []byte
}

func (m ServerMessage) text() string {
	if m.Message != "" {
		return m.Message
	}
	if m.Text != "" {
		return m.Text
	}
	if len(m.Data) > 0 {
		return string(m.Data)
	}
	if len(m.Body) > 0 {
		return string(m.Body)
	}
	if len(m.Payload) > 0 {
		return string(m.Payload)
	}
	return ""
}

// Marshal encodes a ServerMessage payload.
func (m ServerMessage) Marshal() []byte {
	msg := m.text()
	out := make([]byte, 2+len(msg))
	binary.LittleEndian.PutUint16(out[0:2], uint16(len(msg)))
	copy(out[2:], msg)
	return out
}

// Encode is an alias.
func (m ServerMessage) Encode() []byte { return m.Marshal() }

// DecodeServerMessage parses a ServerMessage payload.
func DecodeServerMessage(b []byte) (ServerMessage, error) {
	if len(b) < 2 {
		return ServerMessage{}, fmt.Errorf("%w: %w", ErrServerMessage, ErrFrameTruncated)
	}
	n := int(binary.LittleEndian.Uint16(b[0:2]))
	if len(b) != 2+n {
		if len(b) < 2+n {
			return ServerMessage{}, fmt.Errorf("%w: %w", ErrServerMessage, ErrFrameTruncated)
		}
		return ServerMessage{}, fmt.Errorf("%w: %w", ErrServerMessage, ErrFrameTrailing)
	}
	msg := string(b[2:])
	cp := cloneBytes(b[2:])
	m := ServerMessage{
		Message: msg,
		Text:    msg,
		Data:    cp,
		Body:    cloneBytes(cp),
		Payload: cloneBytes(cp),
	}
	return m, nil
}

// ParseServerMessage is an alias.
func ParseServerMessage(b []byte) (ServerMessage, error) { return DecodeServerMessage(b) }

// Unmarshal implements BinaryUnmarshaler.
func (m *ServerMessage) Unmarshal(b []byte) error {
	g, err := DecodeServerMessage(b)
	if err != nil {
		return err
	}
	*m = g
	return nil
}

// Decode is a method form.
func (m *ServerMessage) Decode(b []byte) error { return m.Unmarshal(b) }

// --- Tag (used by OfferFiles) ---

// Tag is an ed2k tag (normal form only).
type Tag struct {
	Type   byte
	Key    byte
	KeyStr string

	Str   string
	Value uint64
	Hash  [16]byte
}

// Marshal encodes a Tag.
func (t Tag) Marshal() []byte {
	var out []byte
	out = append(out, t.Type)
	if t.KeyStr != "" {
		out = appendU16(out, len(t.KeyStr))
		out = append(out, []byte(t.KeyStr)...)
	} else {
		out = appendU16(out, 1)
		out = append(out, t.Key)
	}
	switch t.Type {
	case 0x01: // hash
		out = append(out, t.Hash[:]...)
	case 0x02: // string
		out = appendU16(out, len(t.Str))
		out = append(out, []byte(t.Str)...)
	case 0x03, 0x04: // int / float as u32
		b := make([]byte, 4)
		binary.LittleEndian.PutUint32(b, uint32(t.Value))
		out = append(out, b...)
	case 0x08: // u16
		b := make([]byte, 2)
		binary.LittleEndian.PutUint16(b, uint16(t.Value))
		out = append(out, b...)
	case 0x09: // u8
		out = append(out, byte(t.Value))
	case 0x0B: // u64
		b := make([]byte, 8)
		binary.LittleEndian.PutUint64(b, t.Value)
		out = append(out, b...)
	}
	return out
}

// Encode is an alias.
func (t Tag) Encode() []byte { return t.Marshal() }

// DecodeTag parses one tag from b, returning the tag and bytes consumed.
func DecodeTag(b []byte) (Tag, int, error) {
	if len(b) < 3 {
		return Tag{}, 0, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
	}
	t := Tag{Type: b[0]}
	off := 1
	keyLen := int(binary.LittleEndian.Uint16(b[off : off+2]))
	off += 2
	if keyLen == 1 {
		if off >= len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		t.Key = b[off]
		off++
	} else {
		if off+keyLen > len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		t.KeyStr = string(b[off : off+keyLen])
		off += keyLen
	}
	switch t.Type {
	case 0x01:
		if off+16 > len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		copy(t.Hash[:], b[off:off+16])
		off += 16
	case 0x02:
		if off+2 > len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		n := int(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2
		if off+n > len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		t.Str = string(b[off : off+n])
		off += n
	case 0x03, 0x04:
		if off+4 > len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		t.Value = uint64(binary.LittleEndian.Uint32(b[off : off+4]))
		off += 4
	case 0x08:
		if off+2 > len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		t.Value = uint64(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2
	case 0x09:
		if off >= len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		t.Value = uint64(b[off])
		off++
	case 0x0B:
		if off+8 > len(b) {
			return Tag{}, off, fmt.Errorf("%w: %w", ErrTag, ErrFrameTruncated)
		}
		t.Value = binary.LittleEndian.Uint64(b[off : off+8])
		off += 8
	default:
		return Tag{}, off, fmt.Errorf("%w: unknown tag type 0x%02X", ErrTag, t.Type)
	}
	return t, off, nil
}

// ParseTag is an alias.
func ParseTag(b []byte) (Tag, int, error) { return DecodeTag(b) }

// --- OfferFiles (OP_OFFERFILES) ---

// OfferedFile is one file entry in an OP_OFFERFILES payload.
type OfferedFile struct {
	Hash [16]byte

	ID       uint32
	ClientID uint32

	Port uint16

	Tags    []Tag
	TagList []Tag
	TagSet  []Tag
}

func (f OfferedFile) id() uint32 {
	if f.ID != 0 {
		return f.ID
	}
	return f.ClientID
}

func (f OfferedFile) tags() []Tag {
	if f.Tags != nil {
		return f.Tags
	}
	if f.TagList != nil {
		return f.TagList
	}
	return f.TagSet
}

// Marshal encodes an OfferedFile entry.
func (f OfferedFile) Marshal() []byte {
	id := f.id()
	tags := f.tags()
	out := make([]byte, 0, 22+len(tags)*8)
	out = append(out, f.Hash[:]...)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, id)
	out = append(out, b...)
	p := make([]byte, 2)
	binary.LittleEndian.PutUint16(p, f.Port)
	out = append(out, p...)
	c := make([]byte, 4)
	binary.LittleEndian.PutUint32(c, uint32(len(tags)))
	out = append(out, c...)
	for _, t := range tags {
		out = append(out, t.Marshal()...)
	}
	return out
}

// Encode is an alias.
func (f OfferedFile) Encode() []byte { return f.Marshal() }

// OfferFiles is the payload of OP_OFFERFILES.
type OfferFiles struct {
	Count uint32
	Files []OfferedFile
}

// Marshal encodes an OfferFiles payload.
func (o OfferFiles) Marshal() []byte {
	files := o.Files
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out[0:4], uint32(len(files)))
	for _, f := range files {
		out = append(out, f.Marshal()...)
	}
	return out
}

// Encode is an alias.
func (o OfferFiles) Encode() []byte { return o.Marshal() }

// DecodeOfferFiles parses an OfferFiles payload.
func DecodeOfferFiles(b []byte) (OfferFiles, error) {
	if len(b) < 4 {
		return OfferFiles{}, fmt.Errorf("%w: %w", ErrOfferFiles, ErrFrameTruncated)
	}
	count := binary.LittleEndian.Uint32(b[0:4])
	off := 4
	files := make([]OfferedFile, 0, count)
	for i := uint32(0); i < count; i++ {
		if off+22 > len(b) {
			return OfferFiles{}, fmt.Errorf("%w: %w", ErrOfferFiles, ErrFrameTruncated)
		}
		var f OfferedFile
		copy(f.Hash[:], b[off:off+16])
		off += 16
		f.ID = binary.LittleEndian.Uint32(b[off : off+4])
		f.ClientID = f.ID
		off += 4
		f.Port = binary.LittleEndian.Uint16(b[off : off+2])
		off += 2
		if off+4 > len(b) {
			return OfferFiles{}, fmt.Errorf("%w: %w", ErrOfferFiles, ErrFrameTruncated)
		}
		tc := binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
		tags := make([]Tag, 0, tc)
		for j := uint32(0); j < tc; j++ {
			tag, consumed, err := DecodeTag(b[off:])
			if err != nil {
				return OfferFiles{}, fmt.Errorf("%w: %w", ErrOfferFiles, err)
			}
			tags = append(tags, tag)
			off += consumed
		}
		f.Tags = tags
		f.TagList = cloneTags(tags)
		f.TagSet = cloneTags(tags)
		files = append(files, f)
	}
	if off != len(b) {
		return OfferFiles{}, fmt.Errorf("%w: %w", ErrOfferFiles, ErrFrameTrailing)
	}
	o := OfferFiles{Count: uint32(len(files)), Files: files}
	return o, nil
}

// ParseOfferFiles is an alias.
func ParseOfferFiles(b []byte) (OfferFiles, error) { return DecodeOfferFiles(b) }

// Unmarshal implements BinaryUnmarshaler.
func (o *OfferFiles) Unmarshal(b []byte) error {
	g, err := DecodeOfferFiles(b)
	if err != nil {
		return err
	}
	*o = g
	return nil
}

// Decode is a method form.
func (o *OfferFiles) Decode(b []byte) error { return o.Unmarshal(b) }

func cloneTags(in []Tag) []Tag {
	if in == nil {
		return nil
	}
	out := make([]Tag, len(in))
	copy(out, in)
	return out
}

// --- helpers ---

func appendU16(dst []byte, v int) []byte {
	b := make([]byte, 2)
	binary.LittleEndian.PutUint16(b, uint16(v))
	return append(dst, b...)
}

// ensure io import usage is retained in all build configs.
var _ = io.EOF
