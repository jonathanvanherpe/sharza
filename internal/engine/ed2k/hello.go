// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the ed2k client-to-client (C2C) Hello handshake codecs:
// OP_HELLO (0x01) and OP_HELLOANSWER (0x4C). There is no networking, peer
// dialing, obfuscation, file I/O, .part.met or Engine wiring here.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// C2C Hello opcodes. Values follow Shareaza's EDPacket.h
// (ED2K_C2C_HELLO / ED2K_C2C_HELLOANSWER).
const (
	OP_HELLO       byte = 0x01 // ED2K_C2C_HELLO
	OP_HELLOANSWER byte = 0x4C // ED2K_C2C_HELLOANSWER
)

// CamelCase aliases for the opcodes.
const (
	OpHello       = OP_HELLO
	OpHelloAnswer = OP_HELLOANSWER
)

// Sentinel errors.
var (
	ErrHello       = errors.New("ed2k: malformed hello")
	ErrHelloAnswer = errors.New("ed2k: malformed hello answer")
)

// --- Hello (OP_HELLO) ---

// Hello is the payload of OP_HELLO (C2C):
// 0x10 <HASH 16><ID 4><PORT 2><count 4><Tag...>.
type Hello struct {
	// Leading hash-size byte (always 0x10).
	Protocol byte
	Leading  byte

	// User GUID (16 bytes).
	Hash     [16]byte
	GUID     [16]byte
	UserHash [16]byte

	// Client ID.
	ClientID uint32
	ID       uint32

	// Listening port.
	Port uint16

	// Tags.
	Tags    []Tag
	TagList []Tag
	TagSet  []Tag
}

func (h Hello) leadingByte() byte {
	if h.Protocol != 0 {
		return h.Protocol
	}
	if h.Leading != 0 {
		return h.Leading
	}
	return 0x10
}

func (h Hello) hashBytes() [16]byte {
	for _, hh := range []([16]byte){h.Hash, h.GUID, h.UserHash} {
		if hh != ([16]byte{}) {
			return hh
		}
	}
	return [16]byte{}
}

func (h Hello) idValue() uint32 {
	if h.ClientID != 0 {
		return h.ClientID
	}
	return h.ID
}

func (h Hello) tags() []Tag {
	if h.Tags != nil {
		return h.Tags
	}
	if h.TagList != nil {
		return h.TagList
	}
	return h.TagSet
}

// Marshal encodes a Hello payload.
func (h Hello) Marshal() []byte {
	hash := h.hashBytes()
	tags := h.tags()
	lb := h.leadingByte()
	if lb == 0 {
		lb = 0x10
	}
	out := make([]byte, 0, 1+16+4+2+4+len(tags)*8)
	out = append(out, lb)
	out = append(out, hash[:]...)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, h.idValue())
	out = append(out, b...)
	p := make([]byte, 2)
	binary.LittleEndian.PutUint16(p, h.Port)
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
func (h Hello) Encode() []byte { return h.Marshal() }

// Bytes is an alias.
func (h Hello) Bytes() []byte { return h.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (h Hello) MarshalBinary() ([]byte, error) { return h.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (h Hello) AppendTo(dst []byte) []byte {
	return append(dst, h.Marshal()...)
}

// DecodeHello parses a Hello payload.
func DecodeHello(b []byte) (Hello, error) {
	if len(b) < 1+16+4+2+4 {
		return Hello{}, fmt.Errorf("%w: %w", ErrHello, ErrFrameTruncated)
	}
	if b[0] != 0x10 {
		return Hello{}, fmt.Errorf("%w: unexpected leading byte 0x%02X", ErrHello, b[0])
	}
	var h Hello
	h.Protocol = 0x10
	h.Leading = 0x10

	copy(h.Hash[:], b[1:1+16])
	h.GUID = h.Hash
	h.UserHash = h.Hash

	h.ClientID = binary.LittleEndian.Uint32(b[1+16 : 1+16+4])
	h.ID = h.ClientID

	h.Port = binary.LittleEndian.Uint16(b[1+16+4 : 1+16+4+2])

	count := binary.LittleEndian.Uint32(b[1+16+4+2 : 1+16+4+2+4])
	if count > 1024 {
		return Hello{}, fmt.Errorf("%w: too many tags", ErrHello)
	}
	off := 1 + 16 + 4 + 2 + 4
	tags := make([]Tag, 0, count)
	for i := uint32(0); i < count; i++ {
		tag, consumed, err := DecodeTag(b[off:])
		if err != nil {
			return Hello{}, fmt.Errorf("%w: %w", ErrHello, err)
		}
		if consumed <= 0 || off+consumed > len(b) {
			return Hello{}, fmt.Errorf("%w: %w", ErrHello, ErrFrameTruncated)
		}
		tags = append(tags, tag)
		off += consumed
	}
	if off != len(b) {
		return Hello{}, fmt.Errorf("%w: %w", ErrHello, ErrFrameTrailing)
	}
	h.Tags = tags
	h.TagList = cloneTags(tags)
	h.TagSet = cloneTags(tags)
	return h, nil
}

// ParseHello is an alias.
func ParseHello(b []byte) (Hello, error) { return DecodeHello(b) }

// UnmarshalHello is an alias.
func UnmarshalHello(b []byte) (Hello, error) { return DecodeHello(b) }

// Top-level helpers.
func EncodeHello(h Hello) []byte { return h.Marshal() }
func MarshalHello(h Hello) []byte { return h.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (h *Hello) Unmarshal(b []byte) error {
	g, err := DecodeHello(b)
	if err != nil {
		return err
	}
	*h = g
	return nil
}

// Decode is a method form.
func (h *Hello) Decode(b []byte) error { return h.Unmarshal(b) }

// --- HelloAnswer (OP_HELLOANSWER) ---

// HelloAnswer is the payload of OP_HELLOANSWER (C2C):
// <HASH 16><ID 4><PORT 2><count 4><Tag...><SERVER_IP 4><SERVER_PORT 2>.
type HelloAnswer struct {
	// User GUID (16 bytes).
	Hash     [16]byte
	GUID     [16]byte
	UserHash [16]byte

	// Client ID.
	ClientID uint32
	ID       uint32

	// Listening port.
	Port uint16

	// Tags.
	Tags    []Tag
	TagList []Tag
	TagSet  []Tag

	// Server info (trailing).
	ServerIP   [4]byte
	ServerPort uint16
}

func (a HelloAnswer) hashBytes() [16]byte {
	for _, hh := range []([16]byte){a.Hash, a.GUID, a.UserHash} {
		if hh != ([16]byte{}) {
			return hh
		}
	}
	return [16]byte{}
}

func (a HelloAnswer) idValue() uint32 {
	if a.ClientID != 0 {
		return a.ClientID
	}
	return a.ID
}

func (a HelloAnswer) tags() []Tag {
	if a.Tags != nil {
		return a.Tags
	}
	if a.TagList != nil {
		return a.TagList
	}
	return a.TagSet
}

// Marshal encodes a HelloAnswer payload.
func (a HelloAnswer) Marshal() []byte {
	hash := a.hashBytes()
	tags := a.tags()
	out := make([]byte, 0, 16+4+2+4+len(tags)*8+4+2)
	out = append(out, hash[:]...)
	b := make([]byte, 4)
	binary.LittleEndian.PutUint32(b, a.idValue())
	out = append(out, b...)
	p := make([]byte, 2)
	binary.LittleEndian.PutUint16(p, a.Port)
	out = append(out, p...)
	c := make([]byte, 4)
	binary.LittleEndian.PutUint32(c, uint32(len(tags)))
	out = append(out, c...)
	for _, t := range tags {
		out = append(out, t.Marshal()...)
	}
	out = append(out, a.ServerIP[:]...)
	sp := make([]byte, 2)
	binary.LittleEndian.PutUint16(sp, a.ServerPort)
	out = append(out, sp...)
	return out
}

// Encode is an alias.
func (a HelloAnswer) Encode() []byte { return a.Marshal() }

// Bytes is an alias.
func (a HelloAnswer) Bytes() []byte { return a.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (a HelloAnswer) MarshalBinary() ([]byte, error) { return a.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (a HelloAnswer) AppendTo(dst []byte) []byte {
	return append(dst, a.Marshal()...)
}

// DecodeHelloAnswer parses a HelloAnswer payload.
func DecodeHelloAnswer(b []byte) (HelloAnswer, error) {
	if len(b) < 16+4+2+4+4+2 {
		return HelloAnswer{}, fmt.Errorf("%w: %w", ErrHelloAnswer, ErrFrameTruncated)
	}
	var a HelloAnswer
	copy(a.Hash[:], b[0:16])
	a.GUID = a.Hash
	a.UserHash = a.Hash

	a.ClientID = binary.LittleEndian.Uint32(b[16:20])
	a.ID = a.ClientID

	a.Port = binary.LittleEndian.Uint16(b[20:22])

	count := binary.LittleEndian.Uint32(b[22:26])
	if count > 1024 {
		return HelloAnswer{}, fmt.Errorf("%w: too many tags", ErrHelloAnswer)
	}
	off := 26
	tags := make([]Tag, 0, count)
	for i := uint32(0); i < count; i++ {
		tag, consumed, err := DecodeTag(b[off:])
		if err != nil {
			return HelloAnswer{}, fmt.Errorf("%w: %w", ErrHelloAnswer, err)
		}
		if consumed <= 0 || off+consumed > len(b) {
			return HelloAnswer{}, fmt.Errorf("%w: %w", ErrHelloAnswer, ErrFrameTruncated)
		}
		tags = append(tags, tag)
		off += consumed
	}
	if off+4+2 != len(b) {
		if off+4+2 > len(b) {
			return HelloAnswer{}, fmt.Errorf("%w: %w", ErrHelloAnswer, ErrFrameTruncated)
		}
		return HelloAnswer{}, fmt.Errorf("%w: %w", ErrHelloAnswer, ErrFrameTrailing)
	}
	copy(a.ServerIP[:], b[off:off+4])
	a.ServerPort = binary.LittleEndian.Uint16(b[off+4 : off+6])

	a.Tags = tags
	a.TagList = cloneTags(tags)
	a.TagSet = cloneTags(tags)
	return a, nil
}

// ParseHelloAnswer is an alias.
func ParseHelloAnswer(b []byte) (HelloAnswer, error) { return DecodeHelloAnswer(b) }

// UnmarshalHelloAnswer is an alias.
func UnmarshalHelloAnswer(b []byte) (HelloAnswer, error) { return DecodeHelloAnswer(b) }

// Top-level helpers.
func EncodeHelloAnswer(a HelloAnswer) []byte { return a.Marshal() }
func MarshalHelloAnswer(a HelloAnswer) []byte { return a.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (a *HelloAnswer) Unmarshal(b []byte) error {
	g, err := DecodeHelloAnswer(b)
	if err != nil {
		return err
	}
	*a = g
	return nil
}

// Decode is a method form.
func (a *HelloAnswer) Decode(b []byte) error { return a.Unmarshal(b) }
