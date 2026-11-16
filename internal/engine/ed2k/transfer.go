// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the ed2k transfer protocol codecs: OP_REQUESTPARTS and
// OP_SENDINGPART. There is no networking, file I/O, obfuscation, .part.met,
// AICH or range-map integration here.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Transfer opcodes. Values follow Shareaza's EDPacket.h
// (ED2K_C2C_REQUESTPARTS / ED2K_C2C_SENDINGPART).
const (
	OP_REQUESTPARTS byte = 0x47 // ED2K_C2C_REQUESTPARTS
	OP_SENDINGPART  byte = 0x46 // ED2K_C2C_SENDINGPART
)

// CamelCase aliases for the opcodes.
const (
	OpRequestParts = OP_REQUESTPARTS
	OpSendingPart  = OP_SENDINGPART
)

// Sentinel errors.
var (
	ErrRequestParts = errors.New("ed2k: malformed request parts")
	ErrSendingPart  = errors.New("ed2k: malformed sending part")
)

// --- RequestParts (OP_REQUESTPARTS) ---

// RequestParts is the payload of OP_REQUESTPARTS:
// <HASH 16><von[3] 4*3><bis[3] 4*3>.
type RequestParts struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte

	// Three "von" (start) offsets, one per requested range.
	Von    [3]uint32
	Vons   [3]uint32
	From   [3]uint32
	Froms  [3]uint32
	Start  [3]uint32
	Starts [3]uint32
	Begin  [3]uint32
	Begins [3]uint32

	Von1 uint32
	Von2 uint32
	Von3 uint32

	// Three "bis" (end) offsets, one per requested range.
	Bis     [3]uint32
	Biss    [3]uint32
	To      [3]uint32
	Tos     [3]uint32
	End     [3]uint32
	Ends    [3]uint32
	Finish  [3]uint32
	Finishes [3]uint32

	Bis1 uint32
	Bis2 uint32
	Bis3 uint32
}

func (r RequestParts) hashBytes() [16]byte {
	for _, h := range []([16]byte){r.Hash, r.FileHash, r.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

func (r RequestParts) vonArray() [3]uint32 {
	for _, a := range [][3]uint32{r.Von, r.Vons, r.From, r.Froms, r.Start, r.Starts, r.Begin, r.Begins} {
		if a != ([3]uint32{}) {
			return a
		}
	}
	if r.Von1 != 0 || r.Von2 != 0 || r.Von3 != 0 {
		return [3]uint32{r.Von1, r.Von2, r.Von3}
	}
	return [3]uint32{}
}

func (r RequestParts) bisArray() [3]uint32 {
	for _, a := range [][3]uint32{r.Bis, r.Biss, r.To, r.Tos, r.End, r.Ends, r.Finish, r.Finishes} {
		if a != ([3]uint32{}) {
			return a
		}
	}
	if r.Bis1 != 0 || r.Bis2 != 0 || r.Bis3 != 0 {
		return [3]uint32{r.Bis1, r.Bis2, r.Bis3}
	}
	return [3]uint32{}
}

func (r RequestParts) normalized() ([16]byte, [3]uint32, [3]uint32) {
	return r.hashBytes(), r.vonArray(), r.bisArray()
}

// Marshal encodes a RequestParts payload.
func (r RequestParts) Marshal() []byte {
	hash, von, bis := r.normalized()
	out := make([]byte, 16+3*4+3*4)
	copy(out[0:16], hash[:])
	off := 16
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint32(out[off:off+4], von[i])
		off += 4
	}
	for i := 0; i < 3; i++ {
		binary.LittleEndian.PutUint32(out[off:off+4], bis[i])
		off += 4
	}
	return out
}

// Encode is an alias.
func (r RequestParts) Encode() []byte { return r.Marshal() }

// Bytes is an alias.
func (r RequestParts) Bytes() []byte { return r.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (r RequestParts) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (r RequestParts) AppendTo(dst []byte) []byte {
	return append(dst, r.Marshal()...)
}

// DecodeRequestParts parses a RequestParts payload.
func DecodeRequestParts(b []byte) (RequestParts, error) {
	if len(b) < 16+3*4+3*4 {
		return RequestParts{}, fmt.Errorf("%w: %w", ErrRequestParts, ErrFrameTruncated)
	}
	if len(b) != 16+3*4+3*4 {
		return RequestParts{}, fmt.Errorf("%w: %w", ErrRequestParts, ErrFrameTrailing)
	}
	var r RequestParts
	copy(r.Hash[:], b[0:16])
	r.FileHash = r.Hash
	r.MD4 = r.Hash

	off := 16
	for i := 0; i < 3; i++ {
		r.Von[i] = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
	}
	r.Vons = r.Von
	r.From = r.Von
	r.Froms = r.Von
	r.Start = r.Von
	r.Starts = r.Von
	r.Begin = r.Von
	r.Begins = r.Von
	r.Von1 = r.Von[0]
	r.Von2 = r.Von[1]
	r.Von3 = r.Von[2]

	for i := 0; i < 3; i++ {
		r.Bis[i] = binary.LittleEndian.Uint32(b[off : off+4])
		off += 4
	}
	r.Biss = r.Bis
	r.To = r.Bis
	r.Tos = r.Bis
	r.End = r.Bis
	r.Ends = r.Bis
	r.Finish = r.Bis
	r.Finishes = r.Bis
	r.Bis1 = r.Bis[0]
	r.Bis2 = r.Bis[1]
	r.Bis3 = r.Bis[2]

	return r, nil
}

// ParseRequestParts is an alias.
func ParseRequestParts(b []byte) (RequestParts, error) { return DecodeRequestParts(b) }

// UnmarshalRequestParts is an alias.
func UnmarshalRequestParts(b []byte) (RequestParts, error) { return DecodeRequestParts(b) }

// Top-level helpers.
func EncodeRequestParts(r RequestParts) []byte { return r.Marshal() }
func MarshalRequestParts(r RequestParts) []byte { return r.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (r *RequestParts) Unmarshal(b []byte) error {
	g, err := DecodeRequestParts(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}

// Decode is a method form.
func (r *RequestParts) Decode(b []byte) error { return r.Unmarshal(b) }

// --- SendingPart (OP_SENDINGPART) ---

// SendingPart is the payload of OP_SENDINGPART:
// <HASH 16><von 4><bis 4><Daten len:(von-bis)>.
type SendingPart struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte

	// Start offset of the part data.
	Von    uint32
	From   uint32
	Start  uint32
	Begin  uint32
	Offset uint32

	// End offset (exclusive) of the part data.
	Bis    uint32
	To     uint32
	End    uint32
	Finish uint32

	// Part data.
	Data     []byte
	Body     []byte
	Payload  []byte
	PartData []byte
	Content  []byte
	Part     []byte
	Chunk    []byte
	Daten    []byte
}

func (s SendingPart) hashBytes() [16]byte {
	for _, h := range []([16]byte){s.Hash, s.FileHash, s.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

func (s SendingPart) vonValue() uint32 {
	for _, v := range []uint32{s.Von, s.From, s.Start, s.Begin, s.Offset} {
		if v != 0 {
			return v
		}
	}
	// allow explicit zero if all aliases zero; default 0
	if s.Von == 0 && s.From == 0 && s.Start == 0 && s.Begin == 0 && s.Offset == 0 {
		return 0
	}
	return s.Von
}

func (s SendingPart) bisValue() uint32 {
	for _, v := range []uint32{s.Bis, s.To, s.End, s.Finish} {
		if v != 0 {
			return v
		}
	}
	return s.Bis
}

func (s SendingPart) dataBytes() []byte {
	for _, d := range [][]byte{s.Data, s.Body, s.Payload, s.PartData, s.Content, s.Part, s.Chunk, s.Daten} {
		if d != nil {
			return d
		}
	}
	return nil
}

func (s SendingPart) normalized() ([16]byte, uint32, uint32, []byte) {
	von := s.vonValue()
	bis := s.bisValue()
	// If all von aliases were zero but a non-zero not captured? already handled.
	data := s.dataBytes()
	return s.hashBytes(), von, bis, data
}

// Marshal encodes a SendingPart payload.
func (s SendingPart) Marshal() []byte {
	hash, von, bis, data := s.normalized()
	out := make([]byte, 16+4+4+len(data))
	copy(out[0:16], hash[:])
	binary.LittleEndian.PutUint32(out[16:20], von)
	binary.LittleEndian.PutUint32(out[20:24], bis)
	copy(out[24:], data)
	return out
}

// Encode is an alias.
func (s SendingPart) Encode() []byte { return s.Marshal() }

// Bytes is an alias.
func (s SendingPart) Bytes() []byte { return s.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (s SendingPart) MarshalBinary() ([]byte, error) { return s.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (s SendingPart) AppendTo(dst []byte) []byte {
	return append(dst, s.Marshal()...)
}

// DecodeSendingPart parses a SendingPart payload.
func DecodeSendingPart(b []byte) (SendingPart, error) {
	if len(b) < 16+4+4 {
		return SendingPart{}, fmt.Errorf("%w: %w", ErrSendingPart, ErrFrameTruncated)
	}
	var s SendingPart
	copy(s.Hash[:], b[0:16])
	s.FileHash = s.Hash
	s.MD4 = s.Hash

	s.Von = binary.LittleEndian.Uint32(b[16:20])
	s.From = s.Von
	s.Start = s.Von
	s.Begin = s.Von
	s.Offset = s.Von

	s.Bis = binary.LittleEndian.Uint32(b[20:24])
	s.To = s.Bis
	s.End = s.Bis
	s.Finish = s.Bis

	data := cloneBytes(b[24:])
	s.Data = data
	s.Body = cloneBytes(data)
	s.Payload = cloneBytes(data)
	s.PartData = cloneBytes(data)
	s.Content = cloneBytes(data)
	s.Part = cloneBytes(data)
	s.Chunk = cloneBytes(data)
	s.Daten = cloneBytes(data)

	return s, nil
}

// ParseSendingPart is an alias.
func ParseSendingPart(b []byte) (SendingPart, error) { return DecodeSendingPart(b) }

// UnmarshalSendingPart is an alias.
func UnmarshalSendingPart(b []byte) (SendingPart, error) { return DecodeSendingPart(b) }

// Top-level helpers.
func EncodeSendingPart(s SendingPart) []byte { return s.Marshal() }
func MarshalSendingPart(s SendingPart) []byte { return s.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (s *SendingPart) Unmarshal(b []byte) error {
	g, err := DecodeSendingPart(b)
	if err != nil {
		return err
	}
	*s = g
	return nil
}

// Decode is a method form.
func (s *SendingPart) Decode(b []byte) error { return s.Unmarshal(b) }


