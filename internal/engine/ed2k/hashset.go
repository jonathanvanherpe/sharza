// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the ed2k client-to-client (C2C) hash-set codecs:
// OP_HASHSETREQUEST (0x51) and OP_HASHSETANSWER (0x52). There is no networking,
// file I/O, AICH integration, .part.met or Engine wiring here.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Hash-set opcodes. Values follow Shareaza's EDPacket.h
// (ED2K_C2C_HASHSETREQUEST / ED2K_C2C_HASHSETANSWER).
const (
	OP_HASHSETREQUEST byte = 0x51 // ED2K_C2C_HASHSETREQUEST
	OP_HASHSETANSWER  byte = 0x52 // ED2K_C2C_HASHSETANSWER
)

// CamelCase aliases for the opcodes.
const (
	OpHashSetRequest = OP_HASHSETREQUEST
	OpHashSetAnswer  = OP_HASHSETANSWER
)

// Sentinel errors.
var (
	ErrHashSetRequest = errors.New("ed2k: malformed hash set request")
	ErrHashSetAnswer  = errors.New("ed2k: malformed hash set answer")
)

// --- HashSetRequest (OP_HASHSETREQUEST) ---

// HashSetRequest is the payload of OP_HASHSETREQUEST:
// <HASH 16>.
type HashSetRequest struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte
}

func (r HashSetRequest) hashBytes() [16]byte {
	for _, h := range []([16]byte){r.Hash, r.FileHash, r.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

// Marshal encodes a HashSetRequest payload.
func (r HashSetRequest) Marshal() []byte {
	hash := r.hashBytes()
	out := make([]byte, 16)
	copy(out, hash[:])
	return out
}

// Encode is an alias.
func (r HashSetRequest) Encode() []byte { return r.Marshal() }

// Bytes is an alias.
func (r HashSetRequest) Bytes() []byte { return r.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (r HashSetRequest) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (r HashSetRequest) AppendTo(dst []byte) []byte {
	return append(dst, r.Marshal()...)
}

// DecodeHashSetRequest parses a HashSetRequest payload.
func DecodeHashSetRequest(b []byte) (HashSetRequest, error) {
	if len(b) < 16 {
		return HashSetRequest{}, fmt.Errorf("%w: %w", ErrHashSetRequest, ErrFrameTruncated)
	}
	if len(b) != 16 {
		return HashSetRequest{}, fmt.Errorf("%w: %w", ErrHashSetRequest, ErrFrameTrailing)
	}
	var r HashSetRequest
	copy(r.Hash[:], b[0:16])
	r.FileHash = r.Hash
	r.MD4 = r.Hash
	return r, nil
}

// ParseHashSetRequest is an alias.
func ParseHashSetRequest(b []byte) (HashSetRequest, error) { return DecodeHashSetRequest(b) }

// UnmarshalHashSetRequest is an alias.
func UnmarshalHashSetRequest(b []byte) (HashSetRequest, error) { return DecodeHashSetRequest(b) }

// Top-level helpers.
func EncodeHashSetRequest(r HashSetRequest) []byte { return r.Marshal() }
func MarshalHashSetRequest(r HashSetRequest) []byte { return r.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (r *HashSetRequest) Unmarshal(b []byte) error {
	g, err := DecodeHashSetRequest(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (r *HashSetRequest) UnmarshalBinary(b []byte) error { return r.Unmarshal(b) }

// Decode is a method form.
func (r *HashSetRequest) Decode(b []byte) error { return r.Unmarshal(b) }

// --- HashSetAnswer (OP_HASHSETANSWER) ---

// HashSetAnswer is the payload of OP_HASHSETANSWER:
// <count u16 LE><HASH[count] 16*count>.
type HashSetAnswer struct {
	// Number of hashes in the set (alias fields).
	Count      uint16
	NumHashes  uint16
	BlockCount uint16
	NumBlocks  uint16
	N          uint16
	Length     uint16
	Len        uint16
	Total      uint16

	// Ordered set of hashes (alias fields).
	Hashes    [][16]byte
	Blocks    [][16]byte
	HashList  [][16]byte
	Entries   [][16]byte
	Items     [][16]byte
	Data      [][16]byte
	List      [][16]byte
	Values    [][16]byte
}

func (a HashSetAnswer) countValue() uint16 {
	for _, c := range []uint16{a.Count, a.NumHashes, a.BlockCount, a.NumBlocks, a.N, a.Length, a.Len, a.Total} {
		if c != 0 {
			return c
		}
	}
	if hs := a.hashesValue(); hs != nil {
		if len(hs) > 0xFFFF {
			return 0xFFFF
		}
		return uint16(len(hs))
	}
	return 0
}

func (a HashSetAnswer) hashesValue() [][16]byte {
	for _, h := range [][][16]byte{a.Hashes, a.Blocks, a.HashList, a.Entries, a.Items, a.Data, a.List, a.Values} {
		if h != nil {
			return h
		}
	}
	return nil
}

func cloneHashes(in [][16]byte) [][16]byte {
	if in == nil {
		return nil
	}
	out := make([][16]byte, len(in))
	copy(out, in)
	return out
}

// Marshal encodes a HashSetAnswer payload.
func (a HashSetAnswer) Marshal() []byte {
	count := a.countValue()
	hashes := a.hashesValue()
	out := make([]byte, 2+int(count)*16)
	binary.LittleEndian.PutUint16(out[0:2], count)
	if hashes != nil {
		for i := 0; i < int(count) && i < len(hashes); i++ {
			copy(out[2+i*16:], hashes[i][:])
		}
	}
	return out
}

// Encode is an alias.
func (a HashSetAnswer) Encode() []byte { return a.Marshal() }

// Bytes is an alias.
func (a HashSetAnswer) Bytes() []byte { return a.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (a HashSetAnswer) MarshalBinary() ([]byte, error) { return a.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (a HashSetAnswer) AppendTo(dst []byte) []byte {
	return append(dst, a.Marshal()...)
}

// DecodeHashSetAnswer parses a HashSetAnswer payload.
func DecodeHashSetAnswer(b []byte) (HashSetAnswer, error) {
	if len(b) < 2 {
		return HashSetAnswer{}, fmt.Errorf("%w: %w", ErrHashSetAnswer, ErrFrameTruncated)
	}
	count := binary.LittleEndian.Uint16(b[0:2])
	needed := int(count) * 16
	if len(b) < 2+needed {
		return HashSetAnswer{}, fmt.Errorf("%w: %w", ErrHashSetAnswer, ErrFrameTruncated)
	}
	if len(b) != 2+needed {
		return HashSetAnswer{}, fmt.Errorf("%w: %w", ErrHashSetAnswer, ErrFrameTrailing)
	}
	hashes := make([][16]byte, count)
	for i := 0; i < int(count); i++ {
		copy(hashes[i][:], b[2+i*16:2+i*16+16])
	}
	cloned := cloneHashes(hashes)
	a := HashSetAnswer{
		Count:      count,
		NumHashes:  count,
		BlockCount: count,
		NumBlocks:  count,
		N:          count,
		Length:     count,
		Len:        count,
		Total:      count,
		Hashes:     hashes,
		Blocks:     cloneHashes(cloned),
		HashList:   cloneHashes(cloned),
		Entries:    cloneHashes(cloned),
		Items:      cloneHashes(cloned),
		Data:       cloneHashes(cloned),
		List:       cloneHashes(cloned),
		Values:     cloneHashes(cloned),
	}
	return a, nil
}

// ParseHashSetAnswer is an alias.
func ParseHashSetAnswer(b []byte) (HashSetAnswer, error) { return DecodeHashSetAnswer(b) }

// UnmarshalHashSetAnswer is an alias.
func UnmarshalHashSetAnswer(b []byte) (HashSetAnswer, error) { return DecodeHashSetAnswer(b) }

// Top-level helpers.
func EncodeHashSetAnswer(a HashSetAnswer) []byte { return a.Marshal() }
func MarshalHashSetAnswer(a HashSetAnswer) []byte { return a.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (a *HashSetAnswer) Unmarshal(b []byte) error {
	g, err := DecodeHashSetAnswer(b)
	if err != nil {
		return err
	}
	*a = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (a *HashSetAnswer) UnmarshalBinary(b []byte) error { return a.Unmarshal(b) }

// Decode is a method form.
func (a *HashSetAnswer) Decode(b []byte) error { return a.Unmarshal(b) }
