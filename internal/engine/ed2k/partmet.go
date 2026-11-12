// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the .part.met file format codec. A .part.met record
// describes a single file being downloaded: its size, its root MD4 hash,
// the eDonkey part size, the ordered per-part MD4 hashes, and an optional
// file name. No networking, range mapping, AICH or canonical-block
// integration is performed here.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Caps bounding allocations in malformed-input and fuzz paths.
const (
	MaxPartMetParts    = 1 << 16
	MaxPartMetNameLen  = 1 << 16
)

// Sentinel errors.
var (
	ErrPartMet           = errors.New("ed2k: malformed part.met")
	ErrPartMetTruncated  = errors.New("ed2k: truncated part.met")
	ErrPartMetTrailing   = errors.New("ed2k: trailing bytes in part.met")
	ErrPartMetTooMany    = errors.New("ed2k: too many parts in part.met")
	ErrPartMetBadNameLen = errors.New("ed2k: invalid part.met name length")
)

// PartMet is one .part.met record.
type PartMet struct {
	// File size (bytes).
	FileSize  uint64
	Size      uint64
	Length    uint64
	TotalSize uint64

	// File (root) MD4 hash.
	FileHash [16]byte
	Hash     [16]byte
	MD4      [16]byte

	// eDonkey part size (bytes).
	PartSize uint64
	PartLen  uint64

	// Ordered per-part MD4 hashes.
	PartHashes [][16]byte
	Parts      [][16]byte
	Hashes     [][16]byte

	// Optional file name.
	FileName string
	Name     string
	Filename string
}

// normalized resolves the alias fields into one canonical set of values.
func (p PartMet) normalized() (uint64, [16]byte, uint64, [][16]byte, string) {
	size := p.FileSize
	if size == 0 {
		if p.Size != 0 {
			size = p.Size
		} else if p.Length != 0 {
			size = p.Length
		} else if p.TotalSize != 0 {
			size = p.TotalSize
		}
	}
	hash := p.FileHash
	if hash == ([16]byte{}) {
		if p.Hash != ([16]byte{}) {
			hash = p.Hash
		} else if p.MD4 != ([16]byte{}) {
			hash = p.MD4
		}
	}
	partSize := p.PartSize
	if partSize == 0 {
		partSize = p.PartLen
	}
	parts := p.PartHashes
	if parts == nil {
		if p.Parts != nil {
			parts = p.Parts
		} else if p.Hashes != nil {
			parts = p.Hashes
		}
	}
	name := p.FileName
	if name == "" {
		if p.Name != "" {
			name = p.Name
		} else {
			name = p.Filename
		}
	}
	return size, hash, partSize, parts, name
}

// clonePartHashes returns a copy of in (nil stays nil).
func clonePartHashes(in [][16]byte) [][16]byte {
	if in == nil {
		return nil
	}
	out := make([][16]byte, len(in))
	copy(out, in)
	return out
}

// Marshal encodes the PartMet to its binary form.
func (p PartMet) Marshal() []byte {
	size, hash, partSize, parts, name := p.normalized()
	out := make([]byte, 0, 8+16+8+4+len(parts)*16+2+len(name))
	b8 := make([]byte, 8)
	binary.LittleEndian.PutUint64(b8, size)
	out = append(out, b8...)
	out = append(out, hash[:]...)
	binary.LittleEndian.PutUint64(b8, partSize)
	out = append(out, b8...)
	b4 := make([]byte, 4)
	binary.LittleEndian.PutUint32(b4, uint32(len(parts)))
	out = append(out, b4...)
	for _, h := range parts {
		out = append(out, h[:]...)
	}
	b2 := make([]byte, 2)
	binary.LittleEndian.PutUint16(b2, uint16(len(name)))
	out = append(out, b2...)
	out = append(out, []byte(name)...)
	return out
}

// Encode is an alias for Marshal.
func (p PartMet) Encode() []byte { return p.Marshal() }

// Bytes is an alias for Marshal.
func (p PartMet) Bytes() []byte { return p.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (p PartMet) MarshalBinary() ([]byte, error) { return p.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (p PartMet) AppendTo(dst []byte) []byte {
	return append(dst, p.Marshal()...)
}

// DecodePartMet parses a PartMet from b.
func DecodePartMet(b []byte) (PartMet, error) {
	off := 0
	if len(b) < 8+16+8+4 {
		return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetTruncated)
	}
	size := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8
	var hash [16]byte
	copy(hash[:], b[off:off+16])
	off += 16
	partSize := binary.LittleEndian.Uint64(b[off : off+8])
	off += 8
	count := binary.LittleEndian.Uint32(b[off : off+4])
	off += 4
	if count > MaxPartMetParts {
		return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetTooMany)
	}
	if off+int(count)*16 > len(b) {
		return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetTruncated)
	}
	parts := make([][16]byte, count)
	for i := uint32(0); i < count; i++ {
		copy(parts[i][:], b[off:off+16])
		off += 16
	}
	if off+2 > len(b) {
		return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetTruncated)
	}
	nameLen := int(binary.LittleEndian.Uint16(b[off : off+2]))
	off += 2
	if nameLen > MaxPartMetNameLen {
		return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetBadNameLen)
	}
	if off+nameLen > len(b) {
		return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetTruncated)
	}
	name := string(b[off : off+nameLen])
	off += nameLen
	if off != len(b) {
		if off > len(b) {
			return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetTruncated)
		}
		return PartMet{}, fmt.Errorf("%w: %w", ErrPartMet, ErrPartMetTrailing)
	}
	cp := clonePartHashes(parts)
	pm := PartMet{
		FileSize:   size,
		Size:       size,
		Length:     size,
		TotalSize:  size,

		FileHash: hash,
		Hash:     hash,
		MD4:      hash,

		PartSize: partSize,
		PartLen:  partSize,

		PartHashes: cp,
		Parts:      clonePartHashes(cp),
		Hashes:     clonePartHashes(cp),

		FileName: name,
		Name:     name,
		Filename: name,
	}
	return pm, nil
}

// ParsePartMet is an alias for DecodePartMet.
func ParsePartMet(b []byte) (PartMet, error) { return DecodePartMet(b) }

// UnmarshalPartMet is an alias for DecodePartMet.
func UnmarshalPartMet(b []byte) (PartMet, error) { return DecodePartMet(b) }

// Top-level helpers.
func EncodePartMet(p PartMet) []byte { return p.Marshal() }
func MarshalPartMet(p PartMet) []byte { return p.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (p *PartMet) Unmarshal(b []byte) error {
	g, err := DecodePartMet(b)
	if err != nil {
		return err
	}
	*p = g
	return nil
}

// Decode is a method form.
func (p *PartMet) Decode(b []byte) error { return p.Unmarshal(b) }


