// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the ed2k client-to-client (C2C) file status codecs:
// OP_FILESTATUSREQUEST (0x4F) and OP_FILESTATUS (0x50). There is no networking,
// peer dialing, queue handling, hashset handling, file I/O, .part.met or
// Engine wiring here.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// File status opcodes. Values follow Shareaza's EDPacket.h
// (ED2K_C2C_FILESTATUSREQUEST / ED2K_C2C_FILESTATUS).
const (
	OP_FILESTATUSREQUEST byte = 0x4F // ED2K_C2C_FILESTATUSREQUEST
	OP_FILESTATUS        byte = 0x50 // ED2K_C2C_FILESTATUS
)

// CamelCase aliases for the opcodes.
const (
	OpFileStatusRequest = OP_FILESTATUSREQUEST
	OpFileStatus        = OP_FILESTATUS
)

// Sentinel errors.
var (
	ErrFileStatusRequest = errors.New("ed2k: malformed file status request")
	ErrFileStatus        = errors.New("ed2k: malformed file status")
)

// --- FileStatusRequest (OP_FILESTATUSREQUEST) ---

// FileStatusRequest is the payload of OP_FILESTATUSREQUEST:
// <HASH 16>.
type FileStatusRequest struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte
}

func (r FileStatusRequest) hashBytes() [16]byte {
	for _, h := range []([16]byte){r.Hash, r.FileHash, r.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

// Marshal encodes a FileStatusRequest payload.
func (r FileStatusRequest) Marshal() []byte {
	hash := r.hashBytes()
	out := make([]byte, 16)
	copy(out, hash[:])
	return out
}

// Encode is an alias.
func (r FileStatusRequest) Encode() []byte { return r.Marshal() }

// Bytes is an alias.
func (r FileStatusRequest) Bytes() []byte { return r.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (r FileStatusRequest) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (r FileStatusRequest) AppendTo(dst []byte) []byte {
	return append(dst, r.Marshal()...)
}

// DecodeFileStatusRequest parses a FileStatusRequest payload.
func DecodeFileStatusRequest(b []byte) (FileStatusRequest, error) {
	if len(b) < 16 {
		return FileStatusRequest{}, fmt.Errorf("%w: %w", ErrFileStatusRequest, ErrFrameTruncated)
	}
	if len(b) != 16 {
		return FileStatusRequest{}, fmt.Errorf("%w: %w", ErrFileStatusRequest, ErrFrameTrailing)
	}
	var r FileStatusRequest
	copy(r.Hash[:], b[0:16])
	r.FileHash = r.Hash
	r.MD4 = r.Hash
	return r, nil
}

// ParseFileStatusRequest is an alias.
func ParseFileStatusRequest(b []byte) (FileStatusRequest, error) {
	return DecodeFileStatusRequest(b)
}

// UnmarshalFileStatusRequest is an alias.
func UnmarshalFileStatusRequest(b []byte) (FileStatusRequest, error) {
	return DecodeFileStatusRequest(b)
}

// Top-level helpers.
func EncodeFileStatusRequest(r FileStatusRequest) []byte { return r.Marshal() }
func MarshalFileStatusRequest(r FileStatusRequest) []byte { return r.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (r *FileStatusRequest) Unmarshal(b []byte) error {
	g, err := DecodeFileStatusRequest(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (r *FileStatusRequest) UnmarshalBinary(b []byte) error { return r.Unmarshal(b) }

// Decode is a method form.
func (r *FileStatusRequest) Decode(b []byte) error { return r.Unmarshal(b) }

// --- FileStatus (OP_FILESTATUS) ---

// FileStatus is the payload of OP_FILESTATUS:
// <HASH 16><count u16 LE><status bit array, ceil(count/8) bytes>.
// Bit i of byte i/8 indicates part i, using Shareaza's 1 << (i % 8) ordering.
type FileStatus struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte

	// Number of parts in the status bitmap.
	Count      uint16
	NumParts   uint16
	BlockCount uint16
	NumBlocks  uint16

	// Status bitmap, ceil(Count/8) bytes.
	Status    []byte
	Bitmap    []byte
	Bits      []byte
	Available []byte
}

func (s FileStatus) hashBytes() [16]byte {
	for _, h := range []([16]byte){s.Hash, s.FileHash, s.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

func (s FileStatus) countValue() uint16 {
	for _, c := range []uint16{s.Count, s.NumParts, s.BlockCount, s.NumBlocks} {
		if c != 0 {
			return c
		}
	}
	return 0
}

func (s FileStatus) statusValue() []byte {
	for _, b := range [][]byte{s.Status, s.Bitmap, s.Bits, s.Available} {
		if b != nil {
			return b
		}
	}
	return nil
}

// Marshal encodes a FileStatus payload.
func (s FileStatus) Marshal() []byte {
	hash := s.hashBytes()
	count := s.countValue()
	needed := (int(count) + 7) / 8
	status := s.statusValue()
	out := make([]byte, 16+2+needed)
	copy(out[0:16], hash[:])
	binary.LittleEndian.PutUint16(out[16:18], count)
	if needed > 0 {
		if status != nil {
			copy(out[18:], status)
		}
	}
	return out
}

// Encode is an alias.
func (s FileStatus) Encode() []byte { return s.Marshal() }

// Bytes is an alias.
func (s FileStatus) Bytes() []byte { return s.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (s FileStatus) MarshalBinary() ([]byte, error) { return s.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (s FileStatus) AppendTo(dst []byte) []byte {
	return append(dst, s.Marshal()...)
}

// DecodeFileStatus parses a FileStatus payload.
func DecodeFileStatus(b []byte) (FileStatus, error) {
	if len(b) < 16+2 {
		return FileStatus{}, fmt.Errorf("%w: %w", ErrFileStatus, ErrFrameTruncated)
	}
	count := binary.LittleEndian.Uint16(b[16:18])
	needed := (int(count) + 7) / 8
	if len(b) < 16+2+needed {
		return FileStatus{}, fmt.Errorf("%w: %w", ErrFileStatus, ErrFrameTruncated)
	}
	if len(b) != 16+2+needed {
		return FileStatus{}, fmt.Errorf("%w: %w", ErrFileStatus, ErrFrameTrailing)
	}
	status := make([]byte, needed)
	copy(status, b[18:18+needed])
	var s FileStatus
	copy(s.Hash[:], b[0:16])
	s.FileHash = s.Hash
	s.MD4 = s.Hash
	s.Count = count
	s.NumParts = count
	s.BlockCount = count
	s.NumBlocks = count
	s.Status = status
	s.Bitmap = cloneBytes(status)
	s.Bits = cloneBytes(status)
	s.Available = cloneBytes(status)
	return s, nil
}

// ParseFileStatus is an alias.
func ParseFileStatus(b []byte) (FileStatus, error) { return DecodeFileStatus(b) }

// UnmarshalFileStatus is an alias.
func UnmarshalFileStatus(b []byte) (FileStatus, error) { return DecodeFileStatus(b) }

// Top-level helpers.
func EncodeFileStatus(s FileStatus) []byte { return s.Marshal() }
func MarshalFileStatus(s FileStatus) []byte { return s.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (s *FileStatus) Unmarshal(b []byte) error {
	g, err := DecodeFileStatus(b)
	if err != nil {
		return err
	}
	*s = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *FileStatus) UnmarshalBinary(b []byte) error { return s.Unmarshal(b) }

// Decode is a method form.
func (s *FileStatus) Decode(b []byte) error { return s.Unmarshal(b) }

// Bit reports whether part i is set in the status bitmap.
func (s FileStatus) Bit(i int) bool {
	status := s.statusValue()
	if status == nil {
		return false
	}
	if i < 0 {
		return false
	}
	byteIdx := i / 8
	if byteIdx < 0 || byteIdx >= len(status) {
		return false
	}
	return status[byteIdx]&(1<<uint(i%8)) != 0
}