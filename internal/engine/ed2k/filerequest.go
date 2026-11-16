// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the ed2k client-to-client (C2C) file-request handshake
// codecs: OP_FILEREQUEST (0x58), OP_FILEREQANSWER (0x59) and OP_FILENOTFOUND
// (0x48). There is no networking, peer dialing, obfuscation, file I/O,
// .part.met or Engine wiring here.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// File-request opcodes. Values follow Shareaza's EDPacket.h
// (ED2K_C2C_FILEREQUEST / ED2K_C2C_FILEREQANSWER / ED2K_C2C_FILENOTFOUND).
const (
	OP_FILEREQUEST   byte = 0x58 // ED2K_C2C_FILEREQUEST
	OP_FILEREQANSWER byte = 0x59 // ED2K_C2C_FILEREQANSWER
	OP_FILENOTFOUND  byte = 0x48 // ED2K_C2C_FILENOTFOUND
)

// CamelCase aliases for the opcodes.
const (
	OpFileRequest   = OP_FILEREQUEST
	OpFileReqAnswer = OP_FILEREQANSWER
	OpFileNotFound  = OP_FILENOTFOUND
)

// Sentinel errors.
var (
	ErrFileRequest   = errors.New("ed2k: malformed file request")
	ErrFileReqAnswer = errors.New("ed2k: malformed file request answer")
	ErrFileNotFound  = errors.New("ed2k: malformed file not found")
)

// --- FileRequest (OP_FILEREQUEST) ---

// FileRequest is the payload of OP_FILEREQUEST:
// <HASH 16>.
type FileRequest struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte
}

func (r FileRequest) hashBytes() [16]byte {
	for _, h := range []([16]byte){r.Hash, r.FileHash, r.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

// Marshal encodes a FileRequest payload.
func (r FileRequest) Marshal() []byte {
	hash := r.hashBytes()
	out := make([]byte, 16)
	copy(out, hash[:])
	return out
}

// Encode is an alias.
func (r FileRequest) Encode() []byte { return r.Marshal() }

// Bytes is an alias.
func (r FileRequest) Bytes() []byte { return r.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (r FileRequest) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (r FileRequest) AppendTo(dst []byte) []byte {
	return append(dst, r.Marshal()...)
}

// DecodeFileRequest parses a FileRequest payload.
func DecodeFileRequest(b []byte) (FileRequest, error) {
	if len(b) < 16 {
		return FileRequest{}, fmt.Errorf("%w: %w", ErrFileRequest, ErrFrameTruncated)
	}
	if len(b) != 16 {
		return FileRequest{}, fmt.Errorf("%w: %w", ErrFileRequest, ErrFrameTrailing)
	}
	var r FileRequest
	copy(r.Hash[:], b[0:16])
	r.FileHash = r.Hash
	r.MD4 = r.Hash
	return r, nil
}

// ParseFileRequest is an alias.
func ParseFileRequest(b []byte) (FileRequest, error) { return DecodeFileRequest(b) }

// UnmarshalFileRequest is an alias.
func UnmarshalFileRequest(b []byte) (FileRequest, error) { return DecodeFileRequest(b) }

// Top-level helpers.
func EncodeFileRequest(r FileRequest) []byte { return r.Marshal() }
func MarshalFileRequest(r FileRequest) []byte { return r.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (r *FileRequest) Unmarshal(b []byte) error {
	g, err := DecodeFileRequest(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (r *FileRequest) UnmarshalBinary(b []byte) error { return r.Unmarshal(b) }

// Decode is a method form.
func (r *FileRequest) Decode(b []byte) error { return r.Unmarshal(b) }

// --- FileReqAnswer (OP_FILEREQANSWER) ---

// FileReqAnswer is the payload of OP_FILEREQANSWER:
// <HASH 16><len u16 little-endian><name bytes>.
type FileReqAnswer struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte

	// Filename (alias fields).
	Name     string
	Filename string
	FileName string
}

func (a FileReqAnswer) hashBytes() [16]byte {
	for _, h := range []([16]byte){a.Hash, a.FileHash, a.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

func (a FileReqAnswer) nameValue() string {
	for _, n := range []string{a.Name, a.Filename, a.FileName} {
		if n != "" {
			return n
		}
	}
	return ""
}

// Marshal encodes a FileReqAnswer payload.
func (a FileReqAnswer) Marshal() []byte {
	hash := a.hashBytes()
	name := a.nameValue()
	out := make([]byte, 16+2+len(name))
	copy(out[0:16], hash[:])
	binary.LittleEndian.PutUint16(out[16:18], uint16(len(name)))
	copy(out[18:], name)
	return out
}

// Encode is an alias.
func (a FileReqAnswer) Encode() []byte { return a.Marshal() }

// Bytes is an alias.
func (a FileReqAnswer) Bytes() []byte { return a.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (a FileReqAnswer) MarshalBinary() ([]byte, error) { return a.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (a FileReqAnswer) AppendTo(dst []byte) []byte {
	return append(dst, a.Marshal()...)
}

// DecodeFileReqAnswer parses a FileReqAnswer payload.
func DecodeFileReqAnswer(b []byte) (FileReqAnswer, error) {
	if len(b) < 16+2 {
		return FileReqAnswer{}, fmt.Errorf("%w: %w", ErrFileReqAnswer, ErrFrameTruncated)
	}
	n := int(binary.LittleEndian.Uint16(b[16:18]))
	if len(b) < 16+2+n {
		return FileReqAnswer{}, fmt.Errorf("%w: %w", ErrFileReqAnswer, ErrFrameTruncated)
	}
	if len(b) != 16+2+n {
		return FileReqAnswer{}, fmt.Errorf("%w: %w", ErrFileReqAnswer, ErrFrameTrailing)
	}
	name := string(b[18 : 18+n])
	var a FileReqAnswer
	copy(a.Hash[:], b[0:16])
	a.FileHash = a.Hash
	a.MD4 = a.Hash
	a.Name = name
	a.Filename = name
	a.FileName = name
	return a, nil
}

// ParseFileReqAnswer is an alias.
func ParseFileReqAnswer(b []byte) (FileReqAnswer, error) { return DecodeFileReqAnswer(b) }

// UnmarshalFileReqAnswer is an alias.
func UnmarshalFileReqAnswer(b []byte) (FileReqAnswer, error) { return DecodeFileReqAnswer(b) }

// Top-level helpers.
func EncodeFileReqAnswer(a FileReqAnswer) []byte { return a.Marshal() }
func MarshalFileReqAnswer(a FileReqAnswer) []byte { return a.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (a *FileReqAnswer) Unmarshal(b []byte) error {
	g, err := DecodeFileReqAnswer(b)
	if err != nil {
		return err
	}
	*a = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (a *FileReqAnswer) UnmarshalBinary(b []byte) error { return a.Unmarshal(b) }

// Decode is a method form.
func (a *FileReqAnswer) Decode(b []byte) error { return a.Unmarshal(b) }

// --- FileNotFound (OP_FILENOTFOUND) ---

// FileNotFound is the payload of OP_FILENOTFOUND:
// <HASH 16>.
type FileNotFound struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte
}

func (f FileNotFound) hashBytes() [16]byte {
	for _, h := range []([16]byte){f.Hash, f.FileHash, f.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

// Marshal encodes a FileNotFound payload.
func (f FileNotFound) Marshal() []byte {
	hash := f.hashBytes()
	out := make([]byte, 16)
	copy(out, hash[:])
	return out
}

// Encode is an alias.
func (f FileNotFound) Encode() []byte { return f.Marshal() }

// Bytes is an alias.
func (f FileNotFound) Bytes() []byte { return f.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (f FileNotFound) MarshalBinary() ([]byte, error) { return f.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (f FileNotFound) AppendTo(dst []byte) []byte {
	return append(dst, f.Marshal()...)
}

// DecodeFileNotFound parses a FileNotFound payload.
func DecodeFileNotFound(b []byte) (FileNotFound, error) {
	if len(b) < 16 {
		return FileNotFound{}, fmt.Errorf("%w: %w", ErrFileNotFound, ErrFrameTruncated)
	}
	if len(b) != 16 {
		return FileNotFound{}, fmt.Errorf("%w: %w", ErrFileNotFound, ErrFrameTrailing)
	}
	var f FileNotFound
	copy(f.Hash[:], b[0:16])
	f.FileHash = f.Hash
	f.MD4 = f.Hash
	return f, nil
}

// ParseFileNotFound is an alias.
func ParseFileNotFound(b []byte) (FileNotFound, error) { return DecodeFileNotFound(b) }

// UnmarshalFileNotFound is an alias.
func UnmarshalFileNotFound(b []byte) (FileNotFound, error) { return DecodeFileNotFound(b) }

// Top-level helpers.
func EncodeFileNotFound(f FileNotFound) []byte { return f.Marshal() }
func MarshalFileNotFound(f FileNotFound) []byte { return f.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (f *FileNotFound) Unmarshal(b []byte) error {
	g, err := DecodeFileNotFound(b)
	if err != nil {
		return err
	}
	*f = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (f *FileNotFound) UnmarshalBinary(b []byte) error { return f.Unmarshal(b) }

// Decode is a method form.
func (f *FileNotFound) Decode(b []byte) error { return f.Unmarshal(b) }
