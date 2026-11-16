// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the ed2k client-to-client (C2C) queue handling codecs:
// OP_QUEUEREQUEST (0x54), OP_STARTUPLOAD (0x55), OP_QUEUERELEASE (0x56),
// OP_FINISHUPLOAD (0x57) and OP_QUEUERANK (0x5C). There is no networking,
// scheduling, file I/O, .part.met or Engine wiring here.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Queue handling opcodes. Values follow Shareaza's EDPacket.h
// (ED2K_C2C_QUEUEREQUEST / ED2K_C2C_STARTUPLOAD / ED2K_C2C_QUEUERELEASE /
// ED2K_C2C_FINISHUPLOAD / ED2K_C2C_QUEUERANK).
const (
	OP_QUEUEREQUEST  byte = 0x54 // ED2K_C2C_QUEUEREQUEST
	OP_STARTUPLOAD   byte = 0x55 // ED2K_C2C_STARTUPLOAD
	OP_QUEUERELEASE  byte = 0x56 // ED2K_C2C_QUEUERELEASE
	OP_FINISHUPLOAD  byte = 0x57 // ED2K_C2C_FINISHUPLOAD
	OP_QUEUERANK     byte = 0x5C // ED2K_C2C_QUEUERANK
)

// CamelCase aliases for the opcodes.
const (
	OpQueueRequest = OP_QUEUEREQUEST
	OpStartUpload  = OP_STARTUPLOAD
	OpQueueRelease = OP_QUEUERELEASE
	OpFinishUpload = OP_FINISHUPLOAD
	OpQueueRank    = OP_QUEUERANK
)

// Sentinel errors.
var (
	ErrQueueRequest  = errors.New("ed2k: malformed queue request")
	ErrStartUpload   = errors.New("ed2k: malformed start upload")
	ErrQueueRelease  = errors.New("ed2k: malformed queue release")
	ErrFinishUpload  = errors.New("ed2k: malformed finish upload")
	ErrQueueRank     = errors.New("ed2k: malformed queue rank")

	ErrQueueRequestPayload  = errors.New("ed2k: queue request payload must be 16 bytes")
	ErrStartUploadPayload    = errors.New("ed2k: start upload payload must be empty")
	ErrQueueReleasePayload   = errors.New("ed2k: queue release payload must be empty")
	ErrFinishUploadPayload   = errors.New("ed2k: finish upload payload must be empty")
	ErrQueueRankPayload      = errors.New("ed2k: queue rank payload must be 4 bytes")
)

// --- QueueRequest (OP_QUEUEREQUEST) ---

// QueueRequest is the payload of OP_QUEUEREQUEST:
// <HASH 16>.
type QueueRequest struct {
	// File (root) MD4 hash.
	Hash     [16]byte
	FileHash [16]byte
	MD4      [16]byte
}

func (r QueueRequest) hashBytes() [16]byte {
	for _, h := range []([16]byte){r.Hash, r.FileHash, r.MD4} {
		if h != ([16]byte{}) {
			return h
		}
	}
	return [16]byte{}
}

// Marshal encodes a QueueRequest payload.
func (r QueueRequest) Marshal() []byte {
	hash := r.hashBytes()
	out := make([]byte, 16)
	copy(out, hash[:])
	return out
}

// Encode is an alias.
func (r QueueRequest) Encode() []byte { return r.Marshal() }

// Bytes is an alias.
func (r QueueRequest) Bytes() []byte { return r.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (r QueueRequest) MarshalBinary() ([]byte, error) { return r.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (r QueueRequest) AppendTo(dst []byte) []byte {
	return append(dst, r.Marshal()...)
}

// DecodeQueueRequest parses a QueueRequest payload.
func DecodeQueueRequest(b []byte) (QueueRequest, error) {
	if len(b) < 16 {
		return QueueRequest{}, fmt.Errorf("%w: %w", ErrQueueRequest, ErrFrameTruncated)
	}
	if len(b) != 16 {
		return QueueRequest{}, fmt.Errorf("%w: %w", ErrQueueRequest, ErrFrameTrailing)
	}
	var r QueueRequest
	copy(r.Hash[:], b[0:16])
	r.FileHash = r.Hash
	r.MD4 = r.Hash
	return r, nil
}

// ParseQueueRequest is an alias.
func ParseQueueRequest(b []byte) (QueueRequest, error) { return DecodeQueueRequest(b) }

// UnmarshalQueueRequest is an alias.
func UnmarshalQueueRequest(b []byte) (QueueRequest, error) { return DecodeQueueRequest(b) }

// Top-level helpers.
func EncodeQueueRequest(r QueueRequest) []byte { return r.Marshal() }
func MarshalQueueRequest(r QueueRequest) []byte { return r.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (r *QueueRequest) Unmarshal(b []byte) error {
	g, err := DecodeQueueRequest(b)
	if err != nil {
		return err
	}
	*r = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (r *QueueRequest) UnmarshalBinary(b []byte) error { return r.Unmarshal(b) }

// Decode is a method form.
func (r *QueueRequest) Decode(b []byte) error { return r.Unmarshal(b) }

// --- StartUpload (OP_STARTUPLOAD) ---

// StartUpload is the payload of OP_STARTUPLOAD (empty).
type StartUpload struct{}

// Marshal encodes a StartUpload payload (empty).
func (StartUpload) Marshal() []byte { return []byte{} }

// Encode is an alias.
func (StartUpload) Encode() []byte { return []byte{} }

// Bytes is an alias.
func (StartUpload) Bytes() []byte { return []byte{} }

// MarshalBinary implements encoding.BinaryMarshaler.
func (StartUpload) MarshalBinary() ([]byte, error) { return []byte{}, nil }

// AppendTo appends the encoding to dst.
func (StartUpload) AppendTo(dst []byte) []byte {
	return append(dst, []byte{}...)
}

// DecodeStartUpload parses a StartUpload payload.
func DecodeStartUpload(b []byte) (StartUpload, error) {
	if len(b) != 0 {
		return StartUpload{}, ErrStartUploadPayload
	}
	return StartUpload{}, nil
}

// ParseStartUpload is an alias.
func ParseStartUpload(b []byte) (StartUpload, error) { return DecodeStartUpload(b) }

// UnmarshalStartUpload is an alias.
func UnmarshalStartUpload(b []byte) (StartUpload, error) { return DecodeStartUpload(b) }

// Top-level helpers.
func EncodeStartUpload(s StartUpload) []byte { return s.Marshal() }
func MarshalStartUpload(s StartUpload) []byte { return s.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (s *StartUpload) Unmarshal(b []byte) error {
	_, err := DecodeStartUpload(b)
	return err
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (s *StartUpload) UnmarshalBinary(b []byte) error { return s.Unmarshal(b) }

// Decode is a method form.
func (s *StartUpload) Decode(b []byte) error { return s.Unmarshal(b) }

// --- QueueRelease (OP_QUEUERELEASE) ---

// QueueRelease is the payload of OP_QUEUERELEASE (empty).
type QueueRelease struct{}

// Marshal encodes a QueueRelease payload (empty).
func (QueueRelease) Marshal() []byte { return []byte{} }

// Encode is an alias.
func (QueueRelease) Encode() []byte { return []byte{} }

// Bytes is an alias.
func (QueueRelease) Bytes() []byte { return []byte{} }

// MarshalBinary implements encoding.BinaryMarshaler.
func (QueueRelease) MarshalBinary() ([]byte, error) { return []byte{}, nil }

// AppendTo appends the encoding to dst.
func (QueueRelease) AppendTo(dst []byte) []byte {
	return append(dst, []byte{}...)
}

// DecodeQueueRelease parses a QueueRelease payload.
func DecodeQueueRelease(b []byte) (QueueRelease, error) {
	if len(b) != 0 {
		return QueueRelease{}, ErrQueueReleasePayload
	}
	return QueueRelease{}, nil
}

// ParseQueueRelease is an alias.
func ParseQueueRelease(b []byte) (QueueRelease, error) { return DecodeQueueRelease(b) }

// UnmarshalQueueRelease is an alias.
func UnmarshalQueueRelease(b []byte) (QueueRelease, error) { return DecodeQueueRelease(b) }

// Top-level helpers.
func EncodeQueueRelease(r QueueRelease) []byte { return r.Marshal() }
func MarshalQueueRelease(r QueueRelease) []byte { return r.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (r *QueueRelease) Unmarshal(b []byte) error {
	_, err := DecodeQueueRelease(b)
	return err
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (r *QueueRelease) UnmarshalBinary(b []byte) error { return r.Unmarshal(b) }

// Decode is a method form.
func (r *QueueRelease) Decode(b []byte) error { return r.Unmarshal(b) }

// --- FinishUpload (OP_FINISHUPLOAD) ---

// FinishUpload is the payload of OP_FINISHUPLOAD (empty).
type FinishUpload struct{}

// Marshal encodes a FinishUpload payload (empty).
func (FinishUpload) Marshal() []byte { return []byte{} }

// Encode is an alias.
func (FinishUpload) Encode() []byte { return []byte{} }

// Bytes is an alias.
func (FinishUpload) Bytes() []byte { return []byte{} }

// MarshalBinary implements encoding.BinaryMarshaler.
func (FinishUpload) MarshalBinary() ([]byte, error) { return []byte{}, nil }

// AppendTo appends the encoding to dst.
func (FinishUpload) AppendTo(dst []byte) []byte {
	return append(dst, []byte{}...)
}

// DecodeFinishUpload parses a FinishUpload payload.
func DecodeFinishUpload(b []byte) (FinishUpload, error) {
	if len(b) != 0 {
		return FinishUpload{}, ErrFinishUploadPayload
	}
	return FinishUpload{}, nil
}

// ParseFinishUpload is an alias.
func ParseFinishUpload(b []byte) (FinishUpload, error) { return DecodeFinishUpload(b) }

// UnmarshalFinishUpload is an alias.
func UnmarshalFinishUpload(b []byte) (FinishUpload, error) { return DecodeFinishUpload(b) }

// Top-level helpers.
func EncodeFinishUpload(f FinishUpload) []byte { return f.Marshal() }
func MarshalFinishUpload(f FinishUpload) []byte { return f.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (f *FinishUpload) Unmarshal(b []byte) error {
	_, err := DecodeFinishUpload(b)
	return err
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (f *FinishUpload) UnmarshalBinary(b []byte) error { return f.Unmarshal(b) }

// Decode is a method form.
func (f *FinishUpload) Decode(b []byte) error { return f.Unmarshal(b) }

// --- QueueRank (OP_QUEUERANK) ---

// QueueRank is the payload of OP_QUEUERANK:
// <uint32> rank/slot.
type QueueRank struct {
	Rank          uint32
	Slot          uint32
	Position      uint32
	Index         uint32
	Value         uint32
	Number        uint32
	Wert          uint32
	SlotIndex     uint32
	RankIndex     uint32
	QueueRank     uint32
	QueueSlot     uint32
	QueuePosition uint32
	QueueIndex    uint32
	QueueValue    uint32
	QueueNumber   uint32
}

func (q QueueRank) rankValue() uint32 {
	for _, v := range []uint32{q.Rank, q.Slot, q.Position, q.Index, q.Value, q.Number, q.Wert, q.SlotIndex, q.RankIndex, q.QueueRank, q.QueueSlot, q.QueuePosition, q.QueueIndex, q.QueueValue, q.QueueNumber} {
		if v != 0 {
			return v
		}
	}
	return 0
}

// Marshal encodes a QueueRank payload.
func (q QueueRank) Marshal() []byte {
	v := q.rankValue()
	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, v)
	return out
}

// Encode is an alias.
func (q QueueRank) Encode() []byte { return q.Marshal() }

// Bytes is an alias.
func (q QueueRank) Bytes() []byte { return q.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (q QueueRank) MarshalBinary() ([]byte, error) { return q.Marshal(), nil }

// AppendTo appends the encoding to dst.
func (q QueueRank) AppendTo(dst []byte) []byte {
	return append(dst, q.Marshal()...)
}

// DecodeQueueRank parses a QueueRank payload.
func DecodeQueueRank(b []byte) (QueueRank, error) {
	if len(b) < 4 {
		return QueueRank{}, fmt.Errorf("%w: %w", ErrQueueRank, ErrFrameTruncated)
	}
	if len(b) != 4 {
		return QueueRank{}, fmt.Errorf("%w: %w", ErrQueueRank, ErrFrameTrailing)
	}
	v := binary.LittleEndian.Uint32(b[0:4])
	q := QueueRank{
		Rank:          v,
		Slot:          v,
		Position:      v,
		Index:         v,
		Value:         v,
		Number:        v,
		Wert:          v,
		SlotIndex:     v,
		RankIndex:     v,
		QueueRank:     v,
		QueueSlot:     v,
		QueuePosition: v,
		QueueIndex:    v,
		QueueValue:    v,
		QueueNumber:   v,
	}
	return q, nil
}

// ParseQueueRank is an alias.
func ParseQueueRank(b []byte) (QueueRank, error) { return DecodeQueueRank(b) }

// UnmarshalQueueRank is an alias.
func UnmarshalQueueRank(b []byte) (QueueRank, error) { return DecodeQueueRank(b) }

// Top-level helpers.
func EncodeQueueRank(q QueueRank) []byte { return q.Marshal() }
func MarshalQueueRank(q QueueRank) []byte { return q.Marshal() }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (q *QueueRank) Unmarshal(b []byte) error {
	g, err := DecodeQueueRank(b)
	if err != nil {
		return err
	}
	*q = g
	return nil
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler.
func (q *QueueRank) UnmarshalBinary(b []byte) error { return q.Unmarshal(b) }

// Decode is a method form.
func (q *QueueRank) Decode(b []byte) error { return q.Unmarshal(b) }
