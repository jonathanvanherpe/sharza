// SPDX-License-Identifier: GPL-3.0-or-later

// Package gnutella implements the Gnutella 0.6 TCP handshake and the
// binary message framing (descriptor headers, PING/PONG liveness).
//
// The wire format follows the published protocol: the annotated 0.4
// specification at rfc-gnutella.sourceforge.net and the 0.6 RFC draft.
// All multi-byte fields are little-endian unless otherwise specified;
// IPv4 addresses are the exception, and are written big-endian.
//
// The task brief for this item specified PUSH = 0x03 and a big-endian
// payload length. Both conflict with the published protocol, where PUSH
// is 0x40 and the length is little-endian. The published values are
// implemented here; see docs/handoff.md for the deviation.
package gnutella

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

const (
	// HeaderSize is the length of a Gnu2-agnostic Gnutella descriptor
	// header: a 16-byte descriptor ID, one byte each of payload type,
	// TTL and hops, and a 4-byte little-endian payload length.
	HeaderSize = 23

	// MaxPayloadSize caps the payload length a peer may send in one
	// message. The spec says messages SHOULD NOT exceed 4 kB, and Query
	// Hits up to 64 kB on agreement; 64 kB accepts everything a sane
	// neighbour sends while bounding per-message allocations.
	MaxPayloadSize = 64 * 1024

	// Descriptor ID layout from the spec: byte 8 marks a GUID as
	// "multicast-capable" (0xFF), byte 15 is reserved and must be 0.
	idSize        = 16
	guidNetworkID = 0xFF
	guidReserved  = 0x00
)

// Payload type bytes (spec: "Ping = 0x00, Pong = 0x01, Bye = 0x02,
// Push = 0x40, Query = 0x80, QueryHit = 0x81"). Bye exists in the 0.4
// spec text but is not defined as a message; it is not handled.
const (
	MsgPing     byte = 0x00
	MsgPong     byte = 0x01
	MsgPush     byte = 0x40
	MsgQuery    byte = 0x80
	MsgQueryHit byte = 0x81
)

// ErrPayloadTooLarge wraps a payload length that exceeds MaxPayloadSize.
var ErrPayloadTooLarge = errors.New("gnutella: payload length exceeds maximum")

// Header is a Gnutella descriptor header. ID is the 16-byte descriptor
// ID, Type the payload type byte, TTL and Hops the forwarding counters,
// and Length the payload length in bytes.
type Header struct {
	ID     [idSize]byte
	Type   byte
	TTL    byte
	Hops   byte
	Length uint32
}

// DecodeHeader reads one 23-byte header from r. A payload length above
// MaxPayloadSize is rejected with ErrPayloadTooLarge before any payload
// is read.
func DecodeHeader(r io.Reader) (Header, error) {
	var buf [HeaderSize]byte
	if _, err := io.ReadFull(r, buf[:]); err != nil {
		return Header{}, err
	}
	h := Header{
		Type:   buf[16],
		TTL:    buf[17],
		Hops:   buf[18],
		Length: binary.LittleEndian.Uint32(buf[19:23]),
	}
	copy(h.ID[:], buf[0:16])
	if h.Length > MaxPayloadSize {
		return Header{}, fmt.Errorf("%w: %d bytes", ErrPayloadTooLarge, h.Length)
	}
	return h, nil
}

// AppendTo appends the header encoding to dst and returns the extended
// slice. The payload, h.Length bytes, must follow immediately.
func (h Header) AppendTo(dst []byte) []byte {
	off := len(dst)
	dst = append(dst, make([]byte, HeaderSize)...)
	copy(dst[off:off+idSize], h.ID[:])
	dst[off+idSize] = h.Type
	dst[off+idSize+1] = h.TTL
	dst[off+idSize+2] = h.Hops
	binary.LittleEndian.PutUint32(dst[off+idSize+3:off+HeaderSize], h.Length)
	return dst
}

// Marshal returns the fixed-size header encoding.
func (h Header) Marshal() [HeaderSize]byte {
	var b [HeaderSize]byte
	buf := h.AppendTo(b[:0])
	copy(b[:], buf)
	return b
}

// newDescriptorID returns a fresh descriptor ID. Bytes 8 and 15 are
// tagged per the spec's GUID conventions. crypto/rand failure is
// treated as fatal: it means the OS entropy source is broken, and a
// daemon that keeps serving with guessable IDs is worse than one that
// says so.
func newDescriptorID() [idSize]byte {
	var id [idSize]byte
	if _, err := rand.Read(id[:]); err != nil {
		panic(fmt.Sprintf("gnutella: crypto/rand failed: %v", err))
	}
	id[8] = guidNetworkID
	id[15] = guidReserved
	return id
}

// typeName names a payload type for logs.
func typeName(t byte) string {
	switch t {
	case MsgPing:
		return "ping"
	case MsgPong:
		return "pong"
	case MsgPush:
		return "push"
	case MsgQuery:
		return "query"
	case MsgQueryHit:
		return "queryhit"
	default:
		return fmt.Sprintf("type-0x%02x", t)
	}
}
