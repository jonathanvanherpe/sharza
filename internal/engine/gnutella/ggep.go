// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// GGEP ("Generic Gnutella Extension Protocol") block codec.
//
// A GGEP block is a magic byte 0xC3 followed by one or more extensions.
// Each extension is:
//
//	flags byte      bits 0-3: extension ID length (1-15)
//	                bit  4 (0x10): must be zero (GGEP_F_MBZ)
//	                bit  5 (0x20): payload is deflated
//	                bit  6 (0x40): payload is COBS-encoded
//	                bit  7 (0x80): last extension in the block
//	ID              exactly ID-length bytes, printable ASCII
//	data length     1-3 bytes, big-endian base-64:
//	                bit  7 (0x80): another length byte follows
//	                bit  6 (0x40): this is the last length byte
//	                bits 0-5:      6-bit value, most significant first
//	data            exactly the decoded length in bytes
//
// The length encoding is *not* little-endian: it is a big-endian sequence
// of 6-bit groups, most significant group first, terminated by a byte with
// 0x40 set. The task brief described a little-endian length, "0x40
// encoding-length and 0x20 data-length" flags and a 0x00 block terminator;
// the published format (gtk-gnutella ggep.h and Shareaza GGEP.cpp agree on
// every field, and the annotated Gnutella spec says the extension block
// "SHOULD NOT be followed by a null byte") is what is implemented here. See
// docs/handoff.md for the deviation.
//
// Only the subset the browse-host "BH" extension needs is implemented: plain
// (non-COBS, non-deflated) payloads. An extension that declares COBS or
// deflate is rejected rather than silently returned still encoded, because a
// caller that could not decode it would otherwise read compressed bytes as
// data.

import (
	"errors"
	"fmt"
)

const (
	ggepMagic byte = 0xC3 // block prefix

	ggepFlagLast    byte = 0x80 // last extension in the block
	ggepFlagCOBS    byte = 0x40 // payload is COBS-encoded
	ggepFlagDeflate byte = 0x20 // payload is deflated
	ggepFlagMBZ     byte = 0x10 // must be zero
	ggepIDLenMask   byte = 0x0F // where the ID length is stored

	ggepLenCont  byte = 0x80 // another length byte follows
	ggepLenLast  byte = 0x40 // this is the last length byte
	ggepLenValue byte = 0x3F // 6-bit length value

	ggepMaxIDLen   = 15            // ID length is a 4-bit field
	ggepMaxLenByte = 3             // length is at most 3 bytes
	ggepMaxDataLen = (1 << 18) - 1 // 3 six-bit groups = 262143 bytes
)

// ErrGGEPBadFormat is returned when a GGEP block is malformed.
var ErrGGEPBadFormat = errors.New("gnutella: malformed ggep block")

// GGEPExtension is one decoded GGEP extension: its ASCII ID and its raw,
// fully decoded payload. A zero-length Data is legal and is how marker
// extensions such as "BH" are carried.
type GGEPExtension struct {
	ID   string
	Data []byte
}

// EncodeGGEP encodes extensions into a GGEP block. An extension is written
// only when its ID is 1..15 printable ASCII bytes and its data fits the
// 18-bit length field; anything else is skipped (writing an ID length of 0
// or above 15 would be unparseable). The block always sets the
// last-extension flag on its final extension, and an empty result is
// returned when no extension is valid. A lone "BH" marker therefore encodes
// exactly as C3 82 42 48 40.
func EncodeGGEP(exts []GGEPExtension) []byte {
	valid := make([]GGEPExtension, 0, len(exts))
	for _, e := range exts {
		if !validGGEPID(e.ID) || len(e.Data) > ggepMaxDataLen {
			continue
		}
		valid = append(valid, e)
	}
	if len(valid) == 0 {
		return nil
	}

	out := make([]byte, 0, 1+len(valid)*(2+ggepMaxLenByte))
	out = append(out, ggepMagic)
	for i, e := range valid {
		flags := byte(len(e.ID)) & ggepIDLenMask
		if i == len(valid)-1 {
			flags |= ggepFlagLast
		}
		out = append(out, flags)
		out = append(out, e.ID...)
		out = appendGGEPLength(out, len(e.Data))
		out = append(out, e.Data...)
	}
	return out
}

// validGGEPID reports whether id is a legal GGEP extension ID: non-empty,
// at most 15 bytes, printable ASCII. The ASCII restriction is not in the
// spec proper but is what gtk-gnutella enforces when parsing, on the
// grounds that a non-ASCII run of bytes may be garbage that merely happened
// to start with the 0xC3 magic.
func validGGEPID(id string) bool {
	if len(id) == 0 || len(id) > ggepMaxIDLen {
		return false
	}
	for i := 0; i < len(id); i++ {
		if id[i] < 0x20 || id[i] > 0x7E {
			return false
		}
	}
	return true
}

// appendGGEPLength appends n as a 1..3 byte big-endian base-64 length. The
// caller guarantees 0 <= n <= ggepMaxDataLen.
func appendGGEPLength(out []byte, n int) []byte {
	if n > 0xFFF { // more than 12 bits: emit the top 6-bit group
		out = append(out, byte((n>>12)&int(ggepLenValue))|ggepLenCont)
	}
	if n > 0x3F { // more than 6 bits: emit the middle group
		out = append(out, byte((n>>6)&int(ggepLenValue))|ggepLenCont)
	}
	return append(out, byte(n&int(ggepLenValue))|ggepLenLast)
}

// DecodeGGEP decodes one complete GGEP block from b. It is strict: the
// magic must be present, every extension must be well-formed, the declared
// data length must fit the remaining bytes, and nothing may follow the
// last-extension marker. A truncated block, an over-long data length, a
// reserved bit, a bad ID or an unsupported (COBS/deflate) payload is
// rejected with ErrGGEPBadFormat.
func DecodeGGEP(b []byte) ([]GGEPExtension, error) {
	if len(b) == 0 {
		return nil, fmt.Errorf("%w: empty block", ErrGGEPBadFormat)
	}
	if b[0] != ggepMagic {
		return nil, fmt.Errorf("%w: bad magic 0x%02x", ErrGGEPBadFormat, b[0])
	}

	pos := 1
	var exts []GGEPExtension
	for {
		if pos >= len(b) {
			return nil, fmt.Errorf("%w: missing extension header", ErrGGEPBadFormat)
		}
		flags := b[pos]
		pos++

		if flags&ggepFlagMBZ != 0 {
			return nil, fmt.Errorf("%w: reserved flag set", ErrGGEPBadFormat)
		}
		if flags&(ggepFlagCOBS|ggepFlagDeflate) != 0 {
			return nil, fmt.Errorf("%w: COBS/deflate payload not supported", ErrGGEPBadFormat)
		}

		idLen := int(flags & ggepIDLenMask)
		if idLen == 0 {
			return nil, fmt.Errorf("%w: zero-length extension ID", ErrGGEPBadFormat)
		}
		if pos+idLen > len(b) {
			return nil, fmt.Errorf("%w: truncated extension ID", ErrGGEPBadFormat)
		}
		id := string(b[pos : pos+idLen])
		pos += idLen
		if !validGGEPID(id) {
			return nil, fmt.Errorf("%w: invalid extension ID", ErrGGEPBadFormat)
		}

		// Data length: 1-3 bytes, most significant group first.
		n := 0
		ended := false
		for i := 0; i < ggepMaxLenByte; i++ {
			if pos >= len(b) {
				return nil, fmt.Errorf("%w: truncated data length", ErrGGEPBadFormat)
			}
			c := b[pos]
			pos++
			// Exactly one of the continuation and last bits must be set.
			if c&ggepLenCont != 0 && c&ggepLenLast != 0 {
				return nil, fmt.Errorf("%w: data length byte sets both continuation and last", ErrGGEPBadFormat)
			}
			if c&ggepLenCont == 0 && c&ggepLenLast == 0 {
				return nil, fmt.Errorf("%w: data length byte sets neither continuation nor last", ErrGGEPBadFormat)
			}
			n = (n << 6) | int(c&ggepLenValue)
			if c&ggepLenLast != 0 {
				ended = true
				break
			}
		}
		if !ended {
			return nil, fmt.Errorf("%w: data length exceeds %d bytes", ErrGGEPBadFormat, ggepMaxLenByte)
		}
		if n > len(b)-pos {
			return nil, fmt.Errorf("%w: data length %d exceeds %d remaining byte(s)", ErrGGEPBadFormat, n, len(b)-pos)
		}

		data := append([]byte(nil), b[pos:pos+n]...)
		pos += n
		exts = append(exts, GGEPExtension{ID: id, Data: data})

		if flags&ggepFlagLast != 0 {
			break
		}
	}

	if pos != len(b) {
		return nil, fmt.Errorf("%w: %d trailing byte(s)", ErrGGEPBadFormat, len(b)-pos)
	}
	return exts, nil
}
