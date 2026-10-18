// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

const (
	queryHeaderMin = 2 // minimum speed (2 bytes LE)
)

// Query represents a Gnutella QUERY message (0x80).
// Payload: 2-byte minimum speed (LE), NUL-terminated search criteria.
type Query struct {
	MinSpeed uint16 // minimum download speed in KB/s, little-endian
	Search   string // search criteria, NUL-terminated in wire
}

// QueryHit represents a Gnutella QUERYHIT message (0x81).
// Payload: 1-byte hit count, 2-byte port (LE), 4-byte IPv4 (BE),
// 4-byte speed (LE), then per hit: 4-byte file index, 4-byte size,
// NUL-terminated name; after the result set, an NUL-terminated
// extensions block and the trailing 16-byte servent identifier
// (spec rfc-0_6-draft §2.2.6).
type QueryHit struct {
	HitCount uint8
	Port     uint16 // little-endian
	IP       [4]byte
	Speed    uint32 // little-endian
	Hits     []FileHit

	// ClientID is the trailing servent identifier (last 16 bytes of the
	// payload): the value a PUSH must target to reach the servent that
	// sent this hit (§2.2.8). It is zero when the payload ended before
	// one, which older or minimal encoders may produce.
	ClientID [idSize]byte

	// Via names the connection this hit arrived on. It is not wire data
	// and is never encoded or decoded: the receiving peer stamps it so a
	// caller can send a PUSH back down the path the hit came from, which
	// is what makes the request routable without new machinery. It is
	// nil for hits built locally (e.g. our own QUERYHIT replies).
	Via net.Addr
}

// FileHit is a single result in a QUERYHIT.
type FileHit struct {
	FileIndex uint32 // little-endian
	FileSize  uint32 // little-endian
	FileName  string // NUL-terminated in wire
}

// ErrQueryHitBadFormat is returned when QUERYHIT is malformed.
var ErrQueryHitBadFormat = errors.New("gnutella: malformed queryhit")

// ErrQueryBadFormat is returned when QUERY is malformed.
var ErrQueryBadFormat = errors.New("gnutella: malformed query")

// EncodeQuery encodes a Query to its wire representation.
func EncodeQuery(q Query) []byte {
	// search must be NUL-terminated on wire
	s := q.Search
	if s == "" || s[len(s)-1] != '\x00' {
		s = s + "\x00"
	}
	out := make([]byte, 2+len(s))
	binary.LittleEndian.PutUint16(out[0:2], q.MinSpeed)
	copy(out[2:], []byte(s))
	return out
}

// DecodeQuery decodes a Query from payload.
func DecodeQuery(payload []byte) (Query, error) {
	if len(payload) < queryHeaderMin {
		return Query{}, fmt.Errorf("%w: payload too short", ErrQueryBadFormat)
	}
	q := Query{
		MinSpeed: binary.LittleEndian.Uint16(payload[0:2]),
	}
	// search criteria is NUL-terminated
	searchBytes := payload[2:]
	if len(searchBytes) == 0 {
		return Query{}, fmt.Errorf("%w: missing search criteria", ErrQueryBadFormat)
	}
	// find NUL terminator
	idx := bytes.IndexByte(searchBytes, 0x00)
	if idx < 0 {
		return Query{}, fmt.Errorf("%w: missing NUL terminator", ErrQueryBadFormat)
	}
	q.Search = string(searchBytes[:idx]) // exclude NUL
	return q, nil
}

// EncodeQueryHit encodes a QueryHit to its wire representation.
func EncodeQueryHit(qh QueryHit) []byte {
	if qh.HitCount != uint8(len(qh.Hits)) {
		qh.HitCount = uint8(len(qh.Hits))
	}
	// minimum size: 1+2+4+4 + (per hit: 4+4 + NUL)
	out := make([]byte, 11)
	out[0] = qh.HitCount
	binary.LittleEndian.PutUint16(out[1:3], qh.Port)
	copy(out[3:7], qh.IP[:])
	binary.LittleEndian.PutUint32(out[7:11], qh.Speed)
	for _, hit := range qh.Hits {
		// append file index (4 LE), file size (4 LE), name + NUL
		name := hit.FileName
		if name == "" || name[len(name)-1] != '\x00' {
			name = name + "\x00"
		}
		hdr := make([]byte, 8+len(name))
		binary.LittleEndian.PutUint32(hdr[0:4], hit.FileIndex)
		binary.LittleEndian.PutUint32(hdr[4:8], hit.FileSize)
		copy(hdr[8:], []byte(name))
		out = append(out, hdr...)
	}
	if qh.ClientID != ([idSize]byte{}) {
		// The extensions block after the result set is NUL-terminated
		// even when empty, so a hit with no extensions carries a double
		// NUL (the last name's terminator plus the block's own), and the
		// servent identifier is the 16 bytes after it (§2.2.6). A hit
		// with no servent identifier emits nothing here, which keeps
		// locally built payloads byte-identical to the result set.
		out = append(out, 0x00)
		out = append(out, qh.ClientID[:]...)
	}
	return out
}

// DecodeQueryHit decodes a QueryHit from payload.
func DecodeQueryHit(payload []byte) (QueryHit, error) {
	if len(payload) < 11 {
		return QueryHit{}, fmt.Errorf("%w: payload too short", ErrQueryHitBadFormat)
	}
	qh := QueryHit{
		HitCount: uint8(payload[0]),
		Port:     binary.LittleEndian.Uint16(payload[1:3]),
		Speed:    binary.LittleEndian.Uint32(payload[7:11]),
	}
	copy(qh.IP[:], payload[3:7])
	pos := 11
	hits := make([]FileHit, 0, qh.HitCount)
	if qh.HitCount > 0 && pos >= len(payload) {
		return QueryHit{}, fmt.Errorf("%w: hit 0 header too short", ErrQueryHitBadFormat)
	}
	for i := 0; i < int(qh.HitCount); i++ {
		if pos+8 > len(payload) {
			return QueryHit{}, fmt.Errorf("%w: hit %d header too short", ErrQueryHitBadFormat, i)
		}
		hit := FileHit{
			FileIndex: binary.LittleEndian.Uint32(payload[pos : pos+4]),
			FileSize:  binary.LittleEndian.Uint32(payload[pos+4 : pos+8]),
		}
		pos += 8
		nameBytes := payload[pos:]
		nulIdx := bytes.IndexByte(nameBytes, 0x00)
		if nulIdx < 0 {
			return QueryHit{}, fmt.Errorf("%w: hit %d missing NUL", ErrQueryHitBadFormat, i)
		}
		hit.FileName = string(nameBytes[:nulIdx])
		pos += nulIdx + 1
		hits = append(hits, hit)
		if pos > len(payload) {
			break
		}
	}
	// The servent identifier is the last 16 bytes of the payload
	// (§2.2.6), whatever extensions or private data sit between the
	// result set and it (neither of which this decoder parses). It is
	// only taken when at least 16 bytes remain past the result set: a
	// payload that ends with the result set (an older or minimal
	// encoder) simply has none, and the last hit's name bytes are not
	// an identifier.
	if len(payload)-pos >= idSize {
		copy(qh.ClientID[:], payload[len(payload)-idSize:])
	}
	qh.Hits = hits
	return qh, nil
}
