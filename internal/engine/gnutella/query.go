// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
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
// NUL-terminated name.
type QueryHit struct {
	HitCount uint8
	Port     uint16 // little-endian
	IP       [4]byte
	Speed    uint32 // little-endian
	Hits     []FileHit
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
	qh.Hits = hits
	return qh, nil
}