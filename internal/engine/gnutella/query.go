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

	// queryHitHeaderMin is the fixed QUERYHIT header: 1-byte hit count,
	// 2-byte port (LE), 4-byte IPv4 (BE), 4-byte speed (LE) and the
	// mandatory 16-byte servent ID (GUID). Both the annotated 0.4 spec
	// and the 0.6 RFC place the servent ID between Speed and the hits;
	// a payload shorter than this cannot be a well-formed QUERYHIT.
	queryHitHeaderMin = 27
)

// Query represents a Gnutella QUERY message (0x80).
// Payload: 2-byte minimum speed (LE), NUL-terminated search criteria.
type Query struct {
	MinSpeed uint16 // minimum download speed in KB/s, little-endian
	Search   string // search criteria, NUL-terminated in wire
}

// QueryHit represents a Gnutella QUERYHIT message (0x81).
// Payload: 1-byte hit count, 2-byte port (LE), 4-byte IPv4 (BE),
// 4-byte speed (LE), 16-byte servent ID (GUID), then per hit:
// 4-byte file index, 4-byte size, NUL-terminated name.
type QueryHit struct {
	HitCount uint8
	Port     uint16 // little-endian
	IP       [4]byte
	Speed    uint32 // little-endian
	// ServentID identifies the servent that answered. Both the
	// annotated 0.4 spec and the 0.6 RFC make it mandatory, between
	// Speed and the hit list; peers use it to tell which client
	// produced the hits (and, later, where to send a PUSH for a
	// firewalled source). It is a GUID tagged like a descriptor ID.
	ServentID [idSize]byte
	Hits      []FileHit
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
	// header: hit count (1), port (2 LE), IPv4 (4 BE), speed (4 LE),
	// servent ID (16); then per hit: 4+4 LE + name + NUL.
	out := make([]byte, queryHitHeaderMin)
	out[0] = qh.HitCount
	binary.LittleEndian.PutUint16(out[1:3], qh.Port)
	copy(out[3:7], qh.IP[:])
	binary.LittleEndian.PutUint32(out[7:11], qh.Speed)
	copy(out[11:27], qh.ServentID[:])
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
	if len(payload) < queryHitHeaderMin {
		return QueryHit{}, fmt.Errorf("%w: payload too short", ErrQueryHitBadFormat)
	}
	qh := QueryHit{
		HitCount: uint8(payload[0]),
		Port:     binary.LittleEndian.Uint16(payload[1:3]),
		Speed:    binary.LittleEndian.Uint32(payload[7:11]),
	}
	copy(qh.IP[:], payload[3:7])
	copy(qh.ServentID[:], payload[11:27])
	pos := queryHitHeaderMin
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