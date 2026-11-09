// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds the server login, ID-change and server-list codecs used
// when talking to an eDonkey server. It does not perform any networking.
package ed2k

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Server-side opcodes. Values follow Shareaza's EDPacket.h.
const (
	OP_LOGINREQUEST  byte = 0x01 // ED2K_C2S_LOGINREQUEST
	OP_GETSERVERLIST byte = 0x14 // ED2K_C2S_GETSERVERLIST
	OP_IDCHANGE      byte = 0x40 // ED2K_S2C_IDCHANGE
	OP_SERVERLIST    byte = 0x32 // ED2K_S2C_SERVERLIST
)

// CamelCase aliases for the opcodes.
const (
	OpLoginRequest  = OP_LOGINREQUEST
	OpGetServerList = OP_GETSERVERLIST
	OpIDChange      = OP_IDCHANGE
	OpServerList    = OP_SERVERLIST
)

// Sentinel errors.
var (
	ErrLoginRequest = errors.New("ed2k: malformed login request")
	ErrIDChange     = errors.New("ed2k: malformed id change")
	ErrServerList   = errors.New("ed2k: malformed server list")
	ErrServerEntry  = errors.New("ed2k: malformed server entry")
)

// LoginRequest is the payload of OP_LOGINREQUEST:
// <hash 16><id 4><port 2><tag count 1><tag set>.
type LoginRequest struct {
	Hash [16]byte

	ClientID uint32
	ID       uint32

	Port uint16

	Tags    []Tag
	TagList []Tag
	TagSet  []Tag
}

func (l LoginRequest) clientID() uint32 {
	if l.ClientID != 0 {
		return l.ClientID
	}
	return l.ID
}

func (l LoginRequest) tags() []Tag {
	if l.Tags != nil {
		return l.Tags
	}
	if l.TagList != nil {
		return l.TagList
	}
	return l.TagSet
}

// Marshal encodes a LoginRequest payload.
func (l LoginRequest) Marshal() []byte {
	id := l.clientID()
	tags := l.tags()
	out := make([]byte, 16+4+2+1)
	copy(out[0:16], l.Hash[:])
	binary.LittleEndian.PutUint32(out[16:20], id)
	binary.LittleEndian.PutUint16(out[20:22], l.Port)
	out[22] = byte(len(tags))
	for _, t := range tags {
		out = append(out, t.Marshal()...)
	}
	return out
}

// Encode is an alias.
func (l LoginRequest) Encode() []byte { return l.Marshal() }

// Bytes is an alias.
func (l LoginRequest) Bytes() []byte { return l.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (l LoginRequest) MarshalBinary() ([]byte, error) { return l.Marshal(), nil }

// DecodeLoginRequest parses a LoginRequest payload.
func DecodeLoginRequest(b []byte) (LoginRequest, error) {
	if len(b) < 16+4+2+1 {
		return LoginRequest{}, fmt.Errorf("%w: %w", ErrLoginRequest, ErrFrameTruncated)
	}
	var l LoginRequest
	copy(l.Hash[:], b[0:16])
	off := 16
	l.ClientID = binary.LittleEndian.Uint32(b[off : off+4])
	l.ID = l.ClientID
	off += 4
	l.Port = binary.LittleEndian.Uint16(b[off : off+2])
	off += 2
	tc := int(b[off])
	off++
	tags := make([]Tag, 0, tc)
	for i := 0; i < tc; i++ {
		tag, consumed, err := DecodeTag(b[off:])
		if err != nil {
			return LoginRequest{}, fmt.Errorf("%w: %w", ErrLoginRequest, err)
		}
		tags = append(tags, tag)
		off += consumed
	}
	if off != len(b) {
		if off > len(b) {
			return LoginRequest{}, fmt.Errorf("%w: %w", ErrLoginRequest, ErrFrameTruncated)
		}
		return LoginRequest{}, fmt.Errorf("%w: %w", ErrLoginRequest, ErrFrameTrailing)
	}
	l.Tags = tags
	l.TagList = cloneTags(tags)
	l.TagSet = cloneTags(tags)
	return l, nil
}

// ParseLoginRequest is an alias.
func ParseLoginRequest(b []byte) (LoginRequest, error) { return DecodeLoginRequest(b) }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (l *LoginRequest) Unmarshal(b []byte) error {
	g, err := DecodeLoginRequest(b)
	if err != nil {
		return err
	}
	*l = g
	return nil
}

// Decode is a method form.
func (l *LoginRequest) Decode(b []byte) error { return l.Unmarshal(b) }

// --- IDChange (OP_IDCHANGE) ---

// IDChange is the payload of OP_IDCHANGE:
// <new id 4><server flags 4><tcp flags / primary port 4><client ip 4>.
type IDChange struct {
	NewID uint32

	ServerFlags uint32

	TCPFlags uint32
	Port     uint32

	ClientIP [4]byte
}

func (ic IDChange) tcpFlags() uint32 {
	if ic.TCPFlags != 0 {
		return ic.TCPFlags
	}
	return ic.Port
}

// Marshal encodes an IDChange payload.
func (ic IDChange) Marshal() []byte {
	out := make([]byte, 16)
	binary.LittleEndian.PutUint32(out[0:4], ic.NewID)
	binary.LittleEndian.PutUint32(out[4:8], ic.ServerFlags)
	binary.LittleEndian.PutUint32(out[8:12], ic.tcpFlags())
	copy(out[12:16], ic.ClientIP[:])
	return out
}

// Encode is an alias.
func (ic IDChange) Encode() []byte { return ic.Marshal() }

// Bytes is an alias.
func (ic IDChange) Bytes() []byte { return ic.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (ic IDChange) MarshalBinary() ([]byte, error) { return ic.Marshal(), nil }

// DecodeIDChange parses an IDChange payload.
func DecodeIDChange(b []byte) (IDChange, error) {
	if len(b) != 16 {
		if len(b) < 16 {
			return IDChange{}, fmt.Errorf("%w: %w", ErrIDChange, ErrFrameTruncated)
		}
		return IDChange{}, fmt.Errorf("%w: %w", ErrIDChange, ErrFrameTrailing)
	}
	var ic IDChange
	ic.NewID = binary.LittleEndian.Uint32(b[0:4])
	ic.ServerFlags = binary.LittleEndian.Uint32(b[4:8])
	ic.TCPFlags = binary.LittleEndian.Uint32(b[8:12])
	ic.Port = ic.TCPFlags
	copy(ic.ClientIP[:], b[12:16])
	return ic, nil
}

// ParseIDChange is an alias.
func ParseIDChange(b []byte) (IDChange, error) { return DecodeIDChange(b) }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (ic *IDChange) Unmarshal(b []byte) error {
	g, err := DecodeIDChange(b)
	if err != nil {
		return err
	}
	*ic = g
	return nil
}

// Decode is a method form.
func (ic *IDChange) Decode(b []byte) error { return ic.Unmarshal(b) }

// --- ServerEntry / ServerList (OP_SERVERLIST) ---

// ServerEntry is one entry in an OP_SERVERLIST payload.
type ServerEntry struct {
	IP   [4]byte
	Port uint16

	IPUint32 uint32
}

func (se ServerEntry) ipBytes() [4]byte {
	if se.IP != [4]byte{} {
		return se.IP
	}
	var out [4]byte
	binary.LittleEndian.PutUint32(out[:], se.IPUint32)
	return out
}

// Marshal encodes a ServerEntry.
func (se ServerEntry) Marshal() []byte {
	out := make([]byte, 6)
	ip := se.ipBytes()
	copy(out[0:4], ip[:])
	binary.LittleEndian.PutUint16(out[4:6], se.Port)
	return out
}

// Encode is an alias.
func (se ServerEntry) Encode() []byte { return se.Marshal() }

// Bytes is an alias.
func (se ServerEntry) Bytes() []byte { return se.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (se ServerEntry) MarshalBinary() ([]byte, error) { return se.Marshal(), nil }

// DecodeServerEntry parses one ServerEntry from b, returning entry and bytes consumed.
func DecodeServerEntry(b []byte) (ServerEntry, int, error) {
	if len(b) < 6 {
		return ServerEntry{}, 0, fmt.Errorf("%w: %w", ErrServerEntry, ErrFrameTruncated)
	}
	var se ServerEntry
	copy(se.IP[:], b[0:4])
	se.IPUint32 = binary.LittleEndian.Uint32(b[0:4])
	se.Port = binary.LittleEndian.Uint16(b[4:6])
	return se, 6, nil
}

// ParseServerEntry is an alias.
func ParseServerEntry(b []byte) (ServerEntry, int, error) { return DecodeServerEntry(b) }

// --- ServerList ---

// ServerList is the payload of OP_SERVERLIST:
// <count 1>(<ip 4><port 2>)[count].
type ServerList struct {
	Count   uint8
	Servers []ServerEntry
}

func (sl ServerList) count() int {
	if sl.Servers != nil {
		return len(sl.Servers)
	}
	return int(sl.Count)
}

// Marshal encodes a ServerList payload.
func (sl ServerList) Marshal() []byte {
	n := sl.count()
	out := make([]byte, 1)
	out[0] = byte(n)
	for i := 0; i < n; i++ {
		var se ServerEntry
		if sl.Servers != nil && i < len(sl.Servers) {
			se = sl.Servers[i]
		}
		out = append(out, se.Marshal()...)
	}
	return out
}

// Encode is an alias.
func (sl ServerList) Encode() []byte { return sl.Marshal() }

// Bytes is an alias.
func (sl ServerList) Bytes() []byte { return sl.Marshal() }

// MarshalBinary implements encoding.BinaryMarshaler.
func (sl ServerList) MarshalBinary() ([]byte, error) { return sl.Marshal(), nil }

// DecodeServerList parses a ServerList payload.
func DecodeServerList(b []byte) (ServerList, error) {
	if len(b) < 1 {
		return ServerList{}, fmt.Errorf("%w: %w", ErrServerList, ErrFrameTruncated)
	}
	n := int(b[0])
	if len(b) < 1+n*6 {
		return ServerList{}, fmt.Errorf("%w: %w", ErrServerList, ErrFrameTruncated)
	}
	if len(b) != 1+n*6 {
		return ServerList{}, fmt.Errorf("%w: %w", ErrServerList, ErrFrameTrailing)
	}
	servers := make([]ServerEntry, 0, n)
	off := 1
	for i := 0; i < n; i++ {
		se, consumed, err := DecodeServerEntry(b[off:])
		if err != nil {
			return ServerList{}, fmt.Errorf("%w: %w", ErrServerList, err)
		}
		servers = append(servers, se)
		off += consumed
	}
	sl := ServerList{Count: uint8(n), Servers: servers}
	return sl, nil
}

// ParseServerList is an alias.
func ParseServerList(b []byte) (ServerList, error) { return DecodeServerList(b) }

// Unmarshal implements encoding.BinaryUnmarshaler.
func (sl *ServerList) Unmarshal(b []byte) error {
	g, err := DecodeServerList(b)
	if err != nil {
		return err
	}
	*sl = g
	return nil
}

// Decode is a method form.
func (sl *ServerList) Decode(b []byte) error { return sl.Unmarshal(b) }

// --- IsLowID ---

// IsLowID reports whether id is a low id, matching Shareaza's
// IsLowID (nID > 0 && nID < 16777216).
func IsLowID(id uint32) bool {
	return id > 0 && id < 16777216
}

// Unmarshal implements encoding.BinaryUnmarshaler for ServerEntry.
func (se *ServerEntry) Unmarshal(b []byte) error {
	g, _, err := DecodeServerEntry(b)
	if err != nil {
		return err
	}
	*se = g
	return nil
}

// Decode is a method form.
func (se *ServerEntry) Decode(b []byte) error { return se.Unmarshal(b) }
