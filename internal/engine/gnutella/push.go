// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Gnutella 1 push: the PUSH request (message type 0x40) and the GIV
// upload handshake line it provokes.
//
// Push is the only way to fetch from a servent that cannot accept
// inbound connections: a firewalled source. Its direction is the
// opposite of a plain download and is the single easiest thing to get
// backwards, so it is spelled out here.
//
//  1. A downloader A wants a file that source B holds. A sends a PUSH
//     message addressed to B's servent GUID. The payload names the
//     file's index in B's catalogue and, crucially, A's own address and
//     port, which is where B must dial back.
//  2. B, the firewalled source, receives the PUSH and dials A at that
//     address. That single outbound connection is what the firewall
//     permits.
//  3. On connect B sends "GIV <index>:<B's guid>/" and then serves the
//     file. B is the uploader and the index is B's, so GIV is an offer
//     ("give"), not a request.
//  4. A accepts the connection as the download side, matches the GIV's
//     GUID and index to the transfer it was waiting for, and issues the
//     GET on that same socket.
//
// This file implements the two wire encodings (steps 1 and 3). It does
// not implement the dial-back listener or the upload server they imply;
// see docs/handoff.md for what that slice still needs and why it is
// larger than a codec.
//
// The semantics follow Shareaza's Gnutella 1 implementation, read as a
// reference: CG1Packet::OnPush (the payload layout and the "act only if
// the target GUID is mine" rule), CNetwork::SendPush (how the requester
// builds it), and CHandshake::OnConnected / OnAcceptGive (the GIV line,
// both directions). Multi-byte fields are little-endian, the IPv4
// address excepted, matching the rest of the package.

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

const (
	// pushPayloadSize is the fixed PUSH payload: a 16-byte servent GUID,
	// a 4-byte file index, a 4-byte IPv4 address, and a 2-byte port.
	// Servents may append a GGEP block; only the fixed part is decoded
	// here, and trailing bytes are ignored, as Shareaza's length check
	// (`m_nLength < 26`) allows.
	pushPayloadSize = idSize + 4 + 4 + 2

	// givGUIDHex is the number of hex characters a GIV carries per
	// servent GUID (16 bytes).
	givGUIDHex = idSize * 2
)

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// ErrGIVBadFormat is returned when a GIV line is malformed.
var ErrGIVBadFormat = errors.New("gnutella: malformed GIV")

// Push is the payload of a Gnutella 1 PUSH message (type 0x40).
//
// Target is the servent GUID the push is addressed to: the firewalled
// source B that must dial back. A receiver acts on the push only when
// Target is its own GUID, so an unrelated push is not a callback
// request to anyone else on the path. IP and Port are the requester's
// callback address, i.e. where B connects.
type Push struct {
	Target    [idSize]byte
	FileIndex uint32
	IP        [4]byte
	Port      uint16
}

// EncodePush encodes a Push to its fixed 26-byte wire payload. Target
// and IP are copied in byte order; FileIndex and Port are little-endian.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:idSize], p.Target[:])
	binary.LittleEndian.PutUint32(out[idSize:idSize+4], p.FileIndex)
	copy(out[idSize+4:idSize+8], p.IP[:])
	binary.LittleEndian.PutUint16(out[idSize+8:pushPayloadSize], p.Port)
	return out
}

// DecodePush decodes a PUSH payload. A payload shorter than the fixed
// 26 bytes is rejected; trailing bytes (a GGEP block) are ignored.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: %d bytes, need at least %d",
			ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	var p Push
	copy(p.Target[:], payload[0:idSize])
	p.FileIndex = binary.LittleEndian.Uint32(payload[idSize : idSize+4])
	copy(p.IP[:], payload[idSize+4:idSize+8])
	p.Port = binary.LittleEndian.Uint16(payload[idSize+8 : pushPayloadSize])
	return p, nil
}

// Valid reports whether a push names a callback a servent can actually
// dial: a non-zero port and a non-zero address. Shareaza drops a
// zero-port push outright. Whether an address is reachable (not
// firewalled or in a reserved range) is the caller's policy, not the
// codec's, so it is deliberately not checked here.
func (p Push) Valid() bool {
	return p.Port != 0 && p.IP != [4]byte{}
}

// GIV is the upload handshake line a firewalled source sends on the
// connection a PUSH made it open: "GIV <index>:<guid>/", optionally
// followed by the file name, as in "GIV 124:<guid>/my%20song.mp3".
//
// The GUID is the sender's (the uploader's) servent GUID and the index
// is its catalogue index; the downloader matches both to the transfer
// it was waiting for. The slash and name are optional on the wire
// (Shareaza tolerates a missing slash), and Name is carried verbatim,
// not URL-decoded: servents conventionally percent-encode it, but that
// is the caller's decision and keeping the bytes intact makes the codec
// lossless.
type GIV struct {
	FileIndex uint32
	GUID      [idSize]byte
	Name      string
}

// EncodeGIV encodes a GIV line, including the trailing blank line. The
// index is decimal and the GUID is 32 uppercase hex characters, matching
// Shareaza's "GIV %u:%.2X.../\n\n" format.
func EncodeGIV(g GIV) []byte {
	var b bytes.Buffer
	fmt.Fprintf(&b, "GIV %d:%X/", g.FileIndex, g.GUID[:])
	b.WriteString(g.Name)
	b.WriteString("\n\n")
	return b.Bytes()
}

// DecodeGIV decodes a GIV line. It accepts a line with or without its
// trailing CR/LF. A missing "GIV " prefix, a missing index/guid colon, a
// non-numeric index, or a GUID that is not exactly 32 hex characters is
// an error (Shareaza refuses these with "GNUTELLA/0.6 503 Bad push").
func DecodeGIV(line []byte) (GIV, error) {
	rest, ok := strings.CutPrefix(strings.TrimRight(string(line), "\r\n"), "GIV ")
	if !ok {
		return GIV{}, fmt.Errorf("%w: missing \"GIV \" prefix", ErrGIVBadFormat)
	}
	var g GIV
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		g.Name = rest[i+1:]
		rest = rest[:i]
	}
	idx, hexID, ok := strings.Cut(rest, ":")
	if !ok {
		return GIV{}, fmt.Errorf("%w: missing index separator", ErrGIVBadFormat)
	}
	n, err := strconv.ParseUint(idx, 10, 32)
	if err != nil {
		return GIV{}, fmt.Errorf("%w: bad file index %q", ErrGIVBadFormat, idx)
	}
	g.FileIndex = uint32(n)
	if len(hexID) != givGUIDHex {
		return GIV{}, fmt.Errorf("%w: guid is %d hex characters, want %d",
			ErrGIVBadFormat, len(hexID), givGUIDHex)
	}
	raw, err := hex.DecodeString(hexID)
	if err != nil {
		return GIV{}, fmt.Errorf("%w: bad guid %q", ErrGIVBadFormat, hexID)
	}
	copy(g.GUID[:], raw)
	return g, nil
}
