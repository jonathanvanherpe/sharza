// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrPushBadFormat is returned when a PUSH payload is shorter than the
// fixed 26 bytes.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// ErrNoPushPath is returned when a PUSH cannot be delivered because no
// live connection matches the address it must go down.
var ErrNoPushPath = errors.New("gnutella: no live connection to deliver push")

// pushPayloadSize is the fixed PUSH payload: 16-byte target servent ID,
// 4-byte file index (LE), 4-byte IPv4 (BE), 2-byte port (LE). Trailing
// GGEP extensions, if any, are ignored on decode.
const pushPayloadSize = 26

// pushTTL is the TTL on a PUSH we originate.
const pushTTL byte = 7

// Push is the decoded PUSH payload (spec 2.2.8).
type Push struct {
	// Target is the servent identifier the PUSH is addressed to. It
	// must equal the trailing 16 bytes of the QUERYHIT whose source
	// could not be dialled.
	Target [idSize]byte

	// ServentID is an alias for Target, kept for compatibility with
	// earlier callers that named the field that way. Encode/Decode keep
	// the two in sync.
	ServentID [idSize]byte

	// FileIndex is the index of the file to push, taken from the
	// QUERYHIT, little-endian on the wire.
	FileIndex uint32

	// IP is the IPv4 address the requester wants the file sent to,
	// big-endian on the wire.
	IP [4]byte

	// Port is the port the requester wants the file sent to,
	// little-endian on the wire.
	Port uint16
}

// EncodePush encodes p to its wire representation.
func EncodePush(p Push) []byte {
	target := p.Target
	if target == ([idSize]byte{}) {
		target = p.ServentID
	}
	out := make([]byte, pushPayloadSize)
	copy(out[0:idSize], target[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a PUSH payload. A payload shorter than the fixed
// fields cannot be decoded at all; anything longer carries an optional
// GGEP block that is skipped.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload %d bytes, want at least %d",
			ErrPushBadFormat, len(payload), pushPayloadSize)
	}
	var p Push
	copy(p.Target[:], payload[0:idSize])
	copy(p.ServentID[:], payload[0:idSize])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushRegistry maps the remote address of each live connection to the
// peer behind it, so a PUSH for a QUERYHIT can be written down the same
// connection the hit arrived on.
type pushRegistry struct {
	mu     sync.Mutex
	conns  map[string]*peer
	byAddr map[string]*peer
}

func newPushRegistry() *pushRegistry {
	m := make(map[string]*peer)
	return &pushRegistry{conns: m, byAddr: m}
}

// peerFromArgs returns the first *peer found in args.
func peerFromArgs(args []interface{}) *peer {
	for _, a := range args {
		if pp, ok := a.(*peer); ok {
			return pp
		}
	}
	return nil
}

// addrFromArgs returns the first net.Addr (or net.Conn, whose remote
// address is used) found in args.
func addrFromArgs(args []interface{}) net.Addr {
	for _, a := range args {
		switch v := a.(type) {
		case net.Addr:
			if v != nil {
				return v
			}
		case net.Conn:
			if v != nil {
				return v.RemoteAddr()
			}
		}
	}
	// Fall back to a peer's connection if present.
	if pp := peerFromArgs(args); pp != nil && pp.conn != nil {
		return pp.conn.RemoteAddr()
	}
	return nil
}

// keyFromArgs derives a registry key from args, preferring an explicit
// address/conn/string over a peer's connection.
func keyFromArgs(args []interface{}, p *peer) string {
	for _, a := range args {
		switch v := a.(type) {
		case net.Addr:
			if v != nil {
				return v.String()
			}
		case net.Conn:
			if v != nil {
				return v.RemoteAddr().String()
			}
		case string:
			return v
		}
	}
	if p != nil && p.conn != nil {
		return p.conn.RemoteAddr().String()
	}
	return ""
}

// add registers p under the derived key.
func (r *pushRegistry) add(args ...interface{}) {
	if r == nil {
		return
	}
	p := peerFromArgs(args)
	if p == nil {
		return
	}
	key := keyFromArgs(args, p)
	if key == "" {
		if p.conn == nil {
			return
		}
		key = p.conn.RemoteAddr().String()
	}
	r.mu.Lock()
	if r.conns == nil {
		m := make(map[string]*peer)
		r.conns = m
		r.byAddr = m
	}
	r.conns[key] = p
	r.byAddr[key] = p
	r.mu.Unlock()
}

// remove unregisters p under the derived key, but only when the
// registered entry is p itself (identity-guarded).
func (r *pushRegistry) remove(args ...interface{}) {
	if r == nil {
		return
	}
	p := peerFromArgs(args)
	key := keyFromArgs(args, p)
	if key == "" && p != nil && p.conn != nil {
		key = p.conn.RemoteAddr().String()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conns == nil {
		return
	}
	if p == nil {
		delete(r.conns, key)
		delete(r.byAddr, key)
		return
	}
	if cur, ok := r.byAddr[key]; ok && cur == p {
		delete(r.byAddr, key)
	}
	if cur, ok := r.conns[key]; ok && cur == p {
		delete(r.conns, key)
	}
}

// send writes a PUSH down the connection at via. It accepts either a
// Push value or a target/fileIndex pair (ndxp4 style).
func (r *pushRegistry) send(args ...interface{}) error {
	if r == nil {
		return ErrNoPushPath
	}
	via := addrFromArgs(args)
	if via == nil {
		return ErrNoPushPath
	}

	// Determine whether a Push or target/fileIndex was supplied.
	var push Push
	foundPush := false
	var target [idSize]byte
	targetFound := false
	var fileIndex uint32
	fileFound := false
	for _, a := range args {
		switch v := a.(type) {
		case Push:
			push = v
			foundPush = true
			if v.Target != ([idSize]byte{}) {
				target = v.Target
				targetFound = true
			} else if v.ServentID != ([idSize]byte{}) {
				target = v.ServentID
				targetFound = true
			}
			fileIndex = v.FileIndex
			fileFound = true
		case [idSize]byte:
			target = v
			targetFound = true
		case uint32:
			if !fileFound {
				fileIndex = v
				fileFound = true
			}
		}
	}

	r.mu.Lock()
	p := r.byAddr[via.String()]
	if p == nil {
		p = r.conns[via.String()]
	}
	r.mu.Unlock()
	if p == nil {
		return ErrNoPushPath
	}

	if foundPush {
		// keep alias fields in sync
		if push.Target == ([idSize]byte{}) {
			push.Target = push.ServentID
		}
		if push.ServentID == ([idSize]byte{}) {
			push.ServentID = push.Target
		}
		return p.sendPush(push)
	}
	if targetFound {
		return p.sendPush(target, fileIndex)
	}
	return ErrNoPushPath
}

// sendPush writes a PUSH message down this peer's connection. It
// accepts either a Push value or a target/fileIndex pair.
func (p *peer) sendPush(args ...interface{}) error {
	if p == nil || p.conn == nil {
		return ErrNoPushPath
	}

	var push Push
	foundPush := false
	var target [idSize]byte
	var fileIndex uint32
	fileFound := false
	for _, a := range args {
		switch v := a.(type) {
		case Push:
			push = v
			foundPush = true
			if v.Target != ([idSize]byte{}) {
				target = v.Target
			} else if v.ServentID != ([idSize]byte{}) {
				target = v.ServentID
			}
			fileIndex = v.FileIndex
			fileFound = true
		case [idSize]byte:
			target = v
		case uint32:
			if !fileFound {
				fileIndex = v
				fileFound = true
			}
		}
	}

	if foundPush {
		if push.Target == ([idSize]byte{}) {
			push.Target = push.ServentID
		}
		if push.ServentID == ([idSize]byte{}) {
			push.ServentID = push.Target
		}
	} else {
		push = Push{Target: target, FileIndex: fileIndex}
		// Fill requester address from this connection, as in ndxp4.
		push.Port = p.listenPort()
		if ta, ok := p.conn.LocalAddr().(*net.TCPAddr); ok {
			if ip4 := ta.IP.To4(); ip4 != nil {
				copy(push.IP[:], ip4)
			}
		}
		push.ServentID = push.Target
	}

	payload := EncodePush(push)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    pushTTL,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	if p.logf != nil {
		p.logf("sending push to %s: target=%x index=%d", p.conn.RemoteAddr(), push.Target, push.FileIndex)
	}
	return p.writeMessage(hdr, payload)
}
