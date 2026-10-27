// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
)

// ErrNoPushPath is returned when a PUSH cannot be routed because no
// connection is registered for the requested path.
var ErrNoPushPath = errors.New("gnutella: no push path")

// ErrPushBadFormat is returned when a PUSH payload is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// pushPayloadSize is the fixed PUSH payload size: 16-byte servent ID,
// 4-byte file index, 4-byte IPv4 address, 2-byte port.
const pushPayloadSize = 26

// Push represents a Gnutella PUSH message (0x40).
type Push struct {
	ServentID [idSize]byte
	FileIndex uint32
	IP        [4]byte
	Port      uint16
}

// EncodePush encodes a Push to its wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, pushPayloadSize)
	copy(out[0:16], p.ServentID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from payload. Payloads of at least
// pushPayloadSize bytes are accepted; trailing bytes (e.g. GGEP) are
// ignored.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload too short", ErrPushBadFormat)
	}
	var p Push
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushRegistry tracks live peer connections that can carry a PUSH back
// along the path a QUERYHIT travelled.
type pushRegistry struct {
	mu    sync.Mutex
	peers map[string]*peer
}

// newPushRegistry creates an empty push registry.
func newPushRegistry() *pushRegistry {
	return &pushRegistry{peers: make(map[string]*peer)}
}

// pushKeyOf derives the registry key for v.
func pushKeyOf(v interface{}) string {
	switch val := v.(type) {
	case nil:
		return ""
	case *peer:
		if val == nil {
			return ""
		}
		if val.conn != nil {
			return val.conn.RemoteAddr().String()
		}
		return fmt.Sprintf("%p", val)
	case net.Conn:
		if val == nil {
			return ""
		}
		return val.RemoteAddr().String()
	case net.Addr:
		if val == nil {
			return ""
		}
		return val.String()
	case string:
		return val
	default:
		return fmt.Sprintf("%v", val)
	}
}

// peerFromArgs returns the first *peer found in args.
func peerFromArgs(args []interface{}) *peer {
	for _, a := range args {
		if pp, ok := a.(*peer); ok {
			return pp
		}
	}
	for i := len(args) - 1; i >= 0; i-- {
		if pp, ok := args[i].(*peer); ok {
			return pp
		}
	}
	return nil
}

// keyFromArgs returns an explicit key if any string/addr/conn arg is
// present, otherwise derives one from the peer.
func keyFromArgs(args []interface{}, p *peer) string {
	for _, a := range args {
		if _, ok := a.(Push); ok {
			continue
		}
		if _, ok := a.(*peer); ok {
			continue
		}
		switch v := a.(type) {
		case net.Conn:
			if v != nil {
				return v.RemoteAddr().String()
			}
		case net.Addr:
			if v != nil {
				return v.String()
			}
		case string:
			return v
		default:
			// Treat any other non-nil value as an explicit key.
			if a != nil {
				return fmt.Sprintf("%v", a)
			}
		}
	}
	if p != nil {
		return pushKeyOf(p)
	}
	return ""
}

// pushKey derives the registry key for v. Available as both a method and
// a package-level helper.
func (r *pushRegistry) pushKey(v interface{}) string {
	return pushKeyOf(v)
}

// pushKey is the package-level helper form.
func pushKey(v interface{}) string {
	return pushKeyOf(v)
}

// add registers p under the derived or supplied key. A nil registry is
// a no-op.
func (r *pushRegistry) add(args ...interface{}) {
	if r == nil {
		return
	}
	p := peerFromArgs(args)
	key := keyFromArgs(args, p)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		r.peers = make(map[string]*peer)
	}
	r.peers[key] = p
}

// remove unregisters p under key, but only when the registered entry is
// the same instance (identity-checked). A nil registry is a no-op.
func (r *pushRegistry) remove(args ...interface{}) {
	if r == nil {
		return
	}
	p := peerFromArgs(args)
	key := keyFromArgs(args, p)

	r.mu.Lock()
	defer r.mu.Unlock()
	if r.peers == nil {
		return
	}
	if p == nil {
		delete(r.peers, key)
		return
	}
	if cur, ok := r.peers[key]; ok && cur == p {
		delete(r.peers, key)
	}
}

// send routes push to the peer registered under the derived or supplied
// key, calling its sendPush. Returns ErrNoPushPath when no path exists.
// A nil registry returns ErrNoPushPath.
func (r *pushRegistry) send(args ...interface{}) error {
	if r == nil {
		return ErrNoPushPath
	}
	var push Push
	pushFound := false
	for _, a := range args {
		if v, ok := a.(Push); ok {
			push = v
			pushFound = true
		}
	}
	if !pushFound {
		return ErrNoPushPath
	}
	p := peerFromArgs(args)
	key := keyFromArgs(args, p)

	// If an explicit peer was given, use it directly.
	if p != nil {
		// But if key lookup has a registered peer, prefer registered?
		// Use explicit peer.
	} else {
		r.mu.Lock()
		if r.peers == nil {
			r.peers = make(map[string]*peer)
		}
		p = r.peers[key]
		r.mu.Unlock()
	}

	if p == nil && key != "" {
		r.mu.Lock()
		if r.peers == nil {
			r.peers = make(map[string]*peer)
		}
		p = r.peers[key]
		r.mu.Unlock()
	}

	if p == nil {
		return ErrNoPushPath
	}
	return p.sendPush(push)
}

// sendPush writes a MsgPush frame at TTL 1.
func (p *peer) sendPush(push Push) error {
	if p == nil || p.conn == nil {
		return ErrNoPushPath
	}
	payload := EncodePush(push)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    1,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	return p.writeMessage(hdr, payload)
}
