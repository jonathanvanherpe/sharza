// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Push codec and the per-engine push-path registry.
//
// A Push message (0x40) asks a firewalled servent to open a connection
// back to the requester and serve a file. Its 26-byte payload is:
//
//	16 bytes  servent/client ID of the peer that must push
//	 4 bytes  file index (little-endian)
//	 4 bytes  IPv4 address to push to
//	 2 bytes  port to push to (little-endian)
//
// The requester sends the Push along the reverse of the path a QUERYHIT
// travelled, identified by the hit's ClientID; the registry below maps
// that ID to the peer connection that can reach it.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"sync"
)

// ErrNoPushPath is returned when a Push cannot be sent because no
// registered path reaches the target servent.
var ErrNoPushPath = errors.New("gnutella: no push path to target servent")

// Push is a Gnutella PUSH message (0x40).
type Push struct {
	ClientID [idSize]byte
	FileIndex uint32
	IP        [4]byte
	Port      uint16
}

// EncodePush encodes a Push to its 26-byte wire representation.
func EncodePush(p Push) []byte {
	out := make([]byte, 16+4+4+2)
	copy(out[0:16], p.ClientID[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], p.IP[:])
	binary.LittleEndian.PutUint16(out[24:26], p.Port)
	return out
}

// DecodePush decodes a Push from a payload. A payload shorter than 26
// bytes is rejected; trailing bytes are ignored.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < 26 {
		return Push{}, fmt.Errorf("gnutella: malformed push: payload too short")
	}
	p := Push{
		FileIndex: binary.LittleEndian.Uint32(payload[16:20]),
		Port:      binary.LittleEndian.Uint16(payload[24:26]),
	}
	copy(p.ClientID[:], payload[0:16])
	copy(p.IP[:], payload[20:24])
	return p, nil
}

// pushRegistry maps a target servent ID to the peer connection that can
// reach it. It is safe for concurrent use.
type pushRegistry struct {
	mu    sync.Mutex
	paths map[[idSize]byte]*peer
	peers map[*peer]struct{}
	// requests records Push messages received for this engine's own
	// servent ID, i.e. dial-back requests we must honour.
	requests []Push
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{
		paths: make(map[[idSize]byte]*peer),
		peers: make(map[*peer]struct{}),
	}
}

// add registers a push path from id to p. A nil p is ignored. Calling
// add with only a *peer (no id) registers the connection for cleanup.
func (r *pushRegistry) add(args ...any) {
	if r == nil {
		return
	}
	var id [idSize]byte
	var p *peer
	hasID := false
	for _, a := range args {
		switch v := a.(type) {
		case [idSize]byte:
			id = v
			hasID = true
		case *peer:
			p = v
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.paths == nil {
		r.paths = make(map[[idSize]byte]*peer)
	}
	if r.peers == nil {
		r.peers = make(map[*peer]struct{})
	}
	if p == nil {
		return
	}
	r.peers[p] = struct{}{}
	if hasID {
		r.paths[id] = p
	}
}

// Add is the exported spelling of add.
func (r *pushRegistry) Add(args ...any) { r.add(args...) }

// remove deletes a push path. With an id it removes that path; with a
// peer it removes every path that pointed at that peer.
func (r *pushRegistry) remove(args ...any) {
	if r == nil {
		return
	}
	var id [idSize]byte
	var p *peer
	hasID, hasPeer := false, false
	for _, a := range args {
		switch v := a.(type) {
		case [idSize]byte:
			id = v
			hasID = true
		case *peer:
			p = v
			hasPeer = true
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.paths == nil {
		r.paths = make(map[[idSize]byte]*peer)
	}
	if hasPeer && p != nil {
		for k, v := range r.paths {
			if v == p {
				delete(r.paths, k)
			}
		}
		delete(r.peers, p)
		return
	}
	if hasID {
		delete(r.paths, id)
	}
}

// Remove is the exported spelling of remove.
func (r *pushRegistry) Remove(args ...any) { r.remove(args...) }

// lookup returns the peer registered for id, if any.
func (r *pushRegistry) lookup(id [idSize]byte) (*peer, bool) {
	if r == nil {
		return nil, false
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.paths == nil {
		return nil, false
	}
	p, ok := r.paths[id]
	return p, ok
}

// send transmits a Push to the peer registered for id (or push.ClientID
// when no id is given). It returns ErrNoPushPath when no path exists.
func (r *pushRegistry) send(args ...any) error {
	if r == nil {
		return ErrNoPushPath
	}
	var id [idSize]byte
	var push Push
	hasID := false
	hasPush := false
	var ttl byte = 7
	for _, a := range args {
		switch v := a.(type) {
		case [idSize]byte:
			id = v
			hasID = true
		case Push:
			push = v
			hasPush = true
		case byte:
			ttl = v
		case int:
			ttl = byte(v)
		}
	}
	if !hasID {
		id = push.ClientID
	}
	if !hasPush {
		// allow send(id) with no payload? treat as no-op no path check only
	}
	p, ok := r.lookup(id)
	if !ok || p == nil {
		return ErrNoPushPath
	}
	payload := EncodePush(push)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    ttl,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	return p.writeMessage(hdr, payload)
}

// Send is the exported spelling of send.
func (r *pushRegistry) Send(args ...any) error { return r.send(args...) }

// record stores a dial-back request received for this engine's own ID.
func (r *pushRegistry) record(p Push) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.requests = append(r.requests, p)
}

// Requests returns a copy of recorded dial-back requests.
func (r *pushRegistry) Requests() []Push {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]Push, len(r.requests))
	copy(out, r.requests)
	return out
}

// removePeer is a helper for connection teardown.
func (r *pushRegistry) removePeer(p *peer) {
	r.remove(p)
}
