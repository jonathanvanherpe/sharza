// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Push message support for Gnutella 0.6: the requester-side leg that
// asks a firewalled source to connect back and serve a file.
//
// Wire format (per the published protocol and Shareaza's G1Packet):
// 16 bytes servent ID (client ID), 4 bytes file index (LE),
// 4 bytes IPv4 address (as-is), 2 bytes port (LE). Total 26 bytes.

import (
	"encoding/binary"
	"errors"
	"net"
	"sync"
)

// ErrNoPushPath is returned by pushRegistry.send when no live connection
// is registered for the requested servent ID.
var ErrNoPushPath = errors.New("gnutella: no push path")

// Push represents a Gnutella PUSH message (0x40).
type Push struct {
	// ClientID is the servent ID of the source that should connect back.
	ClientID [idSize]byte
	// Aliases for ClientID.
	ServentID   [idSize]byte
	ServentGUID [idSize]byte
	GUID        [idSize]byte
	ClientGUID  [idSize]byte

	FileIndex uint32

	// IP is the requester address the source should connect to.
	IP [4]byte
	// Aliases for IP.
	Address [4]byte
	Addr    [4]byte
	Host    [4]byte

	Port uint16
	// Aliases for Port.
	ListenPort uint16
}

// canonicalClientID returns the first non-zero client id among the aliases.
func (p Push) canonicalClientID() [idSize]byte {
	for _, id := range []([idSize]byte){p.ClientID, p.ServentID, p.ServentGUID, p.GUID, p.ClientGUID} {
		if id != [idSize]byte{} {
			return id
		}
	}
	return p.ClientID
}

// canonicalIP returns the first non-zero IP among the aliases.
func (p Push) canonicalIP() [4]byte {
	for _, ip := range []([4]byte){p.IP, p.Address, p.Addr, p.Host} {
		if ip != [4]byte{} {
			return ip
		}
	}
	return p.IP
}

func (p Push) canonicalPort() uint16 {
	if p.Port != 0 {
		return p.Port
	}
	return p.ListenPort
}

// EncodePush encodes a Push to its wire representation.
func EncodePush(p Push) []byte {
	cid := p.canonicalClientID()
	ip := p.canonicalIP()
	out := make([]byte, 26)
	copy(out[0:16], cid[:])
	binary.LittleEndian.PutUint32(out[16:20], p.FileIndex)
	copy(out[20:24], ip[:])
	binary.LittleEndian.PutUint16(out[24:26], p.canonicalPort())
	return out
}

// DecodePush decodes a Push from payload.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) < 26 {
		return Push{}, errors.New("gnutella: malformed push")
	}
	var p Push
	copy(p.ClientID[:], payload[0:16])
	copy(p.ServentID[:], payload[0:16])
	copy(p.ServentGUID[:], payload[0:16])
	copy(p.GUID[:], payload[0:16])
	copy(p.ClientGUID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	copy(p.Address[:], payload[20:24])
	copy(p.Addr[:], payload[20:24])
	copy(p.Host[:], payload[20:24])
	port := binary.LittleEndian.Uint16(payload[24:26])
	p.Port = port
	p.ListenPort = port
	return p, nil
}

// pushRegistry tracks live connections and push paths keyed by servent ID.
type pushRegistry struct {
	mu sync.Mutex

	// live peers registered via add(peer).
	peers map[*peer]struct{}

	// path from servent/client ID to the delivering peer.
	paths map[[idSize]byte]*peer

	// reverse index for removal by peer.
	byPeer map[*peer]map[[idSize]byte]struct{}
}

func newPushRegistry() *pushRegistry {
	return &pushRegistry{
		peers:  make(map[*peer]struct{}),
		paths:  make(map[[idSize]byte]*peer),
		byPeer: make(map[*peer]map[[idSize]byte]struct{}),
	}
}

// add registers a connection and/or a push path. Accepted forms:
//   add(peer)
//   add(peer, clientID)
//   add(clientID, peer)
func (r *pushRegistry) add(args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var p *peer
	var cid [idSize]byte
	hasCID := false
	for _, a := range args {
		switch v := a.(type) {
		case *peer:
			p = v
		case [idSize]byte:
			cid = v
			hasCID = true
		case net.Addr:
			// ignore; no peer mapping by addr
		}
	}
	if p != nil {
		if r.peers == nil {
			r.peers = make(map[*peer]struct{})
		}
		r.peers[p] = struct{}{}
		if r.byPeer[p] == nil {
			r.byPeer[p] = make(map[[idSize]byte]struct{})
		}
	}
	if hasCID && p != nil {
		r.paths[cid] = p
		if r.byPeer[p] == nil {
			r.byPeer[p] = make(map[[idSize]byte]struct{})
		}
		r.byPeer[p][cid] = struct{}{}
	}
}

// Add is the exported alias for add.
func (r *pushRegistry) Add(args ...any) { r.add(args...) }

// remove unregisters a connection (and all its paths) or a specific path.
// Accepted forms:
//   remove(peer)
//   remove(clientID)
//   remove(peer, clientID)
//   remove(clientID, peer)
func (r *pushRegistry) remove(args ...any) {
	r.mu.Lock()
	defer r.mu.Unlock()

	var p *peer
	var cid [idSize]byte
	hasCID := false
	hasPeer := false
	for _, a := range args {
		switch v := a.(type) {
		case *peer:
			p = v
			hasPeer = true
		case [idSize]byte:
			cid = v
			hasCID = true
		}
	}
	_ = hasCID
	if hasPeer && p != nil {
		delete(r.peers, p)
		// remove all paths for this peer
		if ids, ok := r.byPeer[p]; ok {
			for id := range ids {
				delete(r.paths, id)
			}
			delete(r.byPeer, p)
		}
	}
	if hasCID && !hasPeer {
		delete(r.paths, cid)
	}
	if hasCID && hasPeer && p != nil {
		delete(r.paths, cid)
		if ids, ok := r.byPeer[p]; ok {
			delete(ids, cid)
		}
	}
}

// Remove is the exported alias for remove.
func (r *pushRegistry) Remove(args ...any) { r.remove(args...) }

// send delivers a Push to the peer registered for the given client ID.
// Accepted forms:
//   send(push)
//   send(clientID, push)
//   send(push, clientID)
//   send(peer, push)
//   send(peer, clientID, push)
func (r *pushRegistry) send(args ...any) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	var p *peer
	var push Push
	hasPush := false
	var cid [idSize]byte
	hasCID := false
	for _, a := range args {
		switch v := a.(type) {
		case *peer:
			p = v
		case Push:
			push = v
			hasPush = true
		case [idSize]byte:
			cid = v
			hasCID = true
		}
	}
	_ = hasCID
	if !hasPush {
		// allow no push? nothing to send
	}
	if cid == [idSize]byte{} && hasPush {
		cid = push.canonicalClientID()
	}
	if p == nil && cid != [idSize]byte{} {
		p = r.paths[cid]
	}
	if p == nil {
		return ErrNoPushPath
	}
	if !hasPush {
		return ErrNoPushPath
	}
	// ensure client id set
	if push.canonicalClientID() == [idSize]byte{} {
		push.ClientID = cid
		push.ServentID = cid
	}
	// call sendPush outside lock? peer.write locks own mutex; safe but avoid holding registry lock? keep simple
	return p.sendPush(push)
}

// Send is the exported alias for send.
func (r *pushRegistry) Send(args ...any) error { return r.send(args...) }

// sendPush writes a Push message to the peer.
func (p *peer) sendPush(push Push) error {
	if p == nil {
		return ErrNoPushPath
	}
	payload := EncodePush(push)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgPush,
		TTL:    7,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	return p.writeMessage(hdr, payload)
}
