// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

const pushPayloadSize = 26

// ErrPushBadFormat is returned when PUSH is malformed.
var ErrPushBadFormat = errors.New("gnutella: malformed push")

// Push represents a Gnutella PUSH message (0x40).
// Payload: 16-byte servent ID, 4-byte file index (LE), 4-byte IP (BE),
// 2-byte port (LE).
type Push struct {
	ServentID [16]byte
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

// DecodePush decodes a Push from payload.
func DecodePush(payload []byte) (Push, error) {
	if len(payload) != pushPayloadSize {
		return Push{}, fmt.Errorf("%w: payload size %d", ErrPushBadFormat, len(payload))
	}
	var p Push
	copy(p.ServentID[:], payload[0:16])
	p.FileIndex = binary.LittleEndian.Uint32(payload[16:20])
	copy(p.IP[:], payload[20:24])
	p.Port = binary.LittleEndian.Uint16(payload[24:26])
	return p, nil
}

// pushRoute connects a servent ID to the peer connection context needed to route.
type pushRoute struct {
	pc *peerConn
}

// pushDialBack represents a pending dial-back for a (serventID, fileIndex) pair.
type pushDialBack struct {
	done    chan struct{}
	conn    net.Conn
	err     error
	expires time.Time
}

type pushKey struct {
	id        [16]byte
	fileIndex uint32
}

type pushRegistry struct {
	mu      sync.Mutex
	routes  map[[16]byte]pushRoute
	pending map[pushKey]*pushDialBack
	timeout time.Duration
}

func newPushRegistry(timeout time.Duration) *pushRegistry {
	if timeout <= 0 {
		timeout = 10 * time.Second
	}
	return &pushRegistry{
		routes:  make(map[[16]byte]pushRoute),
		pending: make(map[pushKey]*pushDialBack),
		timeout: timeout,
	}
}

func (r *pushRegistry) setRoute(id [16]byte, pc *peerConn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if pc == nil {
		delete(r.routes, id)
		return
	}
	r.routes[id] = pushRoute{pc: pc}
}

func (r *pushRegistry) getRoute(id [16]byte) (pushRoute, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pr, ok := r.routes[id]
	return pr, ok
}

func (r *pushRegistry) claim(id [16]byte, fileIndex uint32, conn net.Conn) {
	r.mu.Lock()
	defer r.mu.Unlock()
	k := pushKey{id: id, fileIndex: fileIndex}
	if pb, ok := r.pending[k]; ok {
		if pb.conn == nil {
			pb.conn = conn
		}
		close(pb.done)
		delete(r.pending, k)
	}
}

func (r *pushRegistry) waitFor(id [16]byte, fileIndex uint32) (*pushDialBack, func()) {
	pb := &pushDialBack{
		done:    make(chan struct{}),
		expires: time.Now().Add(r.timeout),
	}
	k := pushKey{id: id, fileIndex: fileIndex}
	r.mu.Lock()
	r.pending[k] = pb
	r.mu.Unlock()
	cancel := func() {
		r.mu.Lock()
		if p, ok := r.pending[k]; ok && p == pb {
			delete(r.pending, k)
		}
		r.mu.Unlock()
	}
	return pb, cancel
}

func (pb *pushDialBack) wait() (net.Conn, error) {
	t := time.NewTimer(time.Until(pb.expires))
	defer t.Stop()
	select {
	case <-t.C:
		return nil, errors.New("gnutella: push dial-back timeout")
	case <-pb.done:
		if pb.err != nil {
			return nil, pb.err
		}
		return pb.conn, nil
	}
}

// getPendingByAddr tries to match a pending dial-back by the remote address
// if the IP/port in the original PUSH are known? But we don't store them here.
// Keep simple: the engine can have a way to claim by addr - alternatively,
// we can allow claiming without exact key match if there's only one pending?
// But better to add a method that finds a pending waiting for any (we'll scan
// by checking - but not efficient; instead add claimAny style). Or alternatively
// pass the file index context differently. Let us also add methods.

func (r *pushRegistry) claimAny(conn net.Conn) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, pb := range r.pending {
		if pb.conn == nil {
			pb.conn = conn
			close(pb.done)
			delete(r.pending, k)
			return true
		}
	}
	return false
}
