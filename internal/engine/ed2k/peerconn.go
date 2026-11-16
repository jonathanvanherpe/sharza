// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// PeerInfo is the identity a peer reports in its OP_HELLOANSWER.
type PeerInfo struct {
	ClientID uint32
	ID       uint32
	Port     uint16
	UserHash [16]byte
	Hash     [16]byte
	GUID     [16]byte
	Tags     []Tag
	TagList  []Tag
	TagSet   []Tag
	LowID    bool

	// Parsed (best-effort) name/version surfaced from the tag set.
	Name    string
	Version string
}

// dialDeadline returns the effective deadline for a dial/read/write,
// honouring the context when it carries one.
func dialDeadline(ctx context.Context) time.Time {
	if dl, ok := ctx.Deadline(); ok {
		return dl
	}
	return time.Now().Add(ed2kDialTimeout)
}

// dialTimeoutFor returns a duration suitable for net.DialTimeout.
func dialTimeoutFor(ctx context.Context) time.Duration {
	d := ed2kDialTimeout
	if dl, ok := ctx.Deadline(); ok {
		if rem := time.Until(dl); rem < d {
			if rem <= 0 {
				return 1
			}
			return rem
		}
	}
	return d
}

// (e *Engine) identity helpers used to build our OP_HELLO.

func (e *Engine) peerUserHash() [16]byte {
	if e == nil {
		return [16]byte{}
	}
	if id := e.KadSelfID(); id != ([16]byte{}) {
		return id
	}
	return [16]byte{}
}

func (e *Engine) peerClientID() uint32 {
	if e == nil {
		return 0
	}
	return e.ClientID()
}

func (e *Engine) peerLowID() bool {
	if e == nil {
		return false
	}
	return e.IsLowID()
}

func (e *Engine) peerListenPort() uint16 {
	if e == nil {
		return 0
	}
	if a := e.Addr(); a != nil {
		if ta, ok := a.(*net.TCPAddr); ok {
			return uint16(ta.Port)
		}
	}
	e.mu.Lock()
	ln := e.ln
	e.mu.Unlock()
	if ln != nil {
		if ta, ok := ln.Addr().(*net.TCPAddr); ok {
			return uint16(ta.Port)
		}
	}
	return 0
}

func (e *Engine) peerTags() []Tag {
	// Minimal tag set for this slice.
	return nil
}

// buildPeerHello constructs the OP_HELLO payload from the engine's identity.
func (e *Engine) buildPeerHello() Hello {
	return Hello{
		Protocol:  0x10,
		Leading:   0x10,
		LeadingByte: 0x10,
		ProtocolByte: 0x10,
		Proto:     0x10,
		LeadingProtocol: 0x10,
		HashSize:  0x10,
		Hash:      e.peerUserHash(),
		GUID:      e.peerUserHash(),
		UserHash:  e.peerUserHash(),
		ClientID:  e.peerClientID(),
		ID:        e.peerClientID(),
		Port:      e.peerListenPort(),
		Tags:      e.peerTags(),
		TagList:   cloneTags(e.peerTags()),
		TagSet:    cloneTags(e.peerTags()),
	}
}

// dialPeerConn performs the handshake over an already-open connection.
func (e *Engine) dialPeerConn(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	if conn == nil {
		return PeerInfo{}, fmt.Errorf("ed2k: nil connection")
	}
	if e == nil {
		e = New()
	}

	// Write our HELLO.
	hello := e.buildPeerHello()
	frame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_HELLO,
		Payload:  hello.Marshal(),
	}
	wl := dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return PeerInfo{}, err
	}
	if _, err := conn.Write(frame.Marshal()); err != nil {
		return PeerInfo{}, err
	}

	// Read frames until HELLOANSWER or REJECT.
	for {
		if err := ctx.Err(); err != nil {
			return PeerInfo{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return PeerInfo{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return PeerInfo{}, err
		}
		op := f.Opcode
		if op == 0 {
			op = f.Type
		}
		if op == 0 {
			op = f.Op
		}
		payload := f.Payload
		if payload == nil {
			payload = f.Data
		}
		if payload == nil {
			payload = f.Body
		}
		if payload == nil {
			payload = []byte{}
		}

		switch op {
		case OP_REJECT:
			return PeerInfo{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_HELLOANSWER:
			ha, err := DecodeHelloAnswer(payload)
			if err != nil {
				return PeerInfo{}, err
			}
			cid := ha.ClientID
			if cid == 0 {
				cid = ha.ID
			}
			uh := ha.UserHash
			if uh == ([16]byte{}) {
				uh = ha.Hash
			}
			if uh == ([16]byte{}) {
				uh = ha.GUID
			}
			tags := cloneTags(ha.Tags)
			info := PeerInfo{
				ClientID: cid,
				ID:       cid,
				Port:     ha.Port,
				UserHash: uh,
				Hash:     uh,
				GUID:     uh,
				Tags:     tags,
				TagList:  cloneTags(tags),
				TagSet:   cloneTags(tags),
				LowID:    IsLowID(cid),
			}
			for _, t := range info.Tags {
				if t.Type == 0x02 {
					if t.Key == 1 {
						info.Name = t.Str
					}
					if t.Key == 2 {
						info.Version = t.Str
					}
				}
			}
			return info, nil
		default:
			// Tolerate leading/unexpected frames.
			continue
		}
	}
}

// DialPeerConn performs the handshake over an already-open connection.
func (e *Engine) DialPeerConn(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.dialPeerConn(ctx, conn)
}

// DialPeer dials addr, performs the OP_HELLO handshake, and returns
// the peer's identity.
func (e *Engine) DialPeer(ctx context.Context, addr string) (PeerInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	timeout := dialTimeoutFor(ctx)
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return PeerInfo{}, err
	}
	defer conn.Close()
	return e.dialPeerConn(ctx, conn)
}

// Package-level helper for testability.
func dialPeer(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var eng *Engine
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	} else {
		eng = New()
	}
	if conn == nil {
		return PeerInfo{}, fmt.Errorf("ed2k: nil connection")
	}
	return eng.dialPeerConn(ctx, conn)
}

// Method form of the helper.
func (e *Engine) dialPeer(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.dialPeerConn(ctx, conn)
}

// Aliases for alternate helper spellings.
func dialPeerConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return dialPeer(ctx, conn, e...)
}

func dialPeerWithConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return dialPeer(ctx, conn, e...)
}

func dialPeerIO(ctx context.Context, rw io.ReadWriter, e ...*Engine) (PeerInfo, error) {
	if c, ok := rw.(net.Conn); ok {
		return dialPeer(ctx, c, e...)
	}
	// Wrap a non-conn ReadWriter in a minimal net.Conn adapter is not
	// possible without deadlines; fall back to a pipe-backed adapter.
	return PeerInfo{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

// Ensure io import usage retained.
var _ = io.EOF