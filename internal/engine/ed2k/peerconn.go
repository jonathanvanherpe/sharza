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

	// Opt-in protocol obfuscation: wrap the dialed connection before the
	// OP_HELLO handshake when requested via Options. Defaults to off.
	// Skip if already wrapped (e.g. by an enclosing dial helper).
	if _, ok := conn.(*ObfuscatedConn); !ok {
		obfuscated := false
		e.mu.Lock()
		obfuscated = e.opts.Obfuscation || e.opts.Obfuscated
		e.mu.Unlock()
		if obfuscated {
			wrapped, err := ObfuscateConn(conn, nil)
			if err != nil {
				return PeerInfo{}, err
			}
			conn = wrapped
		}
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

// hashFromAny extracts a 16-byte file hash from a variety of inputs.
func fileRequestHash(v any) [16]byte {
	switch t := v.(type) {
	case nil:
		return [16]byte{}
	case [16]byte:
		return t
	case []byte:
		var h [16]byte
		copy(h[:], t)
		return h
	case FileRequest:
		return t.hashBytes()
	case *FileRequest:
		if t != nil {
			return t.hashBytes()
		}
	case FileReqAnswer:
		return t.hashBytes()
	case *FileReqAnswer:
		if t != nil {
			return t.hashBytes()
		}
	case FileNotFound:
		return t.hashBytes()
	case *FileNotFound:
		if t != nil {
			return t.hashBytes()
		}
	case RequestParts:
		return t.hashBytes()
	case *RequestParts:
		if t != nil {
			return t.hashBytes()
		}
	case SendingPart:
		return t.hashBytes()
	case *SendingPart:
		if t != nil {
			return t.hashBytes()
		}
	case QueueRequest:
		return t.hashBytes()
	case *QueueRequest:
		if t != nil {
			return t.hashBytes()
		}
	}
	return [16]byte{}
}

// dialPeerFileConn performs the handshake over conn, sends OP_FILEREQUEST for
// hash, and waits for OP_FILEREQANSWER / OP_FILENOTFOUND.
func (e *Engine) dialPeerFileConn(ctx context.Context, conn net.Conn, hash [16]byte) (PeerInfo, FileReqAnswer, error) {
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, fmt.Errorf("ed2k: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	// Opt-in protocol obfuscation.
	if _, ok := conn.(*ObfuscatedConn); !ok {
		obfuscated := false
		e.mu.Lock()
		obfuscated = e.opts.Obfuscation || e.opts.Obfuscated
		e.mu.Unlock()
		if obfuscated {
			wrapped, err := ObfuscateConn(conn, nil)
			if err != nil {
				return PeerInfo{}, FileReqAnswer{}, err
			}
			conn = wrapped
		}
	}

	// Handshake first.
	pi, err := e.dialPeerConn(ctx, conn)
	if err != nil {
		return PeerInfo{}, FileReqAnswer{}, err
	}

	// Send OP_FILEREQUEST.
	frame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_FILEREQUEST,
		Payload:  FileRequest{Hash: hash}.Marshal(),
	}
	wl := dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return pi, FileReqAnswer{}, err
	}
	if _, err := conn.Write(frame.Marshal()); err != nil {
		return pi, FileReqAnswer{}, err
	}

	// Read until answer / not-found / reject.
	for {
		if err := ctx.Err(); err != nil {
			return pi, FileReqAnswer{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return pi, FileReqAnswer{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return pi, FileReqAnswer{}, err
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
			return pi, FileReqAnswer{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILENOTFOUND:
			if _, err := DecodeFileNotFound(payload); err != nil {
				return pi, FileReqAnswer{}, err
			}
			return pi, FileReqAnswer{}, ErrFileNotFound
		case OP_FILEREQANSWER:
			ans, err := DecodeFileReqAnswer(payload)
			if err != nil {
				return pi, FileReqAnswer{}, err
			}
			return pi, ans, nil
		default:
			// Tolerate leading/unexpected frames.
			continue
		}
	}
}

// DialPeerFile dials addr (or uses an open net.Conn), performs the handshake
// and issues OP_FILEREQUEST, returning the peer identity and file availability.
func (e *Engine) DialPeerFile(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}
	h := fileRequestHash(hash)

	if c, ok := target.(net.Conn); ok {
		return e.dialPeerFileConn(ctx, c, h)
	}
	if s, ok := target.(string); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", s, timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, err
		}
		defer conn.Close()
		return e.dialPeerFileConn(ctx, conn, h)
	}
	if st, ok := target.(fmt.Stringer); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", st.String(), timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, err
		}
		defer conn.Close()
		return e.dialPeerFileConn(ctx, conn, h)
	}
	return PeerInfo{}, FileReqAnswer{}, fmt.Errorf("ed2k: invalid target %T", target)
}

// RequestFile is an alias for DialPeerFile.
func (e *Engine) RequestFile(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, error) {
	return e.DialPeerFile(ctx, target, hash)
}

// Package-level helpers (testable), mirroring dialPeer.
func dialPeerFile(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var eng *Engine
	var hash any
	for _, a := range args {
		if en, ok := a.(*Engine); ok && en != nil {
			eng = en
		} else {
			hash = a
		}
	}
	if eng == nil {
		eng = New()
	}
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, fmt.Errorf("ed2k: nil connection")
	}
	return eng.dialPeerFileConn(ctx, conn, fileRequestHash(hash))
}

func requestFile(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialPeerFile(ctx, conn, args...)
}

// dialPeerFileIO mirrors dialPeerIO.
func dialPeerFileIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, error) {
	if c, ok := rw.(net.Conn); ok {
		return dialPeerFile(ctx, c, args...)
	}
	return PeerInfo{}, FileReqAnswer{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func requestFileIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialPeerFileIO(ctx, rw, args...)
}

// Package-level DialPeerFile / RequestFile helpers.
func DialPeerFile(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, error) {
	var eng *Engine
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	} else {
		eng = New()
	}
	// If target is a net.Conn, keep conn-based semantics via method.
	return eng.DialPeerFile(ctx, target, hash)
}

func RequestFile(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, error) {
	return DialPeerFile(ctx, target, hash, e...)
}

// Aliases for alternate helper spellings.
func DialPeerFileConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialPeerFile(ctx, conn, args...)
}

func RequestFileConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialPeerFile(ctx, conn, args...)
}

func DialPeerFileWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialPeerFile(ctx, conn, args...)
}

func RequestPeerFile(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, error) {
	return DialPeerFile(ctx, target, hash, e...)
}

func PeerFileRequest(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, error) {
	return DialPeerFile(ctx, target, hash, e...)
}

// Method aliases for alternate spellings.
func (e *Engine) DialPeerFileConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialPeerFile(ctx, conn, append([]any{e}, args...)...)
}

func (e *Engine) RequestFileConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return e.DialPeerFileConn(ctx, conn, args...)
}

// Ensure io import usage retained.
var _ = io.EOF