// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// dialFileRequestConn performs the C2C handshake over an already-open
// connection, sends OP_FILEREQUEST for hash, and waits for
// OP_FILEREQANSWER (returned) or OP_FILENOTFOUND (ErrFileNotFound).
func (e *Engine) dialFileRequestConn(ctx context.Context, conn net.Conn, hash [16]byte) (PeerInfo, FileReqAnswer, error) {
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

// DialFileRequest dials a peer (or uses an open connection via the helper),
// performs the OP_HELLO handshake, sends OP_FILEREQUEST for hash, and
// returns the peer identity plus the reported file availability.
func (e *Engine) DialFileRequest(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}
	h := fileRequestHash(hash)

	if c, ok := target.(net.Conn); ok {
		return e.dialFileRequestConn(ctx, c, h)
	}
	if s, ok := target.(string); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", s, timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, err
		}
		defer conn.Close()
		return e.dialFileRequestConn(ctx, conn, h)
	}
	if st, ok := target.(fmt.Stringer); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", st.String(), timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, err
		}
		defer conn.Close()
		return e.dialFileRequestConn(ctx, conn, h)
	}
	return PeerInfo{}, FileReqAnswer{}, fmt.Errorf("ed2k: invalid target %T", target)
}

// RequestFileRequest is an alias for DialFileRequest.
func (e *Engine) RequestFileRequest(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, error) {
	return e.DialFileRequest(ctx, target, hash)
}

// FileRequest is a method alias (Engine-level) for DialFileRequest.
func (e *Engine) FileRequest(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, error) {
	return e.DialFileRequest(ctx, target, hash)
}

// Conn-arg method variants, mirroring DialPeerFileConn.
func (e *Engine) DialFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, append([]any{e}, args...)...)
}

func (e *Engine) RequestFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return e.DialFileRequestConn(ctx, conn, args...)
}

func (e *Engine) FileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return e.DialFileRequestConn(ctx, conn, args...)
}

// Package-level helper (testable), mirroring dialPeer.
func dialFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
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
	return eng.dialFileRequestConn(ctx, conn, fileRequestHash(hash))
}

// Package-level exported helper, mirroring DialPeer.
func DialFileRequest(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, error) {
	var eng *Engine
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	} else {
		eng = New()
	}
	return eng.DialFileRequest(ctx, target, hash)
}

// Package-level conn helper aliases.
func DialFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, args...)
}

func RequestFileRequest(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, error) {
	return DialFileRequest(ctx, target, hash, e...)
}

func RequestFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, args...)
}

func FileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, args...)
}

// IO variants.
func dialFileRequestIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, error) {
	if c, ok := rw.(net.Conn); ok {
		return dialFileRequest(ctx, c, args...)
	}
	return PeerInfo{}, FileReqAnswer{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func DialFileRequestIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequestIO(ctx, rw, args...)
}

// Alias spellings for the helper.
func dialFileRequestWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, args...)
}

func dialFileRequestDirect(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, args...)
}

var _ = time.Second
var _ = io.EOF

// Additional method aliases for lowercase helper spellings.
func (e *Engine) dialFileRequest(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, error) {
	return e.DialFileRequest(ctx, target, hash)
}

func (e *Engine) dialFileRequestIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequestIO(ctx, rw, args...)
}

// Package-level lowercase conn helper with the same name as the method.
func dialFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	// Support both dialFileRequestConn(ctx, conn, hash) and (... , e).
	// If a hash/engine ordering is ambiguous, scan args.
	var hash any
	var eng *Engine
	// If called as dialFileRequestConn(ctx, conn, hash, e...) the args include hash+engine.
	for _, a := range args {
		if en, ok := a.(*Engine); ok && en != nil {
			eng = en
		} else if hash == nil {
			hash = a
		}
	}
	if eng == nil {
		// try first arg as engine? already handled
	}
	if eng == nil {
		eng = New()
	}
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, fmt.Errorf("ed2k: nil connection")
	}
	if len(args) == 0 {
		return eng.dialFileRequestConn(ctx, conn, [16]byte{})
	}
	return eng.dialFileRequestConn(ctx, conn, fileRequestHash(hash))
}

// Generic alternate names.
func (e *Engine) fileRequest(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, error) {
	return e.DialFileRequest(ctx, target, hash)
}

func fileRequest(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, error) {
	var eng *Engine
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	} else {
		eng = New()
	}
	return eng.DialFileRequest(ctx, target, hash)
}

func fileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, args...)
}

func requestFileRequest2(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, error) {
	return dialFileRequest(ctx, conn, args...)
}
