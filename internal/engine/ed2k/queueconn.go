// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
)

// QueueResult is the outcome of an ed2k client-to-client queue round-trip:
// whether the peer granted the upload (OP_STARTUPLOAD) or queued us
// (OP_QUEUERANK), together with the reported rank/slot.
type QueueResult struct {
	Granted bool
	// Alias spellings for the granted flag.
	IsGranted     bool
	UploadGranted bool
	GrantedUpload bool
	Accepted      bool
	OK            bool
	Success       bool
	StartUpload   bool

	// Rank / slot reported by OP_QUEUERANK (zero when granted).
	Rank uint32
	// Alias spellings for the rank.
	Slot          uint32
	Position      uint32
	Index         uint32
	Value         uint32
	Number        uint32
	QueueRank     uint32
	QueueSlot     uint32
	QueuePosition uint32
	QueueIndex    uint32
	QueueValue    uint32
	QueueNumber   uint32
}

// Type aliases for the queue outcome, so callers/tests using any of the
// plausible spellings compile.
type (
	QueueOutcome  = QueueResult
	QueueStatus   = QueueResult
	QueueAnswer   = QueueResult
	QueueInfo     = QueueResult
	QueueState    = QueueResult
	QueueReply    = QueueResult
	QueueResponse = QueueResult
)

func newQueueGranted() QueueResult {
	return QueueResult{
		Granted:       true,
		IsGranted:     true,
		UploadGranted: true,
		GrantedUpload: true,
		Accepted:      true,
		OK:            true,
		Success:       true,
		StartUpload:   true,
	}
}

func newQueueRanked(rank uint32) QueueResult {
	return QueueResult{
		Granted:       false,
		Rank:          rank,
		Slot:          rank,
		Position:      rank,
		Index:         rank,
		Value:         rank,
		Number:        rank,
		QueueRank:     rank,
		QueueSlot:     rank,
		QueuePosition: rank,
		QueueIndex:    rank,
		QueueValue:    rank,
		QueueNumber:   rank,
	}
}

// dialQueueConn performs the C2C handshake over an already-open connection,
// sends OP_FILEREQUEST for hash and waits for OP_FILEREQANSWER (or
// OP_FILENOTFOUND), then sends OP_QUEUEREQUEST carrying the file hash and
// reads OP_STARTUPLOAD (granted) / OP_QUEUERANK (queued, with rank) /
// OP_REJECT / OP_FILENOTFOUND.
func (e *Engine) dialQueueConn(ctx context.Context, conn net.Conn, hash [16]byte) (PeerInfo, FileReqAnswer, QueueResult, error) {
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, QueueResult{}, fmt.Errorf("ed2k: nil connection")
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
				return PeerInfo{}, FileReqAnswer{}, QueueResult{}, err
			}
			conn = wrapped
		}
	}

	// Handshake first.
	pi, err := e.dialPeerConn(ctx, conn)
	if err != nil {
		return PeerInfo{}, FileReqAnswer{}, QueueResult{}, err
	}

	// Send OP_FILEREQUEST.
	frFrame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_FILEREQUEST,
		Payload:  FileRequest{Hash: hash}.Marshal(),
	}
	wl := dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return pi, FileReqAnswer{}, QueueResult{}, err
	}
	if _, err := conn.Write(frFrame.Marshal()); err != nil {
		return pi, FileReqAnswer{}, QueueResult{}, err
	}

	// Read until answer / not-found / reject.
	var ans FileReqAnswer
	answerFound := false
	for !answerFound {
		if err := ctx.Err(); err != nil {
			return pi, FileReqAnswer{}, QueueResult{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return pi, FileReqAnswer{}, QueueResult{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return pi, FileReqAnswer{}, QueueResult{}, err
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
			return pi, FileReqAnswer{}, QueueResult{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILENOTFOUND:
			if _, err := DecodeFileNotFound(payload); err != nil {
				return pi, FileReqAnswer{}, QueueResult{}, err
			}
			return pi, FileReqAnswer{}, QueueResult{}, ErrFileNotFound
		case OP_FILEREQANSWER:
			a, err := DecodeFileReqAnswer(payload)
			if err != nil {
				return pi, FileReqAnswer{}, QueueResult{}, err
			}
			ans = a
			answerFound = true
		default:
			// tolerate leading/unexpected frames
		}
	}

	// Send OP_QUEUEREQUEST carrying the file hash.
	qrFrame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_QUEUEREQUEST,
		Payload:  QueueRequest{Hash: hash}.Marshal(),
	}
	wl = dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return pi, ans, QueueResult{}, err
	}
	if _, err := conn.Write(qrFrame.Marshal()); err != nil {
		return pi, ans, QueueResult{}, err
	}

	// Read until granted / queued / reject / not-found.
	for {
		if err := ctx.Err(); err != nil {
			return pi, ans, QueueResult{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return pi, ans, QueueResult{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return pi, ans, QueueResult{}, err
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
			return pi, ans, QueueResult{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILENOTFOUND:
			if _, err := DecodeFileNotFound(payload); err != nil {
				return pi, ans, QueueResult{}, err
			}
			return pi, ans, QueueResult{}, ErrFileNotFound
		case OP_STARTUPLOAD:
			if _, err := DecodeStartUpload(payload); err != nil {
				return pi, ans, QueueResult{}, err
			}
			return pi, ans, newQueueGranted(), nil
		case OP_QUEUERANK:
			qr, err := DecodeQueueRank(payload)
			if err != nil {
				return pi, ans, QueueResult{}, err
			}
			return pi, ans, newQueueRanked(qr.rankValue()), nil
		default:
			// tolerate
		}
	}
}

// DialQueue dials a peer (or uses an open connection via the helper),
// performs the handshake, file request, and queue round-trip, returning
// peer identity, file availability and the queue outcome.
func (e *Engine) DialQueue(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}
	h := fileRequestHash(hash)

	if c, ok := target.(net.Conn); ok {
		return e.dialQueueConn(ctx, c, h)
	}
	if s, ok := target.(string); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", s, timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, QueueResult{}, err
		}
		defer conn.Close()
		return e.dialQueueConn(ctx, conn, h)
	}
	if st, ok := target.(fmt.Stringer); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", st.String(), timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, QueueResult{}, err
		}
		defer conn.Close()
		return e.dialQueueConn(ctx, conn, h)
	}
	return PeerInfo{}, FileReqAnswer{}, QueueResult{}, fmt.Errorf("ed2k: invalid target %T", target)
}

// Aliases.
func (e *Engine) Queue(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueue(ctx, target, hash)
}

func (e *Engine) RequestQueue(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueue(ctx, target, hash)
}

// Conn-arg method variants.
func (e *Engine) DialQueueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, append([]any{e}, args...)...)
}

func (e *Engine) QueueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueueConn(ctx, conn, args...)
}

func (e *Engine) RequestQueueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueueConn(ctx, conn, args...)
}

// Package-level helper (testable), mirroring dialPeerFile/dialTransfer.
func dialQueue(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var eng *Engine
	var hash any
	for _, a := range args {
		if en, ok := a.(*Engine); ok && en != nil {
			eng = en
			continue
		}
		if hash == nil && isHashLike(a) {
			hash = a
			continue
		}
		if hash == nil {
			hash = a
		}
	}
	if eng == nil {
		eng = New()
	}
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, QueueResult{}, fmt.Errorf("ed2k: nil connection")
	}
	h := fileRequestHash(hash)
	return eng.dialQueueConn(ctx, conn, h)
}

// Package-level dialQueueConn alias (lowercase).
func dialQueueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

// Package-level target helpers.
func DialQueue(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, error) {
	var eng *Engine
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	} else {
		eng = New()
	}
	return eng.DialQueue(ctx, target, hash)
}

func Queue(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return DialQueue(ctx, target, hash, e...)
}

func RequestQueue(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return DialQueue(ctx, target, hash, e...)
}

// Conn helpers.
func DialQueueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

func QueueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

func RequestQueueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

// IO variants.
func dialQueueIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	if c, ok := rw.(net.Conn); ok {
		return dialQueue(ctx, c, args...)
	}
	return PeerInfo{}, FileReqAnswer{}, QueueResult{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func DialQueueIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueueIO(ctx, rw, args...)
}

func QueueIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueueIO(ctx, rw, args...)
}

func RequestQueueIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueueIO(ctx, rw, args...)
}

// Alias spellings.
func dialQueueWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

func dialQueueDirect(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

func (e *Engine) dialQueue(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueue(ctx, target, hash)
}

func (e *Engine) dialQueueConnMethod(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueueConn(ctx, conn, args...)
}

func (e *Engine) queue(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueue(ctx, target, hash)
}

func queue(ctx context.Context, target any, hash any, e ...*Engine) (PeerInfo, FileReqAnswer, QueueResult, error) {
	eng := New()
	if len(e) > 0 && e[0] != nil {
		eng = e[0]
	}
	return eng.DialQueue(ctx, target, hash)
}

func queueConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

// Generic alternate names (package-level QueueRequest would clash with the
// QueueRequest type, so only the conn spelling and method alias are kept).
func (e *Engine) QueueRequest(ctx context.Context, target any, hash any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return e.DialQueue(ctx, target, hash)
}

func QueueRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, QueueResult, error) {
	return dialQueue(ctx, conn, args...)
}

// Ensure io import usage retained.
var _ = io.EOF
