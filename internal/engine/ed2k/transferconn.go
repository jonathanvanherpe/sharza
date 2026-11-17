// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
)

// dialTransferConn performs the C2C handshake over an already-open
// connection, sends OP_FILEREQUEST for hash, waits for OP_FILEREQANSWER
// (or OP_FILENOTFOUND), then sends OP_REQUESTPARTS carrying the requested
// byte ranges and reads OP_SENDINGPART.
func (e *Engine) dialTransferConn(ctx context.Context, conn net.Conn, hash [16]byte, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, SendingPart{}, fmt.Errorf("ed2k: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	// Handshake first.
	pi, err := e.dialPeerConn(ctx, conn)
	if err != nil {
		return PeerInfo{}, FileReqAnswer{}, SendingPart{}, err
	}

	// Send OP_FILEREQUEST.
	frFrame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_FILEREQUEST,
		Payload:  FileRequest{Hash: hash}.Marshal(),
	}
	wl := dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return pi, FileReqAnswer{}, SendingPart{}, err
	}
	if _, err := conn.Write(frFrame.Marshal()); err != nil {
		return pi, FileReqAnswer{}, SendingPart{}, err
	}

	// Read until answer / not-found / reject.
	var ans FileReqAnswer
	answerFound := false
	for !answerFound {
		if err := ctx.Err(); err != nil {
			return pi, FileReqAnswer{}, SendingPart{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return pi, FileReqAnswer{}, SendingPart{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return pi, FileReqAnswer{}, SendingPart{}, err
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
			return pi, FileReqAnswer{}, SendingPart{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILENOTFOUND:
			if _, err := DecodeFileNotFound(payload); err != nil {
				return pi, FileReqAnswer{}, SendingPart{}, err
			}
			return pi, FileReqAnswer{}, SendingPart{}, ErrFileNotFound
		case OP_FILEREQANSWER:
			a, err := DecodeFileReqAnswer(payload)
			if err != nil {
				return pi, FileReqAnswer{}, SendingPart{}, err
			}
			ans = a
			answerFound = true
		default:
			// tolerate
		}
	}

	// Build RequestParts from hash + ranges.
	rp := requestPartsFromArgs(hash, ranges...)

	// Send OP_REQUESTPARTS.
	rpFrame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_REQUESTPARTS,
		Payload:  rp.Marshal(),
	}
	wl = dialDeadline(ctx)
	if err := conn.SetWriteDeadline(wl); err != nil {
		return pi, ans, SendingPart{}, err
	}
	if _, err := conn.Write(rpFrame.Marshal()); err != nil {
		return pi, ans, SendingPart{}, err
	}

	// Read until OP_SENDINGPART / reject / not-found.
	for {
		if err := ctx.Err(); err != nil {
			return pi, ans, SendingPart{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return pi, ans, SendingPart{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return pi, ans, SendingPart{}, err
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
			return pi, ans, SendingPart{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILENOTFOUND:
			if _, err := DecodeFileNotFound(payload); err != nil {
				return pi, ans, SendingPart{}, err
			}
			return pi, ans, SendingPart{}, ErrFileNotFound
		case OP_SENDINGPART:
			sp, err := DecodeSendingPart(payload)
			if err != nil {
				return pi, ans, SendingPart{}, err
			}
			if sp.hashBytes() == ([16]byte{}) {
				sp.Hash = hash
				sp.FileHash = hash
				sp.MD4 = hash
			}
			return pi, ans, sp, nil
		default:
			continue
		}
	}
}

// DialTransfer dials a peer (or uses an open connection via the helper),
// performs the handshake, file request, and requests parts, returning peer
// identity, file availability and received data.
func (e *Engine) DialTransfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	// Extract hash/ranges if hash is a RequestParts carrying ranges.
	var h [16]byte
	var extra []any
	switch t := hash.(type) {
	case RequestParts:
		h = t.hashBytes()
		extra = append(extra, t)
	case *RequestParts:
		if t != nil {
			h = t.hashBytes()
			extra = append(extra, *t)
		}
	default:
		h = fileRequestHash(hash)
	}
	extra = append(extra, ranges...)

	if c, ok := target.(net.Conn); ok {
		return e.dialTransferConn(ctx, c, h, extra...)
	}
	if s, ok := target.(string); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", s, timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, SendingPart{}, err
		}
		defer conn.Close()
		return e.dialTransferConn(ctx, conn, h, extra...)
	}
	if st, ok := target.(fmt.Stringer); ok {
		timeout := dialTimeoutFor(ctx)
		conn, err := net.DialTimeout("tcp", st.String(), timeout)
		if err != nil {
			return PeerInfo{}, FileReqAnswer{}, SendingPart{}, err
		}
		defer conn.Close()
		return e.dialTransferConn(ctx, conn, h, extra...)
	}
	return PeerInfo{}, FileReqAnswer{}, SendingPart{}, fmt.Errorf("ed2k: invalid target %T", target)
}

// Aliases.
func (e *Engine) RequestTransfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransfer(ctx, target, hash, ranges...)
}

func (e *Engine) Transfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransfer(ctx, target, hash, ranges...)
}

func (e *Engine) RequestParts(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransfer(ctx, target, hash, ranges...)
}

func (e *Engine) DialParts(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransfer(ctx, target, hash, ranges...)
}

func (e *Engine) Parts(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransfer(ctx, target, hash, ranges...)
}

// Conn-arg method variants.
func (e *Engine) DialTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, append([]any{e}, args...)...)
}

func (e *Engine) RequestTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransferConn(ctx, conn, args...)
}

func (e *Engine) TransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransferConn(ctx, conn, args...)
}

func (e *Engine) RequestPartsConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransferConn(ctx, conn, args...)
}

func (e *Engine) DialPartsConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransferConn(ctx, conn, args...)
}

// Package-level helper (testable), mirroring dialPeerFile.
func dialTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var eng *Engine
	var hash any
	var ranges []any
	for _, a := range args {
		if en, ok := a.(*Engine); ok && en != nil {
			eng = en
			continue
		}
		if hash == nil && isHashLike(a) {
			hash = a
			continue
		}
		ranges = append(ranges, a)
	}
	if eng == nil {
		eng = New()
	}
	if conn == nil {
		return PeerInfo{}, FileReqAnswer{}, SendingPart{}, fmt.Errorf("ed2k: nil connection")
	}
	h := fileRequestHash(hash)
	// If hash was a RequestParts, include it in ranges for range extraction.
	switch hash.(type) {
	case RequestParts, *RequestParts:
		ranges = append([]any{hash}, ranges...)
	}
	return eng.dialTransferConn(ctx, conn, h, ranges...)
}

// Package-level helpers.
func DialTransfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	eng := New()
	return eng.DialTransfer(ctx, target, hash, ranges...)
}

func RequestTransfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return DialTransfer(ctx, target, hash, ranges...)
}

func Transfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return DialTransfer(ctx, target, hash, ranges...)
}


func DialParts(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return DialTransfer(ctx, target, hash, ranges...)
}

// Conn helpers.
func DialTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

func RequestTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

func TransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

func RequestPartsConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

func DialPartsConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

// IO variants.
func dialTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	if c, ok := rw.(net.Conn); ok {
		return dialTransfer(ctx, c, args...)
	}
	return PeerInfo{}, FileReqAnswer{}, SendingPart{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func DialTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransferIO(ctx, rw, args...)
}

func RequestTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransferIO(ctx, rw, args...)
}

func TransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransferIO(ctx, rw, args...)
}

func RequestPartsIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransferIO(ctx, rw, args...)
}

// Alias spellings.
func dialTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

func dialTransferWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

func dialTransferDirect(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

// Method aliases for alternate spellings.
func (e *Engine) dialTransfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransfer(ctx, target, hash, ranges...)
}

func (e *Engine) dialTransferConnMethod(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransferConn(ctx, conn, args...)
}

// Generic alternate names.
func (e *Engine) transfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return e.DialTransfer(ctx, target, hash, ranges...)
}

func transfer(ctx context.Context, target any, hash any, ranges ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	eng := New()
	return eng.DialTransfer(ctx, target, hash, ranges...)
}

func transferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

func requestTransfer2(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileReqAnswer, SendingPart, error) {
	return dialTransfer(ctx, conn, args...)
}

// requestPartsFromArgs builds a RequestParts from hash and flexible range args.
func requestPartsFromArgs(hash [16]byte, args ...any) RequestParts {
	rp := RequestParts{}
	if hash != ([16]byte{}) {
		rp.Hash = hash
		rp.FileHash = hash
		rp.MD4 = hash
	}

	type rangePair struct{ from, to uint32 }
	var pairs []rangePair

	// pending array handling
	var pending []uint32
	flushPending := func(bis []uint32) {
		if pending == nil {
			return
		}
		if len(pending) == 3 {
			if bis == nil {
				for i := 0; i < 3; i++ {
					pairs = append(pairs, rangePair{pending[i], pending[i]})
				}
			} else {
				for i := 0; i < 3 && i < len(bis); i++ {
					pairs = append(pairs, rangePair{pending[i], bis[i]})
				}
			}
		} else if len(pending) == 2 {
			pairs = append(pairs, rangePair{pending[0], pending[1]})
		} else if len(pending) == 6 {
			for i := 0; i < 3; i++ {
				pairs = append(pairs, rangePair{pending[i], pending[i+3]})
			}
		}
		pending = nil
	}

	var process func(v any)
	process = func(v any) {
		switch t := v.(type) {
		case nil:
		case RequestParts:
			if rp.hashBytes() == ([16]byte{}) {
				if h := t.hashBytes(); h != ([16]byte{}) {
					rp.Hash = h
					rp.FileHash = h
					rp.MD4 = h
				}
			}
			von := t.vonArray()
			bis := t.bisArray()
			// only add if any non-zero
			for i := 0; i < 3; i++ {
				if von[i] != 0 || bis[i] != 0 {
					pairs = append(pairs, rangePair{von[i], bis[i]})
				}
			}
		case *RequestParts:
			if t != nil {
				process(*t)
			}
		case SendingPart:
			pairs = append(pairs, rangePair{t.vonValue(), t.bisValue()})
			if rp.hashBytes() == ([16]byte{}) {
				if h := t.hashBytes(); h != ([16]byte{}) {
					rp.Hash = h
					rp.FileHash = h
					rp.MD4 = h
				}
			}
		case *SendingPart:
			if t != nil {
				process(*t)
			}
		case [3]uint32:
			arr := t
			if pending == nil {
				pending = []uint32{arr[0], arr[1], arr[2]}
			} else {
				flushPending([]uint32{arr[0], arr[1], arr[2]})
				pending = nil
			}
		case []uint32:
			if len(t) == 2 {
				pairs = append(pairs, rangePair{t[0], t[1]})
			} else if len(t) == 6 {
				for i := 0; i < 3; i++ {
					pairs = append(pairs, rangePair{t[i], t[i+3]})
				}
			} else if len(t) == 3 {
				if pending == nil {
					pending = append([]uint32(nil), t...)
				} else {
					flushPending(t)
				}
			} else if len(t) > 0 {
				// try pairs
				for i := 0; i+1 < len(t); i += 2 {
					pairs = append(pairs, rangePair{t[i], t[i+1]})
				}
			}
		case []any:
			for _, x := range t {
				process(x)
			}
		default:
			// numeric single values: accumulate
			switch v := t.(type) {
			case uint8:
				pending = append(pending, uint32(v))
			case uint16:
				pending = append(pending, uint32(v))
			case uint32:
				pending = append(pending, v)
			case uint64:
				pending = append(pending, uint32(v))
			case int:
				pending = append(pending, uint32(v))
			case int32:
				pending = append(pending, uint32(v))
			case int64:
				pending = append(pending, uint32(v))
			}
		}
	}

	for _, a := range args {
		process(a)
	}
	flushPending(nil)

	// Apply pairs to Von/Bis arrays (up to 3).
	von := [3]uint32{}
	bis := [3]uint32{}
	for i := 0; i < 3 && i < len(pairs); i++ {
		von[i] = pairs[i].from
		bis[i] = pairs[i].to
	}
	// If no pairs and pending produced nothing, leave zeros.
	rp.Von = von
	rp.Vons = von
	rp.From = von
	rp.Froms = von
	rp.Start = von
	rp.Starts = von
	rp.Begin = von
	rp.Begins = von
	rp.Von1 = von[0]
	rp.Von2 = von[1]
	rp.Von3 = von[2]

	rp.Bis = bis
	rp.Biss = bis
	rp.To = bis
	rp.Tos = bis
	rp.End = bis
	rp.Ends = bis
	rp.Finish = bis
	rp.Finishes = bis
	rp.Bis1 = bis[0]
	rp.Bis2 = bis[1]
	rp.Bis3 = bis[2]

	return rp
}

func isHashLike(v any) bool {
	switch v.(type) {
	case nil, [16]byte, []byte,
		FileRequest, *FileRequest,
		FileReqAnswer, *FileReqAnswer,
		FileNotFound, *FileNotFound,
		RequestParts, *RequestParts,
		SendingPart, *SendingPart:
		return true
	}
	return false
}

// Ensure io import usage retained.
var _ = io.EOF
