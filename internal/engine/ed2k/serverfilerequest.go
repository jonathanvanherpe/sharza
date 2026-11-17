// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// serveFileRequestConn is the server-side (incoming) peer file request
// flow: read the peer's OP_HELLO, reply with OP_HELLOANSWER carrying our
// identity, then read the peer's OP_FILEREQUEST, decode it, compare the
// requested hash against the caller-supplied available file (hash + name),
// and reply with OP_FILEREQANSWER on match or OP_FILENOTFOUND otherwise.
// It returns the peer identity and the decoded request.
func (e *Engine) serveFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	if conn == nil {
		return PeerInfo{}, FileRequest{}, fmt.Errorf("ed2k: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	availHash, availName, hasAvailable := parseAvailableFile(args)

	// --- Handshake: read OP_HELLO. ---
	var peer PeerInfo
	for {
		if err := ctx.Err(); err != nil {
			return PeerInfo{}, FileRequest{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return PeerInfo{}, FileRequest{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return PeerInfo{}, FileRequest{}, err
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
			return PeerInfo{}, FileRequest{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_HELLO:
			h, err := DecodeHello(payload)
			if err != nil {
				return PeerInfo{}, FileRequest{}, err
			}
			cid := h.ClientID
			if cid == 0 {
				cid = h.ID
			}
			uh := h.UserHash
			if uh == ([16]byte{}) {
				uh = h.Hash
			}
			if uh == ([16]byte{}) {
				uh = h.GUID
			}
			tags := cloneTags(h.Tags)
			info := PeerInfo{
				ClientID: cid,
				ID:       cid,
				Port:     h.Port,
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
			peer = info

			// Write OP_HELLOANSWER.
			ha := e.buildPeerHelloAnswer()
			frame := Frame{
				Protocol: ProtocolEDonkey,
				Opcode:   OP_HELLOANSWER,
				Payload:  ha.Marshal(),
			}
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return PeerInfo{}, FileRequest{}, err
			}
			if _, err := conn.Write(frame.Marshal()); err != nil {
				return PeerInfo{}, FileRequest{}, err
			}
			// proceed to file request read
			goto readRequest
		default:
			return PeerInfo{}, FileRequest{}, fmt.Errorf("ed2k: unexpected opcode 0x%02X", op)
		}
	}

readRequest:
	for {
		if err := ctx.Err(); err != nil {
			return peer, FileRequest{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return peer, FileRequest{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return peer, FileRequest{}, err
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
			return peer, FileRequest{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILEREQUEST:
			fr, err := DecodeFileRequest(payload)
			if err != nil {
				return peer, FileRequest{}, err
			}
			reqHash := fr.hashBytes()

			found := hasAvailable && reqHash == availHash
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return peer, fr, err
			}
			if found {
				ans := FileReqAnswer{Hash: availHash, Name: availName}
				if ans.hashBytes() == ([16]byte{}) {
					ans.Hash = reqHash
				}
				frame := Frame{
					Protocol: ProtocolEDonkey,
					Opcode:   OP_FILEREQANSWER,
					Payload:  ans.Marshal(),
				}
				if _, err := conn.Write(frame.Marshal()); err != nil {
					return peer, fr, err
				}
			} else {
				frame := Frame{
					Protocol: ProtocolEDonkey,
					Opcode:   OP_FILENOTFOUND,
					Payload:  FileNotFound{Hash: reqHash}.Marshal(),
				}
				if _, err := conn.Write(frame.Marshal()); err != nil {
					return peer, fr, err
				}
			}
			return peer, fr, nil
		default:
			// Tolerate leading/unexpected frames.
			continue
		}
	}
}

// parseAvailableFile extracts an available file hash + name from flexible args.
func parseAvailableFile(args []any) ([16]byte, string, bool) {
	var hash [16]byte
	var name string
	has := false
	for _, a := range args {
		if a == nil {
			continue
		}
		if en, ok := a.(*Engine); ok && en != nil {
			continue
		}
		switch t := a.(type) {
		case string:
			if t != "" {
				name = t
				has = true
			}
		case [16]byte:
			hash = t
			has = true
		case []byte:
			var h [16]byte
			copy(h[:], t)
			hash = h
			has = true
		case FileReqAnswer:
			h := t.hashBytes()
			if h != ([16]byte{}) {
				hash = h
			}
			if n := t.nameValue(); n != "" {
				name = n
			}
			has = true
		case *FileReqAnswer:
			if t != nil {
				h := t.hashBytes()
				if h != ([16]byte{}) {
					hash = h
				}
				if n := t.nameValue(); n != "" {
					name = n
				}
				has = true
			}
		case FileRequest:
			h := t.hashBytes()
			if h != ([16]byte{}) {
				hash = h
			}
			has = true
		case *FileRequest:
			if t != nil {
				h := t.hashBytes()
				if h != ([16]byte{}) {
					hash = h
				}
				has = true
			}
		case FileNotFound:
			h := t.hashBytes()
			if h != ([16]byte{}) {
				hash = h
			}
			has = true
		case *FileNotFound:
			if t != nil {
				h := t.hashBytes()
				if h != ([16]byte{}) {
					hash = h
				}
				has = true
			}
		default:
			h := fileRequestHash(t)
			if h != ([16]byte{}) {
				hash = h
				has = true
			} else if st, ok := t.(fmt.Stringer); ok {
				s := st.String()
				if s != "" {
					name = s
					has = true
				}
			}
		}
	}
	// If only a name was provided (hash stays zero), still mark available
	// only when a non-empty name is present.
	if !has {
		// nothing
	}
	if name == "" && hash == ([16]byte{}) {
		// Could still be an explicit empty availability; treat args presence
		// as availability only if args non-empty. Already tracked by has.
	}
	return hash, name, has
}

// ---- Engine method aliases ----

func (e *Engine) ServeFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) HandleFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) AcceptFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) ServeFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) HandleFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) AcceptFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

// lowercase method aliases
func (e *Engine) serveFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) handleFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) acceptFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConn(ctx, conn, args...)
}

func (e *Engine) serveFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	if c, ok := rw.(net.Conn); ok {
		return e.serveFileRequestConn(ctx, c, args...)
	}
	return PeerInfo{}, FileRequest{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func (e *Engine) ServeFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return e.serveFileRequestConnIO(ctx, rw, args...)
}

func (e *Engine) HandleFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return e.ServeFileRequestConnIO(ctx, rw, args...)
}

func (e *Engine) AcceptFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return e.ServeFileRequestConnIO(ctx, rw, args...)
}

// ---- Package-level helpers ----

func serveFileRequestConnPkg(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var eng *Engine
	var rest []any
	for _, a := range args {
		if en, ok := a.(*Engine); ok && en != nil {
			eng = en
		} else {
			rest = append(rest, a)
		}
	}
	if eng == nil {
		eng = New()
	}
	if conn == nil {
		return PeerInfo{}, FileRequest{}, fmt.Errorf("ed2k: nil connection")
	}
	return eng.serveFileRequestConn(ctx, conn, rest...)
}

// lowercase package-level base
func serveFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func handleFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func acceptFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func serveFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func handleFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func acceptFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

// Uppercase package-level helpers
func ServeFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func HandleFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func AcceptFileRequestConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func ServeFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func HandleFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

func AcceptFileRequest(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnPkg(ctx, conn, args...)
}

// IO variants (package-level)
func serveFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	if c, ok := rw.(net.Conn); ok {
		return serveFileRequestConnPkg(ctx, c, args...)
	}
	return PeerInfo{}, FileRequest{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func ServeFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnIO(ctx, rw, args...)
}

func HandleFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnIO(ctx, rw, args...)
}

func AcceptFileRequestConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnIO(ctx, rw, args...)
}

func ServeFileRequestIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnIO(ctx, rw, args...)
}

// lowercase IO aliases
func serveFileRequestIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, error) {
	return serveFileRequestConnIO(ctx, rw, args...)
}

// Additional alternate spellings / aliases
func ServeFileRequestWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return ServeFileRequestConn(ctx, conn, args...)
}

func HandleFileRequestWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return HandleFileRequestConn(ctx, conn, args...)
}

func AcceptFileRequestWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, error) {
	return AcceptFileRequestConn(ctx, conn, args...)
}

// ensure time/io usage
var _ = time.Second
var _ = io.EOF
