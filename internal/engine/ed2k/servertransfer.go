// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// serveTransferConn is the server-side (incoming) transfer flow:
// read the peer's OP_HELLO, reply with OP_HELLOANSWER carrying our
// identity; read the peer's OP_FILEREQUEST, decode it, compare the
// requested hash against the caller-supplied available file (hash + name),
// and reply with OP_FILEREQANSWER on match or OP_FILENOTFOUND otherwise;
// then read the peer's OP_REQUESTPARTS, decode it, and reply with
// OP_SENDINGPART carrying caller-supplied bytes sliced from the optional
// source buffer by the request's von/bis range.
// It returns the peer identity, the decoded FileRequest, the decoded
// RequestParts, and the SendingPart that was sent.
func (e *Engine) serveTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	if conn == nil {
		return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	availHash, availName, source, hasAvailable := parseTransferAvailable(args)

	var fr FileRequest
	var rp RequestParts

	// --- Handshake: read OP_HELLO. ---
	var peer PeerInfo
handshake:
	for {
		if err := ctx.Err(); err != nil {
			return PeerInfo{}, FileRequest{}, RequestParts{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return PeerInfo{}, FileRequest{}, RequestParts{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return PeerInfo{}, FileRequest{}, RequestParts{}, err
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
			return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_HELLO:
			h, err := DecodeHello(payload)
			if err != nil {
				return PeerInfo{}, FileRequest{}, RequestParts{}, err
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
				return PeerInfo{}, FileRequest{}, RequestParts{}, err
			}
			if _, err := conn.Write(frame.Marshal()); err != nil {
				return PeerInfo{}, FileRequest{}, RequestParts{}, err
			}
			break handshake
		default:
			return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: unexpected opcode 0x%02X", op)
		}
	}

	// --- File request: read OP_FILEREQUEST. ---
readRequest:
	for {
		if err := ctx.Err(); err != nil {
			return peer, fr, RequestParts{}, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return peer, fr, RequestParts{}, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return peer, fr, RequestParts{}, err
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
			return peer, fr, RequestParts{}, fmt.Errorf("ed2k: peer rejected connection")
		case OP_FILEREQUEST:
			decoded, err := DecodeFileRequest(payload)
			if err != nil {
				return peer, fr, RequestParts{}, err
			}
			fr = decoded
			reqHash := fr.hashBytes()

			found := hasAvailable && reqHash == availHash
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return peer, fr, RequestParts{}, err
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
					return peer, fr, RequestParts{}, err
				}
			} else {
				frame := Frame{
					Protocol: ProtocolEDonkey,
					Opcode:   OP_FILENOTFOUND,
					Payload:  FileNotFound{Hash: reqHash}.Marshal(),
				}
				if _, err := conn.Write(frame.Marshal()); err != nil {
					return peer, fr, RequestParts{}, err
				}
				return peer, fr, RequestParts{}, nil
			}
			break readRequest
		default:
			// Tolerate leading/unexpected frames.
			continue
		}
	}

	// --- Request parts: read OP_REQUESTPARTS. ---
	for {
		if err := ctx.Err(); err != nil {
			return peer, fr, rp, err
		}
		rl := dialDeadline(ctx)
		if err := conn.SetReadDeadline(rl); err != nil {
			return peer, fr, rp, err
		}
		f, err := readED2KFrame(conn)
		if err != nil {
			return peer, fr, rp, err
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
			return peer, fr, rp, fmt.Errorf("ed2k: peer rejected connection")
		case OP_QUEUEREQUEST:
			// Grant an upload slot so queue-aware download clients (DialDownload)
			// can proceed. Serving-side queue scheduling is otherwise out of
			// scope; this is the minimal grant needed for the in-process
			// exchange slice.
			qframe := Frame{
				Protocol: ProtocolEDonkey,
				Opcode:   OP_STARTUPLOAD,
				Payload:  StartUpload{}.Marshal(),
			}
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return peer, fr, rp, err
			}
			if _, err := conn.Write(qframe.Marshal()); err != nil {
				return peer, fr, rp, err
			}
			continue
		case OP_REQUESTPARTS:
			decoded, err := DecodeRequestParts(payload)
			if err != nil {
				return peer, fr, rp, err
			}
			rp = decoded
			reqHash := rp.hashBytes()

			// Hash mismatch refusal.
			if hasAvailable && availHash != ([16]byte{}) && reqHash != ([16]byte{}) && reqHash != availHash {
				frame := Frame{
					Protocol: ProtocolEDonkey,
					Opcode:   OP_FILENOTFOUND,
					Payload:  FileNotFound{Hash: reqHash}.Marshal(),
				}
				wl := dialDeadline(ctx)
				if err := conn.SetWriteDeadline(wl); err != nil {
					return peer, fr, rp, err
				}
				if _, err := conn.Write(frame.Marshal()); err != nil {
					return peer, fr, rp, err
				}
				return peer, fr, rp, nil
			}

			von := rp.vonArray()
			bis := rp.bisArray()

			h := availHash
			if h == ([16]byte{}) {
				h = reqHash
			}
			if h == ([16]byte{}) {
				h = fr.hashBytes()
			}

			v := von[0]
			b := bis[0]

			// End-of-data: nothing more to serve.
			if source != nil && int(v) >= len(source) {
				sp := SendingPart{
					Hash: h,
					Von:  v,
					Bis:  v,
					Data: nil,
				}
				sp.FileHash = h
				sp.MD4 = h
				frame := Frame{
					Protocol: ProtocolEDonkey,
					Opcode:   OP_SENDINGPART,
					Payload:  sp.Marshal(),
				}
				wl := dialDeadline(ctx)
				if err := conn.SetWriteDeadline(wl); err != nil {
					return peer, fr, rp, err
				}
				if _, err := conn.Write(frame.Marshal()); err != nil {
					return peer, fr, rp, err
				}
				drainConn(conn)
				return peer, fr, rp, nil
			}

			// Clamp the requested end to the available source length.
			if source != nil && int(b) > len(source) {
				b = uint32(len(source))
			}

			// Size/range refusal: out of bounds of supplied source.
			if source != nil {
				if int(v) > len(source) || v > b {
					frame := Frame{
						Protocol: ProtocolEDonkey,
						Opcode:   OP_FILENOTFOUND,
						Payload:  FileNotFound{Hash: reqHash}.Marshal(),
					}
					wl := dialDeadline(ctx)
					if err := conn.SetWriteDeadline(wl); err != nil {
						return peer, fr, rp, err
					}
					if _, err := conn.Write(frame.Marshal()); err != nil {
						return peer, fr, rp, err
					}
					return peer, fr, rp, nil
				}
			}

			var data []byte
			if source != nil {
				data = cloneBytes(source[v:b])
			}

			sp := SendingPart{
				Hash: h,
				Von:  v,
				Bis:  b,
				Data: data,
			}
			sp.FileHash = h
			sp.MD4 = h

			frame := Frame{
				Protocol: ProtocolEDonkey,
				Opcode:   OP_SENDINGPART,
				Payload:  sp.Marshal(),
			}
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return peer, fr, rp, err
			}
			if _, err := conn.Write(frame.Marshal()); err != nil {
				return peer, fr, rp, err
			}
			// Return when this chunk reached the end of the source; otherwise
			// keep serving subsequent requests on the same connection.
			if source == nil || int(b) >= len(source) {
				drainConn(conn)
				return peer, fr, rp, nil
			}
			continue
		default:
			// Tolerate leading/unexpected frames.
			continue
		}
	}
}


// drainConn waits briefly for the peer to finish reading the final frame
// before the server closes its end, avoiding a connection reset that would
// otherwise discard unread data in the kernel buffer.
func drainConn(conn net.Conn) {
	if conn == nil {
		return
	}
	conn.SetReadDeadline(time.Now().Add(50 * time.Millisecond))
	buf := make([]byte, 256)
	for {
		if _, err := conn.Read(buf); err != nil {
			return
		}
	}
}

// parseTransferAvailable extracts available file hash/name plus an optional
// source byte buffer from flexible args.
func parseTransferAvailable(args []any) ([16]byte, string, []byte, bool) {
	var hash [16]byte
	var name string
	var source []byte
	has := false
	hashSet := false
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
			hashSet = true
			has = true
		case []byte:
			if !hashSet && len(t) == 16 {
				var h [16]byte
				copy(h[:], t)
				hash = h
				hashSet = true
				has = true
			} else {
				// treat as source payload (or append?)
				if source == nil {
					source = cloneBytes(t)
					has = true
				} else {
					source = cloneBytes(t)
				}
			}
		case *[]byte:
			if t != nil {
				if !hashSet && len(*t) == 16 {
					var h [16]byte
					copy(h[:], *t)
					hash = h
					hashSet = true
					has = true
				} else {
					source = cloneBytes(*t)
					has = true
				}
			}
		case FileReqAnswer:
			h := t.hashBytes()
			if h != ([16]byte{}) {
				hash = h
				hashSet = true
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
					hashSet = true
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
				hashSet = true
			}
			has = true
		case *FileRequest:
			if t != nil {
				h := t.hashBytes()
				if h != ([16]byte{}) {
					hash = h
					hashSet = true
				}
				has = true
			}
		case FileNotFound:
			h := t.hashBytes()
			if h != ([16]byte{}) {
				hash = h
				hashSet = true
			}
			has = true
		case *FileNotFound:
			if t != nil {
				h := t.hashBytes()
				if h != ([16]byte{}) {
					hash = h
					hashSet = true
				}
				has = true
			}
		case RequestParts:
			h := t.hashBytes()
			if h != ([16]byte{}) {
				hash = h
				hashSet = true
			}
			has = true
		case *RequestParts:
			if t != nil {
				h := t.hashBytes()
				if h != ([16]byte{}) {
					hash = h
					hashSet = true
				}
				has = true
			}
		case SendingPart:
			h := t.hashBytes()
			if h != ([16]byte{}) {
				hash = h
				hashSet = true
			}
			if source == nil {
				if d := t.dataBytes(); d != nil {
					source = cloneBytes(d)
				}
			}
			has = true
		case *SendingPart:
			if t != nil {
				h := t.hashBytes()
				if h != ([16]byte{}) {
					hash = h
					hashSet = true
				}
				if source == nil {
					if d := t.dataBytes(); d != nil {
						source = cloneBytes(d)
					}
				}
				has = true
			}
		default:
			h := fileRequestHash(t)
			if h != ([16]byte{}) {
				hash = h
				hashSet = true
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
	if name == "" && hash == ([16]byte{}) && source == nil {
		// nothing
	}
	return hash, name, source, has
}

// ---- Engine method aliases ----

func (e *Engine) ServeTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) HandleTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) AcceptTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) ServeTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) HandleTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) AcceptTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

// lowercase method aliases
func (e *Engine) serveTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) handleTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) acceptTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConn(ctx, conn, args...)
}

func (e *Engine) serveTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	if c, ok := rw.(net.Conn); ok {
		return e.serveTransferConn(ctx, c, args...)
	}
	return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func (e *Engine) ServeTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveTransferConnIO(ctx, rw, args...)
}

func (e *Engine) HandleTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeTransferConnIO(ctx, rw, args...)
}

func (e *Engine) AcceptTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeTransferConnIO(ctx, rw, args...)
}

func (e *Engine) ServeTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeTransferConnIO(ctx, rw, args...)
}

func (e *Engine) HandleTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeTransferConnIO(ctx, rw, args...)
}

func (e *Engine) AcceptTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeTransferConnIO(ctx, rw, args...)
}

// ---- Package-level helpers ----

func serveTransferConnPkg(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
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
		return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: nil connection")
	}
	return eng.serveTransferConn(ctx, conn, rest...)
}

// lowercase package-level base
func serveTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func handleTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func acceptTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func serveTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func handleTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func acceptTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

// Uppercase package-level helpers
func ServeTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func HandleTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func AcceptTransferConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func ServeTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func HandleTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

func AcceptTransfer(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnPkg(ctx, conn, args...)
}

// IO variants (package-level)
func serveTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	if c, ok := rw.(net.Conn); ok {
		return serveTransferConnPkg(ctx, c, args...)
	}
	return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func ServeTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnIO(ctx, rw, args...)
}

func HandleTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnIO(ctx, rw, args...)
}

func AcceptTransferConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnIO(ctx, rw, args...)
}

func ServeTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnIO(ctx, rw, args...)
}

func HandleTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnIO(ctx, rw, args...)
}

func AcceptTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnIO(ctx, rw, args...)
}

// lowercase IO aliases
func serveTransferIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveTransferConnIO(ctx, rw, args...)
}

// Additional alternate spellings / aliases
func ServeTransferWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return ServeTransferConn(ctx, conn, args...)
}

func HandleTransferWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return HandleTransferConn(ctx, conn, args...)
}

func AcceptTransferWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return AcceptTransferConn(ctx, conn, args...)
}

func ServeTransferConnWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return ServeTransferConn(ctx, conn, args...)
}

func HandleTransferConnWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return HandleTransferConn(ctx, conn, args...)
}

func AcceptTransferConnWithConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return AcceptTransferConn(ctx, conn, args...)
}

// ensure time/io usage
var _ = time.Second
var _ = io.EOF