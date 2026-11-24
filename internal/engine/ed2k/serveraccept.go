// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
	"time"
)

// serveAcceptConn is the server-side (incoming) accept/dispatch flow: read
// the peer's OP_HELLO and reply with OP_HELLOANSWER carrying our identity;
// then dispatch OP_FILEREQUEST to the file-request handling logic and
// OP_REQUESTPARTS to the transfer handling logic, granting OP_QUEUEREQUEST
// with OP_STARTUPLOAD. It returns the peer identity, the decoded (last)
// FileRequest, the decoded (last) RequestParts, and any error.
func (e *Engine) serveAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	if conn == nil {
		return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

	// Opt-in protocol obfuscation: wrap the accepted connection before the
	// OP_HELLO handshake when requested via Options. Defaults to off.
	obfuscated := false
	e.mu.Lock()
	obfuscated = e.opts.Obfuscation || e.opts.Obfuscated
	e.mu.Unlock()
	if obfuscated {
		wrapped, err := ObfuscateConn(conn, nil)
		if err != nil {
			return PeerInfo{}, FileRequest{}, RequestParts{}, err
		}
		conn = wrapped
	}

	availHash, availName, source, hasAvailable := parseTransferAvailable(args)

	var peer PeerInfo
	var fr FileRequest
	var rp RequestParts

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
			if err == io.EOF {
				return peer, fr, rp, nil
			}
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

		case OP_HELLO:
			h, err := DecodeHello(payload)
			if err != nil {
				return peer, fr, rp, err
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

			ha := e.buildPeerHelloAnswer()
			frame := Frame{
				Protocol: ProtocolEDonkey,
				Opcode:   OP_HELLOANSWER,
				Payload:  ha.Marshal(),
			}
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return peer, fr, rp, err
			}
			if _, err := conn.Write(frame.Marshal()); err != nil {
				return peer, fr, rp, err
			}

		case OP_FILEREQUEST:
			decoded, err := DecodeFileRequest(payload)
			if err != nil {
				return peer, fr, rp, err
			}
			fr = decoded
			reqHash := fr.hashBytes()

			found := hasAvailable && reqHash == availHash
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return peer, fr, rp, err
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
					return peer, fr, rp, err
				}
			} else {
				frame := Frame{
					Protocol: ProtocolEDonkey,
					Opcode:   OP_FILENOTFOUND,
					Payload:  FileNotFound{Hash: reqHash}.Marshal(),
				}
				if _, err := conn.Write(frame.Marshal()); err != nil {
					return peer, fr, rp, err
				}
				return peer, fr, rp, nil
			}

		case OP_QUEUEREQUEST:
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

		case OP_REQUESTPARTS:
			decoded, err := DecodeRequestParts(payload)
			if err != nil {
				return peer, fr, rp, err
			}
			rp = decoded
			reqHash := rp.hashBytes()

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

			// End-of-data.
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
				return peer, fr, rp, nil
			}

			if source != nil && int(b) > len(source) {
				b = uint32(len(source))
			}

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
			if source == nil || int(b) >= len(source) {
				return peer, fr, rp, nil
			}
			// else continue serving

		default:
			// tolerate leading/unexpected frames
		}
	}
}

// ---- Engine method aliases ----
func (e *Engine) ServeAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) HandleAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) AcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) ServeAccept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) HandleAccept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) Accept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) serveAccept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) handleAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) acceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConn(ctx, conn, args...)
}
func (e *Engine) serveAcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	if c, ok := rw.(net.Conn); ok {
		return e.serveAcceptConn(ctx, c, args...)
	}
	return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}
func (e *Engine) ServeAcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.serveAcceptConnIO(ctx, rw, args...)
}
func (e *Engine) HandleAcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeAcceptConnIO(ctx, rw, args...)
}
func (e *Engine) AcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeAcceptConnIO(ctx, rw, args...)
}
func (e *Engine) ServeAcceptIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeAcceptConnIO(ctx, rw, args...)
}
func (e *Engine) HandleAcceptIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeAcceptConnIO(ctx, rw, args...)
}
func (e *Engine) AcceptIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return e.ServeAcceptConnIO(ctx, rw, args...)
}

// ---- Package-level helpers ----
func serveAcceptConnPkg(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
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
	return eng.serveAcceptConn(ctx, conn, rest...)
}

func serveAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func handleAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func acceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func serveAccept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func handleAccept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func accept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}

func ServeAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func HandleAcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func AcceptConn(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func ServeAccept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func HandleAccept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}
func Accept(ctx context.Context, conn net.Conn, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnPkg(ctx, conn, args...)
}

// IO variants (package-level)
func serveAcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	if c, ok := rw.(net.Conn); ok {
		return serveAcceptConnPkg(ctx, c, args...)
	}
	return PeerInfo{}, FileRequest{}, RequestParts{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}
func ServeAcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnIO(ctx, rw, args...)
}
func HandleAcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnIO(ctx, rw, args...)
}
func AcceptConnIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnIO(ctx, rw, args...)
}
func ServeAcceptIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnIO(ctx, rw, args...)
}
func HandleAcceptIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnIO(ctx, rw, args...)
}
func AcceptIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnIO(ctx, rw, args...)
}

// lowercase IO aliases
func serveAcceptIO(ctx context.Context, rw io.ReadWriter, args ...any) (PeerInfo, FileRequest, RequestParts, error) {
	return serveAcceptConnIO(ctx, rw, args...)
}

// ensure time/io usage
var _ = time.Second
var _ = io.EOF