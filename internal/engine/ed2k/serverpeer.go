// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"fmt"
	"io"
	"net"
)

// servePeerConn is the server-side (incoming) C2C Hello handshake: read the
// peer's OP_HELLO, reply with OP_HELLOANSWER carrying our identity, and
// return the peer's identity.
func (e *Engine) servePeerConn(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	if conn == nil {
		return PeerInfo{}, fmt.Errorf("ed2k: nil connection")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if e == nil {
		e = New()
	}

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
		case OP_HELLO:
			h, err := DecodeHello(payload)
			if err != nil {
				return PeerInfo{}, err
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

			ha := e.buildPeerHelloAnswer()
			frame := Frame{
				Protocol: ProtocolEDonkey,
				Opcode:   OP_HELLOANSWER,
				Payload:  ha.Marshal(),
			}
			wl := dialDeadline(ctx)
			if err := conn.SetWriteDeadline(wl); err != nil {
				return PeerInfo{}, err
			}
			if _, err := conn.Write(frame.Marshal()); err != nil {
				return PeerInfo{}, err
			}
			return info, nil
		default:
			return PeerInfo{}, fmt.Errorf("ed2k: unexpected opcode 0x%02X", op)
		}
	}
}

func (e *Engine) buildPeerHelloAnswer() HelloAnswer {
	hash := e.peerUserHash()
	var serverIP [4]byte
	if a := e.Addr(); a != nil {
		if ta, ok := a.(*net.TCPAddr); ok && ta.IP != nil {
			if ip := ta.IP.To4(); ip != nil {
				copy(serverIP[:], ip)
			}
		}
	}
	tags := cloneTags(e.peerTags())
	return HelloAnswer{
		Hash:       hash,
		GUID:       hash,
		UserHash:   hash,
		ClientID:   e.peerClientID(),
		ID:         e.peerClientID(),
		Port:       e.peerListenPort(),
		Tags:       tags,
		TagList:    cloneTags(tags),
		TagSet:     cloneTags(tags),
		ServerIP:   serverIP,
		ServerPort: e.peerListenPort(),
	}
}

func (e *Engine) ServePeerConn(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.servePeerConn(ctx, conn)
}

func (e *Engine) HandlePeerConn(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.servePeerConn(ctx, conn)
}

func (e *Engine) AcceptPeerConn(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.servePeerConn(ctx, conn)
}

func (e *Engine) ServePeer(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.servePeerConn(ctx, conn)
}

func (e *Engine) HandlePeer(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.servePeerConn(ctx, conn)
}

func (e *Engine) AcceptPeer(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.servePeerConn(ctx, conn)
}

func servePeerConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
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
	return eng.servePeerConn(ctx, conn)
}

func ServePeerConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func HandlePeerConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func AcceptPeerConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func ServePeer(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func HandlePeer(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func AcceptPeer(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func servePeer(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func handlePeerConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func acceptPeerConn(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func handlePeer(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func acceptPeer(ctx context.Context, conn net.Conn, e ...*Engine) (PeerInfo, error) {
	return servePeerConn(ctx, conn, e...)
}

func servePeerConnIO(ctx context.Context, rw io.ReadWriter, e ...*Engine) (PeerInfo, error) {
	if c, ok := rw.(net.Conn); ok {
		return servePeerConn(ctx, c, e...)
	}
	return PeerInfo{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func ServePeerConnIO(ctx context.Context, rw io.ReadWriter, e ...*Engine) (PeerInfo, error) {
	return servePeerConnIO(ctx, rw, e...)
}

func HandlePeerConnIO(ctx context.Context, rw io.ReadWriter, e ...*Engine) (PeerInfo, error) {
	return servePeerConnIO(ctx, rw, e...)
}

func AcceptPeerConnIO(ctx context.Context, rw io.ReadWriter, e ...*Engine) (PeerInfo, error) {
	return servePeerConnIO(ctx, rw, e...)
}

func (e *Engine) ServePeerConnIO(ctx context.Context, rw io.ReadWriter) (PeerInfo, error) {
	if c, ok := rw.(net.Conn); ok {
		return e.servePeerConn(ctx, c)
	}
	return PeerInfo{}, fmt.Errorf("ed2k: ReadWriter is not a net.Conn")
}

func (e *Engine) HandlePeerConnIO(ctx context.Context, rw io.ReadWriter) (PeerInfo, error) {
	return e.ServePeerConnIO(ctx, rw)
}

func (e *Engine) AcceptPeerConnIO(ctx context.Context, rw io.ReadWriter) (PeerInfo, error) {
	return e.ServePeerConnIO(ctx, rw)
}

func (e *Engine) servePeer(ctx context.Context, conn net.Conn) (PeerInfo, error) {
	return e.servePeerConn(ctx, conn)
}
