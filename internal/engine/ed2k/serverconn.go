// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

const (
	ed2kDialTimeout = 10 * time.Second
)

// readED2KFrame reads one frame from a live connection without requiring
// the sender to close or send trailing bytes.
func readED2KFrame(r io.Reader) (Frame, error) {
	hdr := make([]byte, 5)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return Frame{}, err
	}
	size := binary.LittleEndian.Uint32(hdr[1:5])
	if size < 1 {
		return Frame{}, ErrFrameBadSize
	}
	if size > MaxFrameSize {
		return Frame{}, ErrFrameTooLarge
	}
	rest := make([]byte, size)
	if _, err := io.ReadFull(r, rest); err != nil {
		return Frame{}, err
	}
	buf := make([]byte, 5+size)
	buf[0] = hdr[0]
	copy(buf[1:5], hdr[1:5])
	copy(buf[5:], rest)
	return DecodeFrame(buf)
}

func (e *Engine) dialServer(ctx context.Context, addr string) {
	defer e.wg.Done()

	logf := e.opts.Logf
	conn, err := net.DialTimeout("tcp", addr, ed2kDialTimeout)
	if err != nil {
		logf("dial %s failed: %v", addr, err)
		return
	}
	defer conn.Close()

	lr := LoginRequest{}
	frame := Frame{
		Protocol: ProtocolEDonkey,
		Opcode:   OP_LOGINREQUEST,
		Payload:  lr.Marshal(),
	}
	if _, err := conn.Write(frame.Marshal()); err != nil {
		logf("write login to %s: %v", addr, err)
		return
	}

	for {
		if ctx.Err() != nil {
			return
		}
		conn.SetReadDeadline(time.Now().Add(5 * time.Minute))
		f, err := readED2KFrame(conn)
		if err != nil {
			if ctx.Err() == nil {
				logf("read from %s: %v", addr, err)
			}
			return
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
		case OP_IDCHANGE:
			ic, err := DecodeIDChange(payload)
			if err != nil {
				logf("decode id change: %v", err)
				continue
			}
			e.mu.Lock()
			e.clientID = ic.NewID
			e.lowID = IsLowID(ic.NewID)
			e.tcpFlags = ic.TCPFlags
			if e.tcpFlags == 0 {
				e.tcpFlags = ic.Port
			}
			e.serverFlags = ic.ServerFlags
			e.clientIP = ic.ClientIP
			low := e.lowID
			e.mu.Unlock()

			if low {
				e.mu.Lock()
				e.gotServerList = true
				e.mu.Unlock()
				gf := Frame{
					Protocol: ProtocolEDonkey,
					Opcode:   OP_GETSERVERLIST,
					Payload:  []byte{},
				}
				if _, err := conn.Write(gf.Marshal()); err != nil {
					logf("write getserverlist to %s: %v", addr, err)
				}
			}

		case OP_SERVERLIST:
			sl, err := DecodeServerList(payload)
			if err != nil {
				logf("decode server list: %v", err)
				continue
			}
			e.mu.Lock()
			e.serverList = sl.Servers
			e.mu.Unlock()

		case OP_REJECT:
			e.mu.Lock()
			e.rejected = true
			e.mu.Unlock()
			logf("server %s rejected login", addr)
			return

		case OP_SERVERMESSAGE:
			sm, err := DecodeServerMessage(payload)
			if err != nil {
				logf("decode server message: %v", err)
				continue
			}
			msg := sm.Message
			if msg == "" {
				msg = sm.Text
			}
			e.mu.Lock()
			e.messages = append(e.messages, msg)
			e.mu.Unlock()

		default:
		}
	}
}

var _ = fmt.Sprintf
var _ = net.Dial
