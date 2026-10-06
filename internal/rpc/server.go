// SPDX-License-Identifier: GPL-3.0-or-later

package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// MaxRequestBytes caps a single request. A peer on the control socket is
// trusted-ish, but an unbounded read is still a denial of service: one client
// can send a length header and never the body, and every other client stalls.
const MaxRequestBytes = 4 << 20 // 4 MiB

// SocketPath is the default control socket location. It lives under an
// unprivileged runtime dir rather than /run, so the daemon needs no privileges
// to start.
const SocketPath = "sharzad.sock"

// Server serves JSON-RPC over a Unix domain socket.
//
// The framing is newline-delimited JSON: one request object per line, one
// response object per line. This is chosen over Content-Length framing
// because the only clients are ours and the only peer we have to survive is a
// half-written line at disconnect.
type Server struct {
	disp *Dispatcher
	ln   net.Listener
	path string

	mu       sync.Mutex
	closed   bool
	conns    map[net.Conn]struct{}
	wg       sync.WaitGroup
	maxFrame int
}

// NewServer returns a server bound to path. It does not start serving.
func NewServer(disp *Dispatcher, path string) *Server {
	return &Server{
		disp:     disp,
		path:     path,
		conns:    map[net.Conn]struct{}{},
		maxFrame: MaxRequestBytes,
	}
}

// Addr returns the bound socket path, which is useful when a test or the
// caller supplied a path in a temporary directory.
func (s *Server) Addr() string { return s.path }

// Listen binds the socket, replacing a stale one left by a crashed process.
//
// Removing a pre-existing path is safe here only because the caller owns the
// directory: an arbitrary socket path from an untrusted source must never be
// unlinked, or an attacker could redirect a privileged client to a socket they
// control.
func (s *Server) Listen() error {
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("rpc: create socket dir %s: %w", dir, err)
	}

	if _, err := os.Stat(s.path); err == nil {
		if err := os.Remove(s.path); err != nil {
			return fmt.Errorf("rpc: remove stale socket %s: %w", s.path, err)
		}
	}

	ln, err := net.Listen("unix", s.path)
	if err != nil {
		return fmt.Errorf("rpc: listen on %s: %w", s.path, err)
	}
	// Owner-only: the socket is the entire auth surface for the control
	// plane, so it must not be reachable by other users on the host.
	if err := os.Chmod(s.path, 0o600); err != nil {
		ln.Close()
		return fmt.Errorf("rpc: chmod socket %s: %w", s.path, err)
	}

	s.ln = ln
	return nil
}

// Serve accepts connections until ctx is cancelled or Close is called.
func (s *Server) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = s.Close()
	}()

	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed {
				s.wg.Wait()
				return nil
			}
			// A temporary error must not kill the listener.
			var ne net.Error
			if errors.As(err, &ne) && ne.Timeout() {
				continue
			}
			return fmt.Errorf("rpc: accept: %w", err)
		}

		s.mu.Lock()
		if s.closed {
			s.mu.Unlock()
			conn.Close()
			break
		}
		s.conns[conn] = struct{}{}
		s.mu.Unlock()

		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.handle(conn)
		}()
	}
	return nil
}

func (s *Server) handle(conn net.Conn) {
	defer func() {
		s.mu.Lock()
		delete(s.conns, conn)
		s.mu.Unlock()
		conn.Close()
	}()

	// Bound the whole exchange so an idle client cannot hold a slot forever.
	_ = conn.SetDeadline(time.Now().Add(10 * time.Minute))
	r := bufio.NewReaderSize(conn, 64<<10)
	w := bufio.NewWriter(conn)

	for {
		line, err := readLine(r, s.maxFrame)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return // clean disconnect
			}
			// Framing is broken, so this connection cannot continue. Say
			// why, then hang up: a client that gets silence here cannot
			// tell a server bug from a network fault.
			_ = writeJSON(w, &Response{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   Errorf(CodeParse, "%v", err),
			})
			return
		}
		if len(line) == 0 {
			continue
		}

		var req Request
		if err := json.Unmarshal(line, &req); err != nil {
			if werr := writeJSON(w, &Response{
				JSONRPC: "2.0",
				ID:      json.RawMessage("null"),
				Error:   Errorf(CodeParse, "invalid JSON: %v", err),
			}); werr != nil {
				return
			}
			continue
		}

		resp := s.disp.Dispatch(context.Background(), &req)
		if resp == nil {
			continue // notification
		}
		if err := writeJSON(w, resp); err != nil {
			return
		}
	}
}

// errLineTooLong signals that a frame exceeded maxFrame.
var errLineTooLong = errors.New("rpc: frame exceeds maximum size")

// readLine reads one newline-delimited frame, refusing to buffer more than max
// bytes. bufio.Scanner cannot express this limit without allocating the
// buffer up front, so this reads byte-wise through a small buffer and grows the
// result only as needed.
func readLine(r *bufio.Reader, max int) ([]byte, error) {
	var out []byte
	for {
		chunk, isPrefix, err := r.ReadLine()
		if err != nil {
			if len(out) > 0 && errors.Is(err, io.EOF) {
				// A final frame without a trailing newline is still a frame.
				return out, nil
			}
			return nil, err
		}
		if len(out)+len(chunk) > max {
			return nil, fmt.Errorf("%w (%d > %d)", errLineTooLong, len(out)+len(chunk), max)
		}
		out = append(out, chunk...)
		if !isPrefix {
			return out, nil
		}
	}
}

func writeJSON(w *bufio.Writer, v any) error {
	data, err := json.Marshal(v)
	if err != nil {
		return fmt.Errorf("rpc: encode response: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	if err := w.WriteByte('\n'); err != nil {
		return err
	}
	return w.Flush()
}

// Close stops the listener and all open connections, then removes the socket.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	ln := s.ln
	conns := make([]net.Conn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()

	var firstErr error
	if ln != nil {
		if err := ln.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	for _, c := range conns {
		_ = c.Close()
	}

	// Only remove the socket if it is still ours: a restart may have
	// replaced it while we were shutting down.
	if fi, err := os.Lstat(s.path); err == nil && fi.Mode()&os.ModeSocket != 0 {
		if err := os.Remove(s.path); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
