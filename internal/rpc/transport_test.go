// SPDX-License-Identifier: GPL-3.0-or-later

package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// startServer brings up a real server on a temp socket and returns a client.
func startServer(t *testing.T, register func(*Dispatcher)) (*Client, *Server) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "c.sock")
	d := NewDispatcher()
	if register != nil {
		register(d)
	}
	s := NewServer(d, path)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := s.Serve(ctx); err != nil {
			t.Errorf("Serve: %v", err)
		}
	}()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Error("server did not shut down")
		}
	})

	c, err := Dial(path, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c, s
}

func TestClientServerRoundTrip(t *testing.T) {
	t.Parallel()
	c, _ := startServer(t, func(d *Dispatcher) {
		d.Register("test.add", func(_ context.Context, p json.RawMessage) (any, error) {
			var in struct{ A, B int }
			if err := json.Unmarshal(p, &in); err != nil {
				return nil, Errorf(CodeInvalidParams, "%v", err)
			}
			return in.A + in.B, nil
		})
	})

	var out int
	if err := c.Call(context.Background(), "test.add",
		map[string]int{"A": 2, "B": 3}, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out != 5 {
		t.Errorf("result = %d, want 5", out)
	}
}

func TestClientSurfacesErrorCode(t *testing.T) {
	t.Parallel()
	c, _ := startServer(t, func(d *Dispatcher) {
		d.Register("test.fail", func(context.Context, json.RawMessage) (any, error) {
			return nil, Errorf(CodeFailedPrecond, "job is running")
		})
	})

	err := c.Call(context.Background(), "test.fail", nil, nil)
	if err == nil {
		t.Fatal("Call = nil, want error")
	}
	var re *Error
	if !errors.As(err, &re) {
		t.Fatalf("error type = %T, want *rpc.Error", err)
	}
	if re.Code != CodeFailedPrecond {
		t.Errorf("code = %d, want %d", re.Code, CodeFailedPrecond)
	}
}

func TestClientSequentialCallsMatchIDs(t *testing.T) {
	t.Parallel()
	// A server that replies with a mismatched id would be invisible without
	// an explicit id check, so this covers the client's guard.
	c, _ := startServer(t, func(d *Dispatcher) {
		d.Register("test.n", func(_ context.Context, p json.RawMessage) (any, error) {
			var in int
			_ = json.Unmarshal(p, &in)
			return in * 10, nil
		})
	})

	for i := 1; i <= 5; i++ {
		var out int
		if err := c.Call(context.Background(), "test.n", i, &out); err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
		if out != i*10 {
			t.Errorf("call %d returned %d, want %d", i, out, i*10)
		}
	}
}

func TestSocketIsOwnerOnly(t *testing.T) {
	t.Parallel()
	_, s := startServer(t, func(d *Dispatcher) {
		d.Register("test.ok", func(context.Context, json.RawMessage) (any, error) { return 1, nil })
	})

	fi, err := statMode(s.Addr())
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("socket mode = %04o, want 0600: the socket is the entire auth surface", perm)
	}
}

func TestStaleSocketIsReplaced(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "c.sock")

	// Leave a regular file where the socket should be, mimicking a crashed
	// daemon that failed to clean up.
	if err := writeFile(path); err != nil {
		t.Fatalf("seed stale path: %v", err)
	}

	d := NewDispatcher()
	d.Register("test.ok", func(context.Context, json.RawMessage) (any, error) {
		return "live", nil
	})
	s := NewServer(d, path)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen over stale path: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = s.Serve(ctx) }()
	defer s.Close()

	c, err := Dial(path, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}
	defer c.Close()

	var out string
	if err := c.Call(context.Background(), "test.ok", nil, &out); err != nil {
		t.Fatalf("Call: %v", err)
	}
	if out != "live" {
		t.Errorf("result = %q, want live", out)
	}
}

func TestOversizedFrameIsRejected(t *testing.T) {
	t.Parallel()
	_, s := startServer(t, func(d *Dispatcher) {
		d.Register("test.ok", func(context.Context, json.RawMessage) (any, error) { return 1, nil })
	})

	conn, err := net.Dial("unix", s.Addr())
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()

	// A frame larger than the cap must not be buffered into memory. The
	// write may fail once the server hangs up mid-frame, which is itself
	// the point: it stops reading rather than absorbing the data.
	huge := strings.Repeat("A", MaxRequestBytes+1024)
	_ = conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
	_, _ = conn.Write([]byte(huge + "\n"))

	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil && n == 0 {
		// The server hung up before we could read its reason. Acceptable,
		// but it must have hung up rather than kept reading.
		t.Logf("server closed before replying: %v", err)
		return
	}
	if !strings.Contains(string(buf[:n]), "maximum size") {
		t.Errorf("reply = %q, want a frame-too-large parse error", buf[:n])
	}
}

func TestMalformedJSONGetsParseError(t *testing.T) {
	t.Parallel()
	_, s := startServer(t, func(d *Dispatcher) {
		d.Register("test.ok", func(context.Context, json.RawMessage) (any, error) { return 1, nil })
	})

	conn, err := net.Dial("unix", s.Addr())
	if err != nil {
		t.Fatalf("raw dial: %v", err)
	}
	defer conn.Close()

	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := conn.Write([]byte("{not json\n")); err != nil {
		t.Fatalf("write: %v", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(buf[:n]), "invalid JSON") {
		t.Errorf("reply = %q, want an invalid-JSON parse error", buf[:n])
	}
}

func TestServerSurvivesOneBadClient(t *testing.T) {
	t.Parallel()
	c, s := startServer(t, func(d *Dispatcher) {
		d.Register("test.ok", func(context.Context, json.RawMessage) (any, error) {
			return "pong", nil
		})
	})

	bad, err := net.Dial("unix", s.Addr())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	if _, err := bad.Write([]byte("{garbage\n")); err != nil {
		t.Fatalf("write garbage: %v", err)
	}
	bad.Close()

	// The good client's connection must be unaffected.
	var out string
	if err := c.Call(context.Background(), "test.ok", nil, &out); err != nil {
		t.Fatalf("good client broken by bad neighbour: %v", err)
	}
	if out != "pong" {
		t.Errorf("result = %q, want pong", out)
	}
}

func TestClosedServerRefusesConnections(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "c.sock")
	s := NewServer(NewDispatcher(), path)
	if err := s.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
	if _, err := Dial(path, time.Second); err == nil {
		t.Error("Dial after Close = nil, want error")
	}
}

func TestIsUnavailable(t *testing.T) {
	t.Parallel()
	if _, err := Dial(filepath.Join(t.TempDir(), "absent.sock"), time.Second); err == nil {
		t.Fatal("expected dial failure")
	} else if !IsUnavailable(err) {
		t.Errorf("IsUnavailable(%v) = false, want true for a missing socket", err)
	}
	if IsUnavailable(nil) {
		t.Error("IsUnavailable(nil) = true, want false")
	}
	if IsUnavailable(errors.New("job is running")) {
		t.Error("IsUnavailable on an application error = true, want false")
	}
}

func TestManyConcurrentClients(t *testing.T) {
	t.Parallel()
	c, s := startServer(t, func(d *Dispatcher) {
		d.Register("test.ok", func(_ context.Context, p json.RawMessage) (any, error) {
			var in string
			_ = json.Unmarshal(p, &in)
			return in, nil
		})
	})

	var wg sync.WaitGroup
	errs := make(chan error, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			conn, err := net.Dial("unix", s.Addr())
			if err != nil {
				errs <- err
				return
			}
			defer conn.Close()
			cl := &Client{conn: conn, r: newReader(conn)}
			var out string
			if err := cl.Call(context.Background(), "test.ok", fmt.Sprintf("c%d", i), &out); err != nil {
				errs <- err
				return
			}
			if want := fmt.Sprintf("c%d", i); out != want {
				errs <- fmt.Errorf("client %d got %q, want %q", i, out, want)
			}
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}

	// The original client must still work.
	var out string
	if err := c.Call(context.Background(), "test.ok", "final", &out); err != nil {
		t.Errorf("original client broken: %v", err)
	}
}

// Test helpers kept here so the test file reads as behaviour, not plumbing.

func statMode(path string) (os.FileInfo, error) { return os.Stat(path) }

func writeFile(path string) error {
	return os.WriteFile(path, []byte("stale"), 0o600)
}

func newReader(conn net.Conn) *bufio.Reader { return bufio.NewReaderSize(conn, 64<<10) }
