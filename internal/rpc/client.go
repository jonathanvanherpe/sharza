// SPDX-License-Identifier: GPL-3.0-or-later

package rpc

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"time"
)

// Client speaks JSON-RPC over a Unix domain socket.
//
// Requests are request/response with an incrementing id. Batch requests are
// not supported: Sharza's control plane has few enough methods that batching
// buys nothing and would complicate error attribution.
type Client struct {
	conn net.Conn
	r    *bufio.Reader
	next atomic.Uint64
}

// Dial connects to a control socket.
func Dial(path string, timeout time.Duration) (*Client, error) {
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	conn, err := net.DialTimeout("unix", path, timeout)
	if err != nil {
		return nil, fmt.Errorf("rpc: dial %s: %w", path, err)
	}
	return &Client{conn: conn, r: bufio.NewReaderSize(conn, 64<<10)}, nil
}

// Close closes the connection.
func (c *Client) Close() error { return c.conn.Close() }

// Call issues a request and waits for its response.
func (c *Client) Call(ctx context.Context, method string, params any, out any) error {
	var raw json.RawMessage
	if params != nil {
		encoded, err := json.Marshal(params)
		if err != nil {
			return fmt.Errorf("rpc: encode params for %s: %w", method, err)
		}
		raw = encoded
	}

	id := c.next.Add(1)
	req := Request{JSONRPC: "2.0", Method: method, ID: json.RawMessage(fmt.Sprintf("%d", id))}
	if len(raw) > 0 {
		req.Params = raw
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("rpc: encode request %s: %w", method, err)
	}
	if deadline, ok := ctx.Deadline(); ok {
		_ = c.conn.SetDeadline(deadline)
		defer c.conn.SetDeadline(time.Time{})
	}

	if _, err := c.conn.Write(append(body, '\n')); err != nil {
		return fmt.Errorf("rpc: send %s: %w", method, err)
	}

	// Responses come back in order for a single-connection client, but we
	// still verify the id rather than trusting the server: a mismatch here
	// would silently return another call's result.
	for {
		line, err := readLine(c.r, MaxRequestBytes)
		if err != nil {
			return fmt.Errorf("rpc: read reply to %s: %w", method, err)
		}
		if len(line) == 0 {
			continue
		}

		var resp Response
		if err := json.Unmarshal(line, &resp); err != nil {
			return fmt.Errorf("rpc: decode reply to %s: %w", method, err)
		}

		var gotID uint64
		if err := json.Unmarshal(resp.ID, &gotID); err != nil {
			return fmt.Errorf("rpc: reply to %s has non-numeric id %s", method, resp.ID)
		}
		if gotID != id {
			return fmt.Errorf("rpc: reply id %d does not match request id %d for %s",
				gotID, id, method)
		}

		if resp.Error != nil {
			return resp.Error
		}
		if out == nil {
			return nil
		}
		if err := json.Unmarshal(resp.Result, out); err != nil {
			return fmt.Errorf("rpc: decode result of %s: %w", method, err)
		}
		return nil
	}
}

// ErrUnavailable is returned when the daemon is not reachable. Callers use it
// to distinguish "not running" from "refused my command", which is the
// difference between a retry and an error message.
var ErrUnavailable = errors.New("daemon unavailable")

// IsUnavailable reports whether err means the daemon could not be reached.
func IsUnavailable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, ErrUnavailable) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	// A refused or missing socket surfaces as an opaque net.OpError.
	msg := err.Error()
	return strings.Contains(msg, "connection refused") ||
		strings.Contains(msg, "no such file or directory") ||
		strings.Contains(msg, "socket is closed")
}
