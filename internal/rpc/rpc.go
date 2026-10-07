// SPDX-License-Identifier: GPL-3.0-or-later

// Package rpc implements the control-plane contract between the supervisor
// and its clients.
//
// Two transports share one dispatcher:
//
//   - Unix domain socket, JSON-RPC 2.0, request/response. Request-response
//     because clients need to know whether a command took effect.
//   - Unix domain socket, WebSocket. One direction only: server to client
//     events. A client that wants to change state must use JSON-RPC, so that
//     every mutation is a request with an explicit result.
//
// The split is deliberate. A command whose success is unknown is the hardest
// class of bug in a distributed client, so state changes are never fire and
// forget.
package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

// JSON-RPC 2.0 error codes, plus the implementation-defined server range
// (-32000 to -32099) that Sharza uses for its own failures.
const (
	CodeParse          = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternal       = -32603

	CodeUnauthorized  = -32000
	CodeUnavailable   = -32001
	CodeFailedPrecond = -32002
)

// Request is an incoming JSON-RPC 2.0 request. ID is kept as raw JSON because
// the spec permits a string, a number or null, and echoing back something the
// client did not send is a protocol violation.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
	ID      json.RawMessage `json:"id,omitempty"`
}

// IsNotification reports whether the request expects no response. Only a
// completely absent id makes a notification. An explicit "id": null is not a
// notification: the spec defines a Notification as a Request without an id
// member, and it explicitly discourages null as an id.
func (r *Request) IsNotification() bool {
	return len(r.ID) == 0
}

// HasNullID reports an explicitly null id, which the spec discourages. It is
// rejected rather than silently treated as a notification, because answering
// a call the client may have expected to be silent corrupts its state
// tracking, and staying silent to a call it expected answered hangs it.
func (r *Request) HasNullID() bool {
	return string(r.ID) == "null"
}

// Response is an outgoing JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *Error          `json:"error,omitempty"`
	ID      json.RawMessage `json:"id"`
}

// Error is a JSON-RPC 2.0 error object.
type Error struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

func (e *Error) Error() string { return fmt.Sprintf("rpc error %d: %s", e.Code, e.Message) }

// Errorf builds an *Error.
func Errorf(code int, format string, args ...any) *Error {
	return &Error{Code: code, Message: fmt.Sprintf(format, args...)}
}

// Handler is a single method implementation.
type Handler func(ctx context.Context, params json.RawMessage) (any, error)

// Method names implemented by the supervisor. These are the RPC surface:
// adding or renaming one is a human gate, because clients depend on it.
const (
	MethodStatus     = "sharza.status"
	MethodRoles      = "sharza.roles"
	MethodJobsList   = "sharza.jobs.list"
	MethodJobsAdd    = "sharza.jobs.add"
	MethodJobsPause  = "sharza.jobs.pause"
	MethodJobsResume = "sharza.jobs.resume"
	MethodJobsRemove = "sharza.jobs.remove"

	// MethodRolesPause and MethodRolesResume toggle a worker role on and
	// off. MethodLogsTail returns the supervisor's recent log lines for the
	// web UI to tail.
	MethodRolesPause  = "sharza.roles.pause"
	MethodRolesResume = "sharza.roles.resume"
	MethodLogsTail    = "sharza.logs.tail"
)

// Dispatcher routes methods to handlers.
type Dispatcher struct {
	handlers map[string]Handler
}

// NewDispatcher returns an empty dispatcher.
func NewDispatcher() *Dispatcher {
	return &Dispatcher{handlers: make(map[string]Handler)}
}

// Register adds a handler. It panics on a duplicate method: that is a
// programming error at startup, not a runtime condition to recover from.
func (d *Dispatcher) Register(method string, h Handler) {
	if _, dup := d.handlers[method]; dup {
		panic("rpc: duplicate method registration: " + method)
	}
	d.handlers[method] = h
}

// Methods lists registered method names, sorted, for advertisement.
func (d *Dispatcher) Methods() []string {
	out := make([]string, 0, len(d.handlers))
	for m := range d.handlers {
		out = append(out, m)
	}
	sortStrings(out)
	return out
}

// Dispatch handles a single decoded request and returns the response to send.
// It returns nil for a notification.
func (d *Dispatcher) Dispatch(ctx context.Context, req *Request) *Response {
	// Per JSON-RPC 2.0, a request with no id is a notification and must
	// never be answered, not even with an error. This check comes first
	// because "unknown method" is itself an error, and returning one for a
	// notification would make every client fire-and-forget probe into a
	// half-duplex mess.
	if req.IsNotification() {
		return nil
	}

	if req.JSONRPC != "2.0" {
		// A wrong version means the client is speaking a protocol we do
		// not implement; answering would only encourage it.
		return errResponse(req.ID, Errorf(CodeInvalidRequest,
			"jsonrpc must be exactly \"2.0\", got %q", req.JSONRPC))
	}

	if req.HasNullID() {
		return errResponse(req.ID, Errorf(CodeInvalidRequest,
			"\"id\": null is discouraged by JSON-RPC 2.0; omit the id entirely for a notification"))
	}

	h, ok := d.handlers[req.Method]
	if !ok {
		return errResponse(req.ID, Errorf(CodeMethodNotFound,
			"unknown method %q", req.Method))
	}

	result, err := h(ctx, req.Params)
	if err != nil {
		return errResponse(req.ID, toRPCError(err))
	}

	encoded, mErr := json.Marshal(result)
	if mErr != nil {
		// A result that cannot be encoded is a bug in the handler, and
		// the client is left with an unknown outcome.
		return errResponse(req.ID, Errorf(CodeInternal,
			"could not encode result: %v", mErr))
	}

	return &Response{JSONRPC: "2.0", Result: encoded, ID: req.ID}
}

func errResponse(id json.RawMessage, e *Error) *Response {
	if len(id) == 0 {
		id = json.RawMessage("null")
	}
	return &Response{JSONRPC: "2.0", Error: e, ID: id}
}

// toRPCError maps a Go error onto a JSON-RPC error, defaulting to
// CodeInternal. Handlers should return an *Error directly to control the code.
func toRPCError(err error) *Error {
	var re *Error
	if errors.As(err, &re) {
		return re
	}
	return Errorf(CodeInternal, "%v", err)
}
