// SPDX-License-Identifier: GPL-3.0-or-later

package rpc

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

func mustID(t *testing.T, s string) json.RawMessage {
	t.Helper()
	return json.RawMessage(s)
}

func decodeErr(t *testing.T, r *Response) *Error {
	t.Helper()
	if r == nil {
		t.Fatal("expected a response, got nil (notification)")
	}
	if r.Error == nil {
		t.Fatalf("expected error response, got result %s", r.Result)
	}
	return r.Error
}

func TestDispatchCallsHandler(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	var gotParams string
	d.Register("test.echo", func(_ context.Context, p json.RawMessage) (any, error) {
		gotParams = string(p)
		return "ok", nil
	})

	resp := d.Dispatch(context.Background(), &Request{
		JSONRPC: "2.0",
		Method:  "test.echo",
		Params:  json.RawMessage(`{"a":1}`),
		ID:      mustID(t, "1"),
	})

	if gotParams != `{"a":1}` {
		t.Errorf("handler got params %q, want %q", gotParams, `{"a":1}`)
	}
	if resp.Error != nil {
		t.Fatalf("unexpected error: %v", resp.Error)
	}
	if string(resp.Result) != `"ok"` {
		t.Errorf("result = %s, want \"ok\"", resp.Result)
	}
	if string(resp.ID) != "1" {
		t.Errorf("id = %s, want 1 (must echo the client's id verbatim)", resp.ID)
	}
}

func TestDispatchUnknownMethod(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.known", func(context.Context, json.RawMessage) (any, error) { return nil, nil })

	resp := d.Dispatch(context.Background(), &Request{
		JSONRPC: "2.0", Method: "test.unknown", ID: mustID(t, "7"),
	})

	if got := decodeErr(t, resp); got.Code != CodeMethodNotFound {
		t.Errorf("code = %d, want %d", got.Code, CodeMethodNotFound)
	}
}

func TestDispatchWrongVersion(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	for _, v := range []string{"", "1.0", "2", "2.0.0", "two"} {
		resp := d.Dispatch(context.Background(), &Request{
			JSONRPC: v, Method: "test.any", ID: mustID(t, "1"),
		})
		if got := decodeErr(t, resp); got.Code != CodeInvalidRequest {
			t.Errorf("jsonrpc=%q: code = %d, want %d", v, got.Code, CodeInvalidRequest)
		}
	}
}

func TestDispatchNotificationsGetNoResponse(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.ok", func(context.Context, json.RawMessage) (any, error) { return 1, nil })
	d.Register("test.fail", func(context.Context, json.RawMessage) (any, error) {
		return nil, Errorf(CodeInternal, "boom")
	})

	for _, m := range []string{"test.ok", "test.fail", "test.unknown"} {
		resp := d.Dispatch(context.Background(), &Request{JSONRPC: "2.0", Method: m})
		if resp != nil {
			t.Errorf("%s: got response %+v, want nil for a notification", m, resp)
		}
	}
}

func TestDispatchNotificationWithExplicitNullID(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.ok", func(context.Context, json.RawMessage) (any, error) { return 1, nil })

	// An absent id is a notification and gets nothing back.
	resp := d.Dispatch(context.Background(), &Request{JSONRPC: "2.0", Method: "test.ok"})
	if resp != nil {
		t.Errorf("absent id: got response %+v, want nil", resp)
	}

	// An explicit null id is discouraged by the spec and is rejected,
	// rather than being silently treated either way.
	resp = d.Dispatch(context.Background(), &Request{
		JSONRPC: "2.0", Method: "test.ok", ID: json.RawMessage("null"),
	})
	if got := decodeErr(t, resp); got.Code != CodeInvalidRequest {
		t.Errorf("null id: code = %d, want %d", got.Code, CodeInvalidRequest)
	}
}

func TestDispatchPreservesHandlerErrorCode(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.precond", func(context.Context, json.RawMessage) (any, error) {
		return nil, Errorf(CodeFailedPrecond, "not yet")
	})

	resp := d.Dispatch(context.Background(), &Request{
		JSONRPC: "2.0", Method: "test.precond", ID: mustID(t, "1"),
	})
	if got := decodeErr(t, resp); got.Code != CodeFailedPrecond || got.Message != "not yet" {
		t.Errorf("got %+v, want code %d message %q", got, CodeFailedPrecond, "not yet")
	}
}

func TestDispatchWrapsPlainErrorAsInternal(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.plain", func(context.Context, json.RawMessage) (any, error) {
		return nil, errors.New("plain failure")
	})

	resp := d.Dispatch(context.Background(), &Request{
		JSONRPC: "2.0", Method: "test.plain", ID: mustID(t, "1"),
	})
	if got := decodeErr(t, resp); got.Code != CodeInternal {
		t.Errorf("code = %d, want %d", got.Code, CodeInternal)
	}
}

func TestDispatchUnencodableResultIsInternalError(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.bad", func(context.Context, json.RawMessage) (any, error) {
		return map[string]any{"chan": make(chan int)}, nil
	})

	resp := d.Dispatch(context.Background(), &Request{
		JSONRPC: "2.0", Method: "test.bad", ID: mustID(t, "1"),
	})
	// The client must be told, not left guessing whether the call worked.
	if got := decodeErr(t, resp); got.Code != CodeInternal {
		t.Errorf("code = %d, want %d", got.Code, CodeInternal)
	}
}

func TestDispatchErrorEchoesClientID(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.precond", func(context.Context, json.RawMessage) (any, error) {
		return nil, Errorf(CodeFailedPrecond, "not yet")
	})

	// Both a numeric and a string id must come back byte-identical: the
	// spec allows either, and re-encoding a string id as a number breaks
	// strict clients.
	for _, id := range []string{"1", "\"abc-1\"", "0"} {
		resp := d.Dispatch(context.Background(), &Request{
			JSONRPC: "2.0", Method: "test.precond", ID: mustID(t, id),
		})
		if string(resp.ID) != id {
			t.Errorf("id = %s, want %s echoed verbatim", resp.ID, id)
		}
	}
}

func TestRegisterPanicsOnDuplicate(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	d.Register("test.dup", func(context.Context, json.RawMessage) (any, error) { return nil, nil })

	defer func() {
		if recover() == nil {
			t.Error("expected panic on duplicate method registration")
		}
	}()
	d.Register("test.dup", func(context.Context, json.RawMessage) (any, error) { return nil, nil })
}

func TestMethodsIsSorted(t *testing.T) {
	t.Parallel()
	d := NewDispatcher()
	for _, m := range []string{"z.a", "m.b", "a.c"} {
		d.Register(m, func(context.Context, json.RawMessage) (any, error) { return nil, nil })
	}

	got := d.Methods()
	want := []string{"a.c", "m.b", "z.a"}
	if len(got) != len(want) {
		t.Fatalf("Methods() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Methods() = %v, want %v", got, want)
		}
	}
}
