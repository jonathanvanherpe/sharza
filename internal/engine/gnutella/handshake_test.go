// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"strings"
	"testing"
)

func TestParseConnectRequest(t *testing.T) {
	hs, err := ParseHandshake([]byte("GNUTELLA CONNECT/0.6\r\nUser-Agent: LimeWire/6.0\r\nX-Gnutella-Network: G1,G2\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if !hs.Request {
		t.Error("Request = false, want true for a CONNECT")
	}
	if hs.Version != "0.6" {
		t.Errorf("Version = %q, want 0.6", hs.Version)
	}
	if got, _ := hs.Get("User-Agent"); got != "LimeWire/6.0" {
		t.Errorf("User-Agent = %q, want LimeWire/6.0", got)
	}
	if got, _ := hs.Get("x-gnutella-network"); got != "G1,G2" {
		t.Errorf("network = %q, want G1,G2 (case-insensitive lookup)", got)
	}
	if got := hs.UserAgent(); got != "LimeWire/6.0" {
		t.Errorf("UserAgent() = %q", got)
	}
	if got := hs.Network(); got != "G1,G2" {
		t.Errorf("Network() = %q, want G1,G2", got)
	}
}

func TestParseOKReply(t *testing.T) {
	hs, err := ParseHandshake([]byte("GNUTELLA/0.6 200 OK\r\nListen-IP: 10.0.0.1:6346\r\nRemote-IP: 10.0.0.2\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if hs.Request {
		t.Error("Request = true, want false for a response")
	}
	if !hs.IsOK() {
		t.Errorf("IsOK() = false, want true (status %s)", hs.Status())
	}
	if hs.Code != 200 || hs.Reason != "OK" {
		t.Errorf("code/reason = %d %q, want 200 OK", hs.Code, hs.Reason)
	}
	if got := hs.RemoteIP(); got != "10.0.0.2" {
		t.Errorf("RemoteIP() = %q", got)
	}
}

func TestParseErrorReply(t *testing.T) {
	hs, err := ParseHandshake([]byte("GNUTELLA/0.6 503 Busy\r\n\r\n"))
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if hs.IsOK() {
		t.Error("503 parsed as OK")
	}
	if got := hs.Status(); got != "503 Busy" {
		t.Errorf("Status() = %q, want 503 Busy", got)
	}
}

func TestParseHandshakeErrors(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"no terminator", "GNUTELLA CONNECT/0.6\r\n"},
		{"garbage", "hello world\r\n\r\n"},
		{"not gnutella", "HTTP/1.1 200 OK\r\n\r\n"},
		{"prompt only", "\n\n"},
		{"bad code", "GNUTELLA/0.6 banana OK\r\n\r\n"},
		{"bad code range", "GNUTELLA/0.6 99 Nope\r\n\r\n"},
		{"no version", "GNUTELLA 200 OK\r\n\r\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := ParseHandshake([]byte(tc.in)); err == nil {
				t.Errorf("ParseHandshake(%q) succeeded, want error", tc.in)
			}
		})
	}
}

func TestParseHandshakeTooTall(t *testing.T) {
	in := "GNUTELLA CONNECT/0.6\r\n" + strings.Repeat("X: y\r\n", MaxHandshake) + "\r\n"
	if _, err := ParseHandshake([]byte(in)); err == nil {
		t.Error("oversized handshake accepted")
	}
}

func TestHandshakeContinuationLines(t *testing.T) {
	in := "GNUTELLA/0.6 200 OK\r\nUser-Agent: Sharza/\r\n  0.0.0-dev\r\n\r\n"
	hs, err := ParseHandshake([]byte(in))
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if got := hs.UserAgent(); got != "Sharza/ 0.0.0-dev" {
		t.Errorf("UserAgent = %q, want folded continuation value", got)
	}
}

func TestHandshakeIgnoresMalformedHeaderLines(t *testing.T) {
	in := "GNUTELLA CONNECT/0.6\r\nThisIsNotAHeader\r\nUser-Agent: ok\r\n\r\n"
	hs, err := ParseHandshake([]byte(in))
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if hs.UserAgent() != "ok" {
		t.Errorf("UserAgent = %q, want ok", hs.UserAgent())
	}
}

func TestSupportsVersion(t *testing.T) {
	for _, v := range []string{"0.6", "0.7", "1.0", "0.10"} {
		if !supportsVersion(v) {
			t.Errorf("supportsVersion(%q) = false, want true", v)
		}
	}
	for _, v := range []string{"0.4", "0.5", "", "0", "1", "0.6.1", "x.y", "-1.6"} {
		if supportsVersion(v) {
			t.Errorf("supportsVersion(%q) = true, want false", v)
		}
	}
}

func TestConnectRequestRoundTrip(t *testing.T) {
	b := ConnectRequest(Field{"User-Agent", "test/1.0"})
	hs, err := ParseHandshake(b)
	if err != nil {
		t.Fatalf("ParseHandshake: %v", err)
	}
	if !hs.Request || hs.Version != "0.6" {
		t.Errorf("parsed request = request:%v version:%q", hs.Request, hs.Version)
	}
	if got := hs.UserAgent(); got != "test/1.0" {
		t.Errorf("UserAgent = %q", got)
	}
}

func TestOKAndErrorReplyBuilders(t *testing.T) {
	ok, err := ParseHandshake(OKReply(Field{"User-Agent", "x"}))
	if err != nil || !ok.IsOK() {
		t.Errorf("OKReply round trip: %+v, %v", ok, err)
	}
	errHs, err := ParseHandshake(ErrorReply(503, "Busy"))
	if err != nil || errHs.IsOK() || errHs.Code != 503 {
		t.Errorf("ErrorReply round trip: %+v, %v", errHs, err)
	}
	if got := errHs.Reason; got != "Busy" {
		t.Errorf("reason = %q, want Busy", got)
	}
}

func TestReadHandshakeStopsAtTerminator(t *testing.T) {
	// Everything after the terminator must stay available to the caller.
	r := strings.NewReader("GNUTELLA CONNECT/0.6\r\n\r\nBB") // binary bytes follow
	hs, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("ReadHandshake: %v", err)
	}
	if !hs.Request {
		t.Error("not a request")
	}
	var rest [2]byte
	if n, _ := r.Read(rest[:]); n != 2 || string(rest[:]) != "BB" {
		t.Errorf("trailing bytes lost: n=%d rest=%q", n, rest)
	}
}

func FuzzHandshake(f *testing.F) {
	f.Add([]byte("GNUTELLA CONNECT/0.6\r\nUser-Agent: x\r\n\r\n"))
	f.Add([]byte("GNUTELLA/0.6 200 OK\r\n\r\n"))
	f.Add([]byte(""))
	f.Add([]byte("\r\n\r\n"))
	f.Add([]byte("GNUTELLA/0.6 503 Busy\r\nX: y\r\n\r\n"))

	f.Fuzz(func(t *testing.T, data []byte) {
		hs, err := ParseHandshake(data)
		if err != nil {
			return
		}
		// Whatever parsed must be internally consistent: a request is
		// never OK, an OK response has code 200.
		if hs.Request && hs.IsOK() {
			t.Fatal("parsed handshake is both a request and 200 OK")
		}
		if !hs.Request && hs.Code == 200 && !hs.IsOK() {
			t.Fatal("parsed handshake has code 200 but IsOK() is false")
		}
	})
}
