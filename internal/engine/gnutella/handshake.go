// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Gnutella 0.6 TCP handshake (RFC draft section 2.1).
//
// Only the "full" 0.6 handshake is implemented: the connecting client
// sends "GNUTELLA CONNECT/0.6" plus headers, the server replies
// "GNUTELLA/0.6 200 OK" plus headers, the client replies with its own
// "GNUTELLA/0.6 200 OK", and only then do binary messages flow. The
// legacy 0.4 prompt bytes ("GNUTELLA\n\n") are not supported; a Gnutella
// 0.4-only peer sends them and is refused by the first line parse.
//
// Header names are case-insensitive and treated as RFC 822 fields with
// continuation lines, so the parse shares nothing with the binary
// framing used after the handshake.

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// MaxHandshake caps a handshake block. Heads are a few hundred bytes;
// 8 KiB lets a verbose vendor header set through while bounding memory.
const MaxHandshake = 8 << 10

// Field is one handshake header line. Names keep their original case;
// lookups are case-insensitive.
type Field struct {
	Name  string
	Value string
}

// Handshake is one parsed block: either a CONNECT request or a status
// response, followed by headers. For a request, Code and Reason are
// zero; for a response, Request is false and Version holds the
// negotiated protocol version.
type Handshake struct {
	Request bool
	Version string
	Code    int
	Reason  string
	Fields  []Field
}

// Status renders the status line for logs.
func (h Handshake) Status() string {
	if h.Request {
		return "CONNECT/" + h.Version
	}
	return fmt.Sprintf("%d %s", h.Code, h.Reason)
}

// IsOK reports whether a response is "GNUTELLA/x.y 200 OK".
func (h Handshake) IsOK() bool {
	return !h.Request && h.Code == 200
}

// Get returns the first value for a case-insensitive header name, and
// whether any value was present. Multiple headers with the same name
// are joined with commas, RFC 822 style.
func (h Handshake) Get(name string) (string, bool) {
	want := strings.ToLower(strings.TrimSpace(name))
	var values []string
	for _, f := range h.Fields {
		if strings.EqualFold(f.Name, want) {
			values = append(values, strings.TrimSpace(f.Value))
		}
	}
	if len(values) == 0 {
		return "", false
	}
	return strings.Join(values, ","), true
}

// UserAgent returns the peer's User-Agent header, if any.
func (h Handshake) UserAgent() string {
	v, _ := h.Get("User-Agent")
	return v
}

// RemoteIP returns the Remote-IP header, if any.
func (h Handshake) RemoteIP() string {
	v, _ := h.Get("Remote-IP")
	return v
}

// Network returns the X-Gnutella-Network header, if any. The header
// appears in neither RFC but is common in the wild, and the task brief
// calls for it, so it is surfaced here for completeness.
func (h Handshake) Network() string {
	v, _ := h.Get("X-Gnutella-Network")
	return v
}

// ContentEncoding returns the Content-Encoding header, if any. In the
// 0.6 handshake this declares how the message stream that follows the
// handshake is encoded (see wantsInflate in inflate.go).
func (h Handshake) ContentEncoding() string {
	v, _ := h.Get("Content-Encoding")
	return v
}

// ReadHandshake reads one handshake block from r, up to and including
// the CRLF CRLF terminator, and parses it. It never reads past the
// terminator: extra buffered bytes stay in r for the message reader to
// consume. A block without a terminator, or longer than MaxHandshake,
// is an error.
func ReadHandshake(r io.Reader) (Handshake, error) {
	// One byte at a time. A handshake is at most 8 KiB and happens once
	// per connection, so this is cheap, and it is the only way to read
	// an unbounded delimited block from an arbitrary reader without
	// swallowing bytes that follow the terminator. In the live path r
	// is a bufio.Reader over the connection, so each byte costs a
	// buffer refill, not a syscall.
	var buf []byte
	one := make([]byte, 1)
	for {
		if _, err := io.ReadFull(r, one); err != nil {
			return Handshake{}, fmt.Errorf("handshake not terminated: %w", err)
		}
		buf = append(buf, one[0])
		if bytes.HasSuffix(buf, []byte("\r\n\r\n")) {
			return ParseHandshake(buf)
		}
		if len(buf) > MaxHandshake {
			return Handshake{}, fmt.Errorf("handshake longer than %d bytes", MaxHandshake)
		}
	}
}

// ParseHandshake parses a handshake block that must end with CRLF CRLF.
func ParseHandshake(b []byte) (Handshake, error) {
	if len(b) > MaxHandshake {
		return Handshake{}, fmt.Errorf("handshake %d bytes exceeds cap %d", len(b), MaxHandshake)
	}
	if !bytes.HasSuffix(b, []byte("\r\n\r\n")) {
		return Handshake{}, errors.New("handshake not terminated with CRLF CRLF")
	}
	block := strings.TrimSuffix(string(b), "\r\n\r\n")
	lines := strings.Split(block, "\r\n")
	if len(lines) == 0 || lines[0] == "" {
		return Handshake{}, errors.New("empty handshake")
	}
	var hs Handshake
	if err := hs.parseStatusLine(lines[0]); err != nil {
		return Handshake{}, err
	}
	hs.Fields = parseFieldLines(lines[1:])
	return hs, nil
}

func (h *Handshake) parseStatusLine(line string) error {
	parts := strings.Fields(line)
	switch {
	case len(parts) == 2 && parts[0] == "GNUTELLA" && strings.HasPrefix(parts[1], "CONNECT/"):
		h.Request = true
		h.Version = strings.TrimPrefix(line, "GNUTELLA CONNECT/")
	case len(parts) >= 2 && strings.HasPrefix(parts[0], "GNUTELLA/"):
		h.Version = strings.TrimPrefix(parts[0], "GNUTELLA/")
		if !validVersion(h.Version) {
			return fmt.Errorf("bad protocol version %q", h.Version)
		}
		code, err := strconv.Atoi(parts[1])
		if err != nil || code < 100 || code > 599 {
			return fmt.Errorf("bad status code %q in %q", parts[1], line)
		}
		h.Code = code
		h.Reason = strings.Join(parts[2:], " ")
	default:
		return fmt.Errorf("not a Gnutella handshake status line: %q", line)
	}
	return nil
}

// validVersion accepts the "major.minor" shapes the wire uses.
func validVersion(v string) bool {
	_, _, ok := parseVersion(v)
	return ok
}

// parseVersion splits "0.6" into (0, 6, true).
func parseVersion(v string) (major, minor int, ok bool) {
	a, b, found := strings.Cut(v, ".")
	if !found {
		return 0, 0, false
	}
	x, err1 := strconv.Atoi(a)
	y, err2 := strconv.Atoi(b)
	if err1 != nil || err2 != nil || x < 0 || y < 0 {
		return 0, 0, false
	}
	return x, y, true
}

// supportsVersion reports whether our 0.6 implementation can talk to a
// peer on that version. Higher versions are accepted (the spec says
// they must not be refused by the lower version side); anything below
// 0.6 means a 0.4-style wire that we do not implement.
func supportsVersion(v string) bool {
	major, minor, ok := parseVersion(v)
	return ok && (major > 0 || major == 0 && minor >= 6)
}

// parseFieldLines folds RFC 822 continuation lines and splits headers.
// A header line without a colon is kept with an empty name: it is
// invisible to Get and harmless, and rejecting the handshake for it
// would be pointlessly strict.
func parseFieldLines(lines []string) []Field {
	var fields []Field
	var current []string
	flush := func() {
		if len(current) > 0 {
			name, value, _ := strings.Cut(current[0], ":")
			value = strings.TrimSpace(value)
			for _, cont := range current[1:] {
				value += " " + strings.TrimSpace(cont)
			}
			fields = append(fields, Field{Name: strings.TrimSpace(name), Value: value})
			current = nil
		}
	}
	for _, l := range lines {
		switch {
		case l == "":
			continue
		case l[0] == ' ' || l[0] == '\t':
			current = append(current, l)
		default:
			flush()
			current = []string{l}
		}
	}
	flush()
	return fields
}

// ConnectRequest builds a client handshake block: a CONNECT/0.6 status
// line, the given headers, and the CRLF CRLF terminator.
func ConnectRequest(fields ...Field) []byte {
	return appendHead("GNUTELLA CONNECT/0.6\r\n", fields...)
}

// OKReply builds a "GNUTELLA/0.6 200 OK" handshake block.
func OKReply(fields ...Field) []byte {
	return appendHead("GNUTELLA/0.6 200 OK\r\n", fields...)
}

// ErrorReply builds a refusal handshake block, e.g. ErrorReply(503,
// "Busy"). The peer reads it instead of a 200 and knows the connection
// is refused.
func ErrorReply(code int, reason string) []byte {
	return []byte(fmt.Sprintf("GNUTELLA/0.6 %d %s\r\n\r\n", code, reason))
}

func appendHead(status string, fields ...Field) []byte {
	b := []byte(status)
	for _, f := range fields {
		b = append(b, f.Name...)
		b = append(b, ": "...)
		b = append(b, f.Value...)
		b = append(b, "\r\n"...)
	}
	return append(b, "\r\n"...)
}
