// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Optional compression of a peer's message stream, negotiated by the
// 0.6 handshake's encoding headers.
//
// The live 2026 Gnutella ultrapeers are gtk-gnutella 1.3.1 nodes, and
// they refuse an uncompressed leaf link ("403 Gnet connection not
// compressed") unless the CONNECT request carried Accept-Encoding:
// deflate; once it does, they compress their TX with a zlib-wrapped
// stream (RFC 1950, one context for the connection, installed at
// handshake completion) and expect us to decode it. We advertise the
// offer and inflate what comes back. Our own TX stays uncompressed:
// the offer says what we can read, not what we will write.
//
// "deflate" is ambiguous the way HTTP left it: a peer may send the
// zlib wrapper or a bare RFC 1951 stream, so the first two bytes of
// the stream pick the framing. The sniff peek reads through one
// persistent bufio reader, which keeps bytes past a stream's end
// available: a peer that re-wraps every message gets its next header
// sniffed the same way, rather than the connection ending at the first
// stream.

import (
	"bufio"
	"compress/flate"
	"compress/zlib"
	"fmt"
	"io"
	"strings"
)

// wantsInflate reports whether a handshake block tells us the message
// stream that follows it is deflate-compressed. The value is read
// HTTP-style: a comma-separated token list, matched case-insensitively,
// and only the tokens we advertised are honoured.
func wantsInflate(hs Handshake) bool {
	v := hs.ContentEncoding()
	if v == "" {
		return false
	}
	for _, tok := range strings.Split(v, ",") {
		if strings.EqualFold(strings.TrimSpace(tok), "deflate") {
			return true
		}
	}
	return false
}

// inflateReader turns a peer's compressed message stream into the bytes
// the message loop reads. It wraps the same reader the handshake used,
// through one bufio reader of its own, so bytes the handshake buffered
// past its terminator come through the decoder in order, and nothing is
// read until the first Read call -- which the message loop makes under
// its IdleTimeout deadline.
type inflateReader struct {
	br   *bufio.Reader
	comp io.ReadCloser // armed decompressor, nil before the first Read
}

// newInflateReader wraps r with a decoder for its deflate stream.
func newInflateReader(r io.Reader) *inflateReader {
	return &inflateReader{br: bufio.NewReader(r)}
}

// Read returns the decompressed stream.
func (i *inflateReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		if i.comp == nil {
			if err := i.start(); err != nil {
				return 0, err
			}
		}
		n, err := i.comp.Read(p)
		if n > 0 {
			// Report the data immediately even when this read also
			// hit the end of a stream: callers such as io.ReadAll
			// stop at the first (n>0, io.EOF) and would strand any
			// stream that follows. The restart, or the real end, is
			// the next call's business.
			return n, nil
		}
		if err == io.EOF {
			// End of a stream at a byte boundary. One stream per
			// connection is the norm (what gtk-gnutella installs),
			// in which case the peer has gone quiet or closed; a
			// peer that re-wraps every message simply has the next
			// header waiting.
			_ = i.comp.Close()
			i.comp = nil
			continue
		}
		if err != nil {
			return 0, fmt.Errorf("gnutella: compressed stream: %w", err)
		}
		// A zero-length read with no error is legal, if unusual: pass
		// it through rather than spinning.
		return 0, nil
	}
}

// start sniffs the framing of the next stream and arms the decoder.
// The peek does not consume, and the decoder is handed the same bufio
// reader the peek used, so neither the sniffed bytes nor anything the
// decoder buffered past its stream are lost when it ends.
func (i *inflateReader) start() error {
	head, err := i.br.Peek(2)
	if err != nil {
		return err
	}
	if isZlibHeader([2]byte{head[0], head[1]}) {
		zr, err := zlib.NewReader(i.br)
		if err != nil {
			return fmt.Errorf("gnutella: inflate: %w", err)
		}
		i.comp = zr
		return nil
	}
	// Not a zlib wrapper: a peer that said deflate and does not send
	// RFC 1950 is sending the bare RFC 1951 stream.
	i.comp = flate.NewReader(i.br)
	return nil
}

// Close releases the decompressor. The underlying reader belongs to
// the connection, which the caller closes.
func (i *inflateReader) Close() error {
	if i.comp != nil {
		return i.comp.Close()
	}
	return nil
}

// isZlibHeader reports whether b starts a zlib-wrapped stream: RFC 1950
// fixes the method at 8 in the low nibble of CMF, caps the window at
// 32 KiB (CINFO <= 7) in the high nibble, and requires the two-byte
// CMF/FLG value to be a multiple of 31. That is the check zlib itself
// uses to tell its wrapper from a bare RFC 1951 stream, whose first
// byte carries block flags instead.
func isZlibHeader(b [2]byte) bool {
	if b[0]&0x0f != 8 || b[0]>>4 > 7 {
		return false
	}
	return (uint16(b[0])<<8|uint16(b[1]))%31 == 0
}
