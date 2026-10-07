// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"testing"
)

func TestHeaderRoundTrip(t *testing.T) {
	h := Header{
		ID:     [16]byte{0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0xFF, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x00},
		Type:   MsgPing,
		TTL:    7,
		Hops:   0,
		Length: 0,
	}
	buf := h.AppendTo(nil)
	if len(buf) != HeaderSize {
		t.Fatalf("encoded length = %d, want %d", len(buf), HeaderSize)
	}

	got, err := DecodeHeader(bytes.NewReader(buf))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if got.ID != h.ID || got.Type != h.Type || got.TTL != h.TTL || got.Hops != h.Hops || got.Length != h.Length {
		t.Errorf("round trip mismatch: got %+v want %+v", got, h)
	}
}

func TestHeaderMultipleFields(t *testing.T) {
	want := Header{Type: MsgPong, TTL: 3, Hops: 1, Length: 14}
	b := want.Marshal()
	got, err := DecodeHeader(bytes.NewReader(b[:]))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if got != want {
		t.Errorf("DecodeHeader(Marshal(h)) = %+v, want %+v", got, want)
	}
}

// The length is little-endian on the wire: 0x00001234 is written 34 12
// 00 00, and a big-endian reader would misread it as 0x34120000.
func TestHeaderLengthIsLittleEndian(t *testing.T) {
	buf := [HeaderSize]byte{}
	binary.LittleEndian.PutUint32(buf[19:23], 0x1234)
	h, err := DecodeHeader(bytes.NewReader(buf[:]))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if h.Length != 0x1234 {
		t.Errorf("length = %d, want %d (little-endian decode)", h.Length, 0x1234)
	}
	if big := binary.BigEndian.Uint32(buf[19:23]); big == h.Length {
		t.Error("length bytes are byte-order-ambiguous; this test proves nothing")
	}
}

func TestDecodeHeaderTruncated(t *testing.T) {
	for _, n := range []int{0, 1, 22} {
		_, err := DecodeHeader(bytes.NewReader(make([]byte, n)))
		if err == nil {
			t.Errorf("DecodeHeader(%d bytes) = nil error, want failure", n)
		}
	}
}

func TestDecodeHeaderOversizedRejected(t *testing.T) {
	h := Header{Type: MsgPing, Length: MaxPayloadSize + 1}
	b := h.Marshal()
	_, err := DecodeHeader(bytes.NewReader(b[:]))
	if !errors.Is(err, ErrPayloadTooLarge) {
		t.Fatalf("oversized length error = %v, want ErrPayloadTooLarge", err)
	}
}

func TestDecodeHeaderMaxSizeAccepted(t *testing.T) {
	h := Header{Type: MsgPing, Length: MaxPayloadSize}
	b := h.Marshal()
	if _, err := DecodeHeader(bytes.NewReader(b[:])); err != nil {
		t.Fatalf("max-size length rejected: %v", err)
	}
}

func TestDecodeHeaderAtEOF(t *testing.T) {
	buf := Header{Type: MsgPing, Length: 4}.Marshal()
	r := io.LimitReader(bytes.NewReader(buf[:]), 20)
	if _, err := DecodeHeader(r); err != io.ErrUnexpectedEOF {
		t.Errorf("truncated wait error = %v, want io.ErrUnexpectedEOF", err)
	}
}

func TestHeaderPayloadRoundTrip(t *testing.T) {
	payload := []byte{1, 2, 3, 4, 5}
	h := Header{Type: MsgQuery, TTL: 5, Length: uint32(len(payload))}
	wire := h.AppendTo(nil)
	wire = append(wire, payload...)
	got, err := DecodeHeader(bytes.NewReader(wire))
	if err != nil {
		t.Fatalf("DecodeHeader: %v", err)
	}
	if got.Length != uint32(len(payload)) {
		t.Errorf("length = %d, want %d", got.Length, len(payload))
	}
}

func TestDescriptorIDTags(t *testing.T) {
	seen := map[[16]byte]bool{}
	for i := 0; i < 100; i++ {
		id := newDescriptorID()
		if id[8] != 0xFF {
			t.Errorf("id[8] = %#x, want 0xFF (multicast-capable tag)", id[8])
		}
		if id[15] != 0x00 {
			t.Errorf("id[15] = %#x, want 0x00 (reserved byte)", id[15])
		}
		if seen[id] {
			t.Fatalf("duplicate descriptor ID generated")
		}
		seen[id] = true
	}
}

func FuzzDecodeHeader(f *testing.F) {
	seed := Header{ID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 0xFF, 9, 0, 1, 2, 3, 4, 0}, Type: MsgPing, TTL: 7, Length: 3}
	sb := seed.Marshal()
	f.Add(append([]byte(nil), sb[:]...))
	f.Add([]byte{})
	f.Add(bytes.Repeat([]byte{0xFF}, 23))
	f.Add(bytes.Repeat([]byte{0x00}, 23))

	f.Fuzz(func(t *testing.T, data []byte) {
		// Feeding garbage must either produce a valid (bounded)
		// header or an error, never a panic or a huge allocation.
		_, _ = DecodeHeader(bytes.NewReader(data))
	})
}
