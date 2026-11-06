// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
)

func TestEncodeDecodePartialRoundTrip4Byte(t *testing.T) {
	p := Partial{Complete: 0x12345678}
	enc := EncodePartial(p)
	if len(enc) != 4 {
		t.Fatalf("encoded length: got %d want 4", len(enc))
	}
	dec, err := DecodePartial(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec != p {
		t.Errorf("mismatch: got %+v want %+v", dec, p)
	}
	// boundary: max 32-bit value uses the 4-byte form.
	p2 := Partial{Complete: 0xFFFFFFFF}
	enc2 := EncodePartial(p2)
	if len(enc2) != 4 {
		t.Fatalf("boundary encoded length: got %d want 4", len(enc2))
	}
	dec2, err := DecodePartial(enc2)
	if err != nil {
		t.Fatalf("boundary decode failed: %v", err)
	}
	if dec2 != p2 {
		t.Errorf("boundary mismatch: got %+v want %+v", dec2, p2)
	}
}

func TestEncodeDecodePartialRoundTrip8Byte(t *testing.T) {
	p := Partial{Complete: 0x0102030405060708}
	enc := EncodePartial(p)
	if len(enc) != 8 {
		t.Fatalf("encoded length: got %d want 8", len(enc))
	}
	dec, err := DecodePartial(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec != p {
		t.Errorf("mismatch: got %+v want %+v", dec, p)
	}
	// value just above 32 bits forces the 8-byte form.
	p2 := Partial{Complete: 0x100000000}
	enc2 := EncodePartial(p2)
	if len(enc2) != 8 {
		t.Fatalf("overflow encoded length: got %d want 8", len(enc2))
	}
	dec2, err := DecodePartial(enc2)
	if err != nil {
		t.Fatalf("overflow decode failed: %v", err)
	}
	if dec2 != p2 {
		t.Errorf("overflow mismatch: got %+v want %+v", dec2, p2)
	}
}

func TestDecodePartialMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"too short 1", []byte{0x01}},
		{"too short 3", []byte{0x01, 0x02, 0x03}},
		{"wrong length 5", []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
		{"wrong length 6", make([]byte, 6)},
		{"wrong length 7", make([]byte, 7)},
		{"wrong length 9", make([]byte, 9)},
	}
	for _, c := range cases {
		if _, err := DecodePartial(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func FuzzPartialRoundTrip(f *testing.F) {
	f.Add(EncodePartial(Partial{Complete: 0}))
	f.Add(EncodePartial(Partial{Complete: 42}))
	f.Add(EncodePartial(Partial{Complete: 0xFFFFFFFF}))
	f.Add(EncodePartial(Partial{Complete: 0x0102030405060708}))

	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodePartial(b)
		if err != nil {
			return
		}
		enc := EncodePartial(got)
		got2, err2 := DecodePartial(enc)
		if err2 != nil {
			t.Fatalf("re-decode failed: %v", err2)
		}
		if got != got2 {
			t.Errorf("round-trip mismatch: %+v vs %+v", got, got2)
		}
	})
}