// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"reflect"
	"testing"
)

func TestEncodeDecodeQHTResetRoundTrip(t *testing.T) {
	r := QHTReset{Slots: 0x12345678, InfVal: 42}
	enc := EncodeQHTReset(r)
	if len(enc) != 6 {
		t.Fatalf("encoded length: got %d want 6", len(enc))
	}
	if enc[0] != QHTResetType {
		t.Fatalf("type byte: got %d", enc[0])
	}
	dec, err := DecodeQHTReset(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec != r {
		t.Errorf("mismatch: got %+v want %+v", dec, r)
	}
	w := EncodeQHT(r)
	if len(w) == 0 {
		t.Fatal("empty G2 encode")
	}
	got, err := DecodeQHT(w)
	if err != nil {
		t.Fatalf("G2 decode failed: %v", err)
	}
	rr, ok := got.(QHTReset)
	if !ok {
		t.Fatalf("expected QHTReset, got %T", got)
	}
	if rr != r {
		t.Errorf("G2 mismatch: got %+v want %+v", rr, r)
	}
}

func TestEncodeDecodeQHTPatchRoundTrip(t *testing.T) {
	p := QHTPatch{SeqNo: 7, SeqSize: 9, Compressed: true, Bits: 4, Data: []byte{0xDE, 0xAD, 0xBE, 0xEF}}
	enc := EncodeQHTPatch(p)
	if len(enc) != 5+len(p.Data) {
		t.Fatalf("encoded length: got %d", len(enc))
	}
	if enc[0] != QHTPatchType {
		t.Fatalf("type byte: got %d", enc[0])
	}
	dec, err := DecodeQHTPatch(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.SeqNo != p.SeqNo || dec.SeqSize != p.SeqSize || dec.Compressed != p.Compressed || dec.Bits != p.Bits {
		t.Errorf("header mismatch: got %+v want %+v", dec, p)
	}
	if !bytes.Equal(dec.Data, p.Data) {
		t.Errorf("data mismatch: % x vs % x", dec.Data, p.Data)
	}
	p2 := QHTPatch{SeqNo: 0, SeqSize: 1, Compressed: false, Bits: 1, Data: nil}
	enc2 := EncodeQHTPatch(p2)
	dec2, err := DecodeQHTPatch(enc2)
	if err != nil {
		t.Fatalf("decode2 failed: %v", err)
	}
	if dec2.Compressed {
		t.Error("expected uncompressed")
	}
	if len(dec2.Data) != 0 {
		t.Errorf("expected empty data, got %d", len(dec2.Data))
	}
	w := EncodeQHT(p)
	got, err := DecodeQHT(w)
	if err != nil {
		t.Fatalf("G2 decode failed: %v", err)
	}
	pp, ok := got.(QHTPatch)
	if !ok {
		t.Fatalf("expected QHTPatch, got %T", got)
	}
	if pp.SeqNo != p.SeqNo || !bytes.Equal(pp.Data, p.Data) {
		t.Errorf("G2 mismatch")
	}
}

func TestDecodeQHTResetMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"short 1", []byte{QHTResetType}},
		{"short 5", []byte{QHTResetType, 1, 2, 3, 4}},
		{"wrong type", []byte{QHTPatchType, 1, 2, 3, 4, 5}},
		{"bad slots zero", []byte{QHTResetType, 0, 0, 0, 0, 1}},
		{"trailing", []byte{QHTResetType, 1, 2, 3, 4, 5, 6}},
	}
	for _, c := range cases {
		if _, err := DecodeQHTReset(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
	if _, err := DecodeQHT([]byte{}); err == nil {
		t.Error("empty G2: expected error")
	}
	badTypePkt := &G2Packet{Type: QHT, Payload: []byte{9, 1, 2, 3, 4, 5}}
	b, _ := EncodeG2Packet(badTypePkt)
	if _, err := DecodeQHT(b); err == nil {
		t.Error("bad leading type: expected error")
	}
}

func TestDecodeQHTPatchMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"short 1", []byte{QHTPatchType}},
		{"short 4", []byte{QHTPatchType, 1, 2, 3}},
		{"wrong type", []byte{QHTResetType, 1, 2, 3, 4}},
		{"bad bits", []byte{QHTPatchType, 1, 2, 0, 9}},
	}
	for _, c := range cases {
		if _, err := DecodeQHTPatch(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
	if _, err := DecodeQHTPatch([]byte{QHTPatchType, 1, 2, 0, 255}); err == nil {
		t.Error("expected bad bits error")
	}
}

func TestDecodeQHTBadG2Type(t *testing.T) {
	pkt := &G2Packet{Type: "XX", Payload: []byte{QHTResetType, 1, 2, 3, 4, 5}}
	b, _ := EncodeG2Packet(pkt)
	if _, err := DecodeQHT(b); err == nil {
		t.Error("expected bad G2 type error")
	}
}

func FuzzQHTReset(f *testing.F) {
	f.Add(EncodeQHTReset(QHTReset{Slots: 1, InfVal: 2}))
	f.Add([]byte{})
	f.Add(make([]byte, 6))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeQHTReset(b)
		if err != nil {
			return
		}
		enc := EncodeQHTReset(got)
		got2, err2 := DecodeQHTReset(enc)
		if err2 != nil {
			t.Fatalf("re-decode failed: %v", err2)
		}
		if got != got2 {
			t.Errorf("round-trip mismatch: %+v vs %+v", got, got2)
		}
	})
}

func FuzzQHTPatch(f *testing.F) {
	f.Add(EncodeQHTPatch(QHTPatch{SeqNo: 1, SeqSize: 2, Compressed: true, Bits: 4, Data: []byte{1, 2, 3}}))
	f.Add([]byte{})
	f.Add(make([]byte, 5))
	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodeQHTPatch(b)
		if err != nil {
			return
		}
		enc := EncodeQHTPatch(got)
		got2, err2 := DecodeQHTPatch(enc)
		if err2 != nil {
			t.Fatalf("re-decode failed: %v", err2)
		}
		if got.SeqNo != got2.SeqNo || got.SeqSize != got2.SeqSize || got.Compressed != got2.Compressed || got.Bits != got2.Bits || !bytes.Equal(got.Data, got2.Data) {
			t.Errorf("round-trip mismatch")
		}
	})
}

func FuzzQHT(f *testing.F) {
	f.Add(EncodeQHT(QHTReset{Slots: 1, InfVal: 2}))
	f.Add(EncodeQHT(QHTPatch{SeqNo: 1, SeqSize: 2, Compressed: true, Bits: 4, Data: []byte{1, 2, 3}}))
	f.Add([]byte{})
	f.Add(make([]byte, 6))
	f.Fuzz(func(t *testing.T, b []byte) {
		v, err := DecodeQHT(b)
		if err != nil {
			return
		}
		enc := EncodeQHT(v)
		if len(enc) == 0 {
			t.Fatal("empty re-encode")
		}
		v2, err2 := DecodeQHT(enc)
		if err2 != nil {
			t.Fatalf("re-decode failed: %v", err2)
		}
		if !reflect.DeepEqual(v, v2) {
			t.Errorf("round-trip mismatch: %+v vs %+v", v, v2)
		}
	})
}
