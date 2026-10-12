// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"reflect"
	"testing"
)

// TestEncodeGGEPBrowseHost pins the exact bytes of the lone "BH" marker:
// magic 0xC3, flags 0x82 (ID length 2, last extension), "BH", length 0x40
// (value 0, last length byte). This is the browse QUERY's whole extension
// section, so a change to the codec that keeps round-tripping but changes
// the wire shape is caught here.
func TestEncodeGGEPBrowseHost(t *testing.T) {
	got := EncodeGGEP([]GGEPExtension{{ID: "BH"}})
	want := []byte{0xC3, 0x82, 'B', 'H', 0x40}
	if !bytes.Equal(got, want) {
		t.Fatalf("EncodeGGEP(BH) = % X, want % X", got, want)
	}
}

func TestGGEPRoundTrip(t *testing.T) {
	long := make([]byte, 200)
	for i := range long {
		long[i] = byte('a' + i%26)
	}
	cases := []struct {
		name string
		exts []GGEPExtension
	}{
		{"single marker", []GGEPExtension{{ID: "BH"}}},
		{"two markers", []GGEPExtension{{ID: "BH"}, {ID: "CH"}}},
		{"one byte id", []GGEPExtension{{ID: "H"}}},
		{"fifteen byte id", []GGEPExtension{{ID: "ABCDEFGHIJKLMNO"}}},
		{"data length 1", []GGEPExtension{{ID: "X", Data: []byte{0xFF}}}},
		{"data length 63", []GGEPExtension{{ID: "X", Data: make([]byte, 63)}}},
		{"data length 64", []GGEPExtension{{ID: "X", Data: make([]byte, 64)}}},
		{"data length 4095", []GGEPExtension{{ID: "X", Data: make([]byte, 4095)}}},
		{"data length 4096", []GGEPExtension{{ID: "X", Data: make([]byte, 4096)}}},
		{"data length max", []GGEPExtension{{ID: "X", Data: make([]byte, ggepMaxDataLen)}}},
		{"multiple mixed", []GGEPExtension{
			{ID: "BH"},
			{ID: "LF", Data: []byte{1, 2, 3, 4}},
			{ID: "XYZ", Data: long},
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			enc := EncodeGGEP(c.exts)
			dec, err := DecodeGGEP(enc)
			if err != nil {
				t.Fatalf("DecodeGGEP: %v", err)
			}
			// A zero-length payload decodes as nil, not as an empty slice.
			want := make([]GGEPExtension, 0, len(c.exts))
			for _, e := range c.exts {
				d := e.Data
				if len(d) == 0 {
					d = nil
				}
				want = append(want, GGEPExtension{ID: e.ID, Data: d})
			}
			if !reflect.DeepEqual(dec, want) {
				t.Fatalf("round trip = %+v, want %+v", dec, want)
			}
		})
	}
}

// TestEncodeGGEPRejectsInvalidInput pins the policy that an extension whose
// ID cannot be represented (empty, over 15 bytes, non-ASCII) is skipped
// rather than emitting an unparseable block.
func TestEncodeGGEPRejectsInvalidInput(t *testing.T) {
	cases := []struct {
		name string
		exts []GGEPExtension
		want []byte
	}{
		{"empty id", []GGEPExtension{{ID: ""}}, nil},
		{"id too long", []GGEPExtension{{ID: "ABCDEFGHIJKLMNOP"}}, nil},
		{"id not ascii", []GGEPExtension{{ID: "B\x01"}}, nil},
		{"data too long", []GGEPExtension{{ID: "X", Data: make([]byte, ggepMaxDataLen+1)}}, nil},
		{"invalid then valid", []GGEPExtension{{ID: ""}, {ID: "BH"}}, []byte{0xC3, 0x82, 'B', 'H', 0x40}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := EncodeGGEP(c.exts)
			if !bytes.Equal(got, c.want) {
				t.Fatalf("EncodeGGEP = % X, want % X", got, c.want)
			}
		})
	}
}

func TestDecodeGGEPMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"bad magic", []byte{0x00, 0x82, 'B', 'H', 0x40}},
		{"reserved bit", []byte{0xC3, 0x92, 'B', 'H', 0x40}},
		{"cobs flag", []byte{0xC3, 0xC2, 'B', 'H', 0x40}},
		{"deflate flag", []byte{0xC3, 0xA2, 'B', 'H', 0x40}},
		{"zero id length", []byte{0xC3, 0x80, 0x40}},
		{"truncated id", []byte{0xC3, 0x82, 'B'}},
		{"missing length", []byte{0xC3, 0x82, 'B', 'H'}},
		{"length both flags", []byte{0xC3, 0x82, 'B', 'H', 0xC0}},
		{"length neither flag", []byte{0xC3, 0x82, 'B', 'H', 0x00}},
		{"length too long", []byte{0xC3, 0x82, 'B', 'H', 0x80, 0x80, 0x80}},
		{"data overlong", []byte{0xC3, 0x82, 'B', 'H', 0x45}},
		{"trailing bytes", []byte{0xC3, 0x82, 'B', 'H', 0x40, 0x00}},
		{"control in id", []byte{0xC3, 0x82, 0x01, 'H', 0x40}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := DecodeGGEP(c.b); err == nil {
				t.Fatalf("DecodeGGEP(% X) succeeded, want an error", c.b)
			}
		})
	}
}
