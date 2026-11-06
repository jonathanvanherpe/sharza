// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		ServentID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		FileIndex: 42,
		IP:        [4]byte{127, 0, 0, 1},
		Port:      6346,
	}
	enc := EncodePush(p)
	if len(enc) != pushPayloadSize {
		t.Fatalf("encoded length: got %d want %d", len(enc), pushPayloadSize)
	}
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.ServentID != p.ServentID {
		t.Errorf("servent id mismatch: got %x want %x", dec.ServentID, p.ServentID)
	}
	if dec.FileIndex != p.FileIndex {
		t.Errorf("file index: got %d want %d", dec.FileIndex, p.FileIndex)
	}
	if dec.IP != p.IP {
		t.Errorf("ip mismatch: got %v want %v", dec.IP, p.IP)
	}
	if dec.Port != p.Port {
		t.Errorf("port: got %d want %d", dec.Port, p.Port)
	}
}

func TestDecodePushMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"too short 25", make([]byte, 25)},
		{"one byte", []byte{0x01}},
	}
	for _, c := range cases {
		if _, err := DecodePush(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func FuzzPushRoundTrip(f *testing.F) {
	p := Push{
		ServentID: [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
		FileIndex: 42,
		IP:        [4]byte{127, 0, 0, 1},
		Port:      6346,
	}
	f.Add(EncodePush(p))
	p2 := Push{}
	f.Add(EncodePush(p2))

	f.Fuzz(func(t *testing.T, b []byte) {
		got, err := DecodePush(b)
		if err != nil {
			return
		}
		enc := EncodePush(got)
		got2, err2 := DecodePush(enc)
		if err2 != nil {
			t.Fatalf("re-decode failed: %v", err2)
		}
		if got != got2 {
			t.Errorf("round-trip mismatch: %+v vs %+v", got, got2)
		}
	})
}
