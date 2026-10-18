// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	var guid [idSize]byte
	for i := range guid {
		guid[i] = byte(i + 1)
	}
	p := Push{
		GUID:      guid,
		IPAddress: [4]byte{192, 168, 1, 100},
		Port:      6346,
		FileIndex: 42,
	}
	enc := EncodePush(p)
	if len(enc) != pushPayloadSize {
		t.Fatalf("encoded len = %d, want %d", len(enc), pushPayloadSize)
	}
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.GUID != p.GUID {
		t.Errorf("guid mismatch")
	}
	if dec.IPAddress != p.IPAddress {
		t.Errorf("ip mismatch: %v", dec.IPAddress)
	}
	if dec.Port != p.Port {
		t.Errorf("port mismatch")
	}
	if dec.FileIndex != p.FileIndex {
		t.Errorf("index mismatch")
	}
}

func TestDecodePushMalformed(t *testing.T) {
	if _, err := DecodePush([]byte{1, 2, 3}); err == nil {
		t.Error("expected error for payload too short")
	}
}
