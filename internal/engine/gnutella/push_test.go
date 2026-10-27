// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		ServentID: [idSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0},
		FileIndex: 42,
		IP:        [4]byte{127, 0, 0, 1},
		Port:      6346,
	}
	enc := EncodePush(p)
	if len(enc) != 26 {
		t.Fatalf("len: got %d want 26", len(enc))
	}
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec != p {
		t.Errorf("mismatch: got %+v want %+v", dec, p)
	}
}

func TestDecodePushShort(t *testing.T) {
	if _, err := DecodePush(make([]byte, 25)); err == nil {
		t.Fatal("expected error for short payload")
	}
}

func TestDecodePushTrailingGGEP(t *testing.T) {
	p := Push{
		ServentID: [idSize]byte{9, 9, 9},
		FileIndex: 7,
		IP:        [4]byte{10, 0, 0, 1},
		Port:      1234,
	}
	enc := EncodePush(p)
	enc = append(enc, []byte{0xC3, 0x01, 0x02, 0x00}...) // trailing GGEP-ish
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec != p {
		t.Errorf("mismatch: got %+v want %+v", dec, p)
	}
}

func TestPushRegistryIdentity(t *testing.T) {
	// Two distinct connections sharing one remote address is not
	// possible with real TCP; use a pipe and distinct fake addresses by
	// wrapping. Instead, exercise identity guarding with two peer values
	// backed by the same conn but distinct pointers: remove must not
	// evict a different peer registered under the same address.
	a, b := net.Pipe()
	defer a.Close()
	defer b.Close()

	p1 := &peer{conn: a}
	p2 := &peer{conn: a}

	r := newPushRegistry()
	if !r.add(p1) {
		t.Fatal("add p1 failed")
	}
	// A second, different peer under the same address must not replace.
	if r.add(p2) {
		t.Fatal("add p2 should not replace p1")
	}
	// remove by a non-registered pointer must not evict p1.
	if r.remove(p2) {
		t.Fatal("remove p2 should be no-op")
	}
	// Now remove p1 succeeds.
	if !r.remove(p1) {
		t.Fatal("remove p1 failed")
	}
	if err := r.send(a.RemoteAddr(), Push{}); err != ErrNoPushPath {
		t.Fatalf("expected ErrNoPushPath, got %v", err)
	}
	// Re-add p2 now that slot is free.
	if !r.add(p2) {
		t.Fatal("add p2 after remove failed")
	}
}