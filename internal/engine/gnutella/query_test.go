// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
)

func TestEncodeDecodeQueryRoundTrip(t *testing.T) {
	q := Query{MinSpeed: 1000, Search: "test.mp3"}
	enc := EncodeQuery(q)
	dec, err := DecodeQuery(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.MinSpeed != q.MinSpeed {
		t.Errorf("minspeed: got %d want %d", dec.MinSpeed, q.MinSpeed)
	}
	if dec.Search != q.Search {
		t.Errorf("search: got %q want %q", dec.Search, q.Search)
	}
}

func TestDecodeQueryMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"too short", []byte{0x01}},
		{"no nul", []byte{0x10, 0x27, 0x74, 0x65, 0x73, 0x74}}, // speed 0x2710, "test"
		{"empty search with nul?", []byte{0x00, 0x00, 0x00}},      // speed 0, then just nul - but our code expects search bytes before nul; this gives search empty string after nul? payload[2:] is [0x00], so idx 0 is nul, search becomes empty string - valid
	}
	for _, c := range cases {
		if c.name == "empty search with nul?" {
			// [0x00,0x00,0x00] means speed 0, search bytes [0x00], nul at 0 - so search is empty; this is valid
			if _, err := DecodeQuery(c.b); err != nil {
				t.Errorf("%s: expected no error for empty search, got %v", c.name, err)
			}
			continue
		}
		if _, err := DecodeQuery(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func TestEncodeDecodeQueryHitRoundTrip(t *testing.T) {
	qh := QueryHit{
		HitCount:  1,
		Port:      6346,
		IP:        [4]byte{127, 0, 0, 1},
		Speed:     10000,
		ServentID: testID(0x42),
		Hits: []FileHit{
			{FileIndex: 1, FileSize: 12345, FileName: "file.mp3"},
		},
	}
	enc := EncodeQueryHit(qh)
	dec, err := DecodeQueryHit(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.HitCount != qh.HitCount || dec.Port != qh.Port || dec.Speed != qh.Speed {
		t.Errorf("basic mismatch")
	}
	if dec.IP != qh.IP {
		t.Errorf("ip mismatch")
	}
	if dec.ServentID != qh.ServentID {
		t.Errorf("servent id mismatch: got %x want %x", dec.ServentID, qh.ServentID)
	}
	if len(dec.Hits) != 1 || dec.Hits[0].FileName != "file.mp3" || dec.Hits[0].FileSize != 12345 {
		t.Errorf("hit mismatch: %+v", dec.Hits)
	}
}

// TestEncodeQueryHitByteExact pins the full wire layout of QUERYHIT,
// byte for byte: the 16-byte servent ID sits between Speed and the hit
// list, where the annotated 0.4 spec and the 0.6 RFC both place it.
// Before the servent ID was implemented, this encode wrote 11 header
// bytes and every real peer's QUERYHIT decoded misaligned; a
// byte-exact expectation is what stops that regressing silently.
func TestEncodeQueryHitByteExact(t *testing.T) {
	var servent [16]byte
	for i := range servent {
		servent[i] = byte(i)
	}
	servent[8] = 0xFF // GUID "network" tag, per spec convention
	servent[15] = 0x00
	qh := QueryHit{
		Port:      0x1234,
		IP:        [4]byte{10, 20, 30, 40},
		Speed:     0x01020304,
		ServentID: servent,
		Hits: []FileHit{
			{FileIndex: 0x0A0B0C0D, FileSize: 0x11121314, FileName: "ab"},
		},
	}
	want := []byte{
		0x01, // hit count
		0x34, 0x12, // port, LE
		10, 20, 30, 40, // IPv4, BE
		0x04, 0x03, 0x02, 0x01, // speed, LE
		0, 1, 2, 3, 4, 5, 6, 7, 0xFF, 9, 10, 11, 12, 13, 14, 0x00, // servent ID
		0x0D, 0x0C, 0x0B, 0x0A, // file index, LE
		0x14, 0x13, 0x12, 0x11, // file size, LE
		'a', 'b', 0x00, // name, NUL-terminated
	}
	got := EncodeQueryHit(qh)
	if len(got) != len(want) {
		t.Fatalf("encoded %d bytes, want %d: %x", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("byte %d = 0x%02x, want 0x%02x (full: %x)", i, got[i], want[i], got)
		}
	}
}

// TestDecodeQueryHitSpecPayload decodes a payload shaped the way the
// spec (and every live peer) emits it: the servent ID between Speed
// and the hits, with the hit's own bytes chosen so that reading the
// hit from inside the GUID (the pre-fix misalignment) could not
// produce the right file name or size by accident.
func TestDecodeQueryHitSpecPayload(t *testing.T) {
	payload := []byte{
		0x02,             // hit count: 2
		0x22, 0x13,       // port 4898, LE
		192, 0, 2, 10,    // IPv4 192.0.2.10, BE
		0xE8, 0x03, 0, 0, // speed 1000, LE
		// servent ID: distinct at every offset
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xFF, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0x00,
		// hit 0
		0x01, 0x00, 0x00, 0x00, // index 1
		0x00, 0x10, 0x00, 0x00, // size 4096
		'o', 'n', 'e', '.', 'm', 'p', '3', 0x00,
		// hit 1
		0x02, 0x00, 0x00, 0x00, // index 2
		0x00, 0x20, 0x00, 0x00, // size 8192
		't', 'w', 'o', '.', 'i', 's', 'o', 0x00,
	}
	qh, err := DecodeQueryHit(payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	wantServent := [16]byte{
		0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7,
		0xFF, 0xA9, 0xAA, 0xAB, 0xAC, 0xAD, 0xAE, 0x00,
	}
	if qh.ServentID != wantServent {
		t.Errorf("servent id = %x, want %x", qh.ServentID, wantServent)
	}
	if qh.HitCount != 2 || qh.Port != 4898 || qh.Speed != 1000 {
		t.Errorf("header mismatch: %+v", qh)
	}
	if qh.IP != [4]byte{192, 0, 2, 10} {
		t.Errorf("ip = %v, want 192.0.2.10", qh.IP)
	}
	if len(qh.Hits) != 2 {
		t.Fatalf("got %d hits, want 2", len(qh.Hits))
	}
	if qh.Hits[0].FileName != "one.mp3" || qh.Hits[0].FileSize != 4096 || qh.Hits[0].FileIndex != 1 {
		t.Errorf("hit 0 misaligned: %+v", qh.Hits[0])
	}
	if qh.Hits[1].FileName != "two.iso" || qh.Hits[1].FileSize != 8192 || qh.Hits[1].FileIndex != 2 {
		t.Errorf("hit 1 misaligned: %+v", qh.Hits[1])
	}
}

func TestDecodeQueryHitMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"too short", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"header without servent id", make([]byte, 11)}, // pre-fix header size is now invalid
		{"header minus one byte", make([]byte, 26)},     // 27 is the floor
		{"header only, empty hit list", make([]byte, 27)},
		{"hit header short", func() []byte {
			b := make([]byte, 27)
			b[0] = 1 // hitcount 1, but no hit bytes follow
			return b
		}()},
		{"missing nul", func() []byte {
			b := make([]byte, 27+8+4) // header + hit header + 4 chars no nul
			b[0] = 1
			copy(b[27+8:27+8+4], []byte("file"))
			return b
		}()},
	}
	for _, c := range cases {
		if c.name == "header only, empty hit list" {
			// A 27-byte payload with hitcount 0 decodes as an
			// empty hit list, which is well-formed.
			if _, err := DecodeQueryHit(c.b); err != nil {
				t.Errorf("%s: expected no error for empty hit list, got %v", c.name, err)
			}
			continue
		}
		if _, err := DecodeQueryHit(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

func FuzzDecodeQuery(f *testing.F) {
	// seed with valid messages
	q := Query{MinSpeed: 0, Search: "test"}
	f.Add(EncodeQuery(q))
	q = Query{MinSpeed: 100, Search: ""}
	f.Add(EncodeQuery(q))
	q = Query{MinSpeed: 0, Search: "very long search string with spaces"}
	f.Add(EncodeQuery(q))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeQuery(b)
	})
}

func FuzzDecodeQueryHit(f *testing.F) {
	// seed with valid messages (full wire layout, servent ID included)
	qh := QueryHit{
		HitCount:  1,
		Port:      6346,
		IP:        [4]byte{127, 0, 0, 1},
		Speed:     1000,
		ServentID: testID(0x11),
		Hits:      []FileHit{{FileIndex: 0, FileSize: 100, FileName: "a"}},
	}
	f.Add(EncodeQueryHit(qh))
	qh.HitCount = 2
	qh.ServentID = testID(0x22)
	qh.Hits = []FileHit{{FileIndex: 1, FileSize: 200, FileName: "b"}, {FileIndex: 2, FileSize: 300, FileName: "c"}}
	f.Add(EncodeQueryHit(qh))
	qh.HitCount = 0
	qh.Hits = nil
	f.Add(EncodeQueryHit(qh))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeQueryHit(b)
	})
}