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
		HitCount: 1,
		Port:     6346,
		IP:       [4]byte{127, 0, 0, 1},
		Speed:    10000,
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
	if len(dec.Hits) != 1 || dec.Hits[0].FileName != "file.mp3" || dec.Hits[0].FileSize != 12345 {
		t.Errorf("hit mismatch: %+v", dec.Hits)
	}
}

func TestDecodeQueryHitMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"too short", []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
		{"hit header short", func() []byte {
			b := make([]byte, 11)
			b[0] = 1 // hitcount 1
			return b
		}()},
		{"missing nul", func() []byte {
			b := make([]byte, 11+8+4) // header+8 + 4 chars no nul
			b[0] = 1
			copy(b[11+8:11+8+4], []byte("file"))
			return b
		}()},
	}
	for _, c := range cases {
		if _, err := DecodeQueryHit(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		}
	}
}

// TestDecodeQueryHitReadsTrailingGUID pins the 0.6 QUERYHIT trailer: the
// last hit is followed by the 16-byte servent GUID, then optional
// GGEP/XML/remote-IP data. The GUID is what a PUSH addresses back to the
// servent that answered, and the bytes after it must be ignored so a real
// peer's GGEP block does not break the decode.
func TestDecodeQueryHitReadsTrailingGUID(t *testing.T) {
	guid := testID(0x3C)
	qh := QueryHit{
		HitCount: 1,
		Port:     6346,
		IP:       [4]byte{10, 0, 0, 1},
		Speed:    1000,
		Hits:     []FileHit{{FileIndex: 4, FileSize: 40, FileName: "guid.mp3"}},
	}
	wire := EncodeQueryHit(qh)
	wire = append(wire, guid[:]...)
	// A GGEP block and an XML trailer follow the GUID on real peers.
	wire = append(wire, 0xC3, 0x01, 0x00)
	wire = append(wire, []byte("<xml></xml>")...)

	dec, err := DecodeQueryHit(wire)
	if err != nil {
		t.Fatalf("DecodeQueryHit: %v", err)
	}
	if dec.GUID != guid {
		t.Errorf("GUID = %x, want the trailing servent GUID %x", dec.GUID, guid)
	}
	if len(dec.Hits) != 1 || dec.Hits[0].FileName != "guid.mp3" {
		t.Fatalf("hits = %+v, want the one encoded hit", dec.Hits)
	}
}

// TestDecodeQueryHitWithoutGUIDIsZero covers the tolerant path the live
// swarm needs: a QUERYHIT with no GUID trailer (or a short one) decodes
// with a zero GUID and no error, and the hit itself is unaffected.
func TestDecodeQueryHitWithoutGUIDIsZero(t *testing.T) {
	qh := QueryHit{
		HitCount: 1,
		Port:     6346,
		IP:       [4]byte{10, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 4, FileSize: 40, FileName: "noguid.mp3"}},
	}
	dec, err := DecodeQueryHit(EncodeQueryHit(qh))
	if err != nil {
		t.Fatalf("DecodeQueryHit: %v", err)
	}
	if dec.GUID != ([16]byte{}) {
		t.Errorf("GUID = %x, want the zero GUID when no trailer is present", dec.GUID)
	}

	// Fewer than 16 bytes trailing is a short trailer, not a GUID and not
	// an error.
	short := append(EncodeQueryHit(qh), 0xAA, 0xBB)
	dec2, err := DecodeQueryHit(short)
	if err != nil {
		t.Fatalf("DecodeQueryHit with a short trailer: %v", err)
	}
	if dec2.GUID != ([16]byte{}) {
		t.Errorf("GUID with a short trailer = %x, want zero", dec2.GUID)
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
	// seed with valid messages
	qh := QueryHit{
		HitCount: 1,
		Port:     6346,
		IP:       [4]byte{127, 0, 0, 1},
		Speed:    1000,
		Hits:     []FileHit{{FileIndex: 0, FileSize: 100, FileName: "a"}},
	}
	f.Add(EncodeQueryHit(qh))
	qh.HitCount = 2
	qh.Hits = []FileHit{{FileIndex: 1, FileSize: 200, FileName: "b"}, {FileIndex: 2, FileSize: 300, FileName: "c"}}
	f.Add(EncodeQueryHit(qh))
	qh.HitCount = 0
	qh.Hits = nil
	f.Add(EncodeQueryHit(qh))

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = DecodeQueryHit(b)
	})
}