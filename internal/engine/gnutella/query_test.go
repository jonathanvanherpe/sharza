// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
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
		{"empty search with nul?", []byte{0x00, 0x00, 0x00}},   // speed 0, then just nul - but our code expects search bytes before nul; this gives search empty string after nul? payload[2:] is [0x00], so idx 0 is nul, search becomes empty string - valid
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

// TestQueryHitTrailerCarriesServentIdentifier pins the trailing field
// PUSH routing depends on (§2.2.6/§2.2.8): an encoded hit with a
// ClientID ends in the extensions-block terminator 0x00 followed by
// those 16 bytes, and the decoder gives them back; a hit without one
// keeps its previous byte-exact encoding and decodes to a zero
// ClientID rather than reading its last hit's name bytes as an id.
func TestQueryHitTrailerCarriesServentIdentifier(t *testing.T) {
	base := QueryHit{
		HitCount: 1,
		Port:     6346,
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 1, FileSize: 12345, FileName: "file.mp3"}},
	}
	serventID := testID(0x77)

	withID := base
	withID.ClientID = serventID
	enc := EncodeQueryHit(withID)

	if len(enc) < idSize+1 {
		t.Fatalf("encoded hit is %d bytes, too short for a trailer", len(enc))
	}
	if got := enc[len(enc)-idSize-1]; got != 0x00 {
		t.Errorf("byte before the servent id = %#x, want the extensions terminator 0x00", got)
	}
	if !bytes.Equal(enc[len(enc)-idSize:], serventID[:]) {
		t.Errorf("trailing servent id = %x, want %x", enc[len(enc)-idSize:], serventID)
	}
	dec, err := DecodeQueryHit(enc)
	if err != nil {
		t.Fatalf("DecodeQueryHit: %v", err)
	}
	if dec.ClientID != serventID {
		t.Errorf("decoded ClientID = %x, want %x", dec.ClientID, serventID)
	}
	if len(dec.Hits) != 1 || dec.Hits[0].FileName != "file.mp3" {
		t.Errorf("hits after trailer decode: %+v, want the original hit", dec.Hits)
	}

	// Without an identifier the encoding is exactly what it was before
	// PUSH existed, and the decoder must not mistake trailing name
	// bytes for an id.
	plain := EncodeQueryHit(base)
	if dec, err := DecodeQueryHit(plain); err != nil {
		t.Fatalf("DecodeQueryHit(plain): %v", err)
	} else if dec.ClientID != ([idSize]byte{}) {
		t.Errorf("ClientID of a hit without a trailer = %x, want all zero", dec.ClientID)
	}
}
