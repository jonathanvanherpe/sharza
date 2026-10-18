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
	if dec.HasClientID {
		t.Error("round-trip hit has no client ID but decode reported one; HasClientID leaked true")
	}
}

// TestEncodeDecodeQueryHitWithClientID pins the 0.6 extension: a hit that
// carries a client ID encodes it as the trailing 16 bytes and decodes it
// back, and a hit that does not carry one stays absent. The push item
// depends on this: a QUERYHIT that cannot round-trip its client ID is not
// one a PUSH can be addressed back at.
func TestEncodeDecodeQueryHitWithClientID(t *testing.T) {
	id := [idSize]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	withID := QueryHit{
		HitCount:    1,
		Port:        6346,
		IP:          [4]byte{10, 0, 0, 1},
		Speed:       10000,
		Hits:        []FileHit{{FileIndex: 7, FileSize: 42, FileName: "a.bin"}},
		ClientID:    id,
		HasClientID: true,
	}
	enc := EncodeQueryHit(withID)
	if len(enc) != 11+8+len("a.bin")+1+idSize {
		t.Fatalf("encoded %d bytes, want the 0.6 payload to end with %d client-ID bytes", len(enc), idSize)
	}
	dec, err := DecodeQueryHit(enc)
	if err != nil {
		t.Fatalf("decode with client id: %v", err)
	}
	if !dec.HasClientID {
		t.Fatal("hit carried a client ID but decode dropped it; HasClientID stayed false")
	}
	if dec.ClientID != id {
		t.Errorf("client id round-trip = %x, want %x", dec.ClientID, id)
	}

	// A pre-0.6 sender omits the client ID entirely. Same hit, truncated
	// by the trailing 16 bytes: decode must not invent one.
	without := withID
	without.ClientID = [idSize]byte{}
	without.HasClientID = false
	encNo := EncodeQueryHit(without)
	if len(encNo) == len(enc) {
		t.Fatal("test setup: encoding with and without a client ID produced the same length")
	}
	decNo, err := DecodeQueryHit(encNo)
	if err != nil {
		t.Fatalf("decode without client id: %v", err)
	}
	if decNo.HasClientID {
		t.Error("hit omitted its client ID but decode reported one present")
	}
	if decNo.ClientID != [idSize]byte{} {
		t.Errorf("client id on a pre-0.6 hit = %x, want zero", decNo.ClientID)
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