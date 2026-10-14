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
		HitCount:  1,
		Port:      6346,
		IP:        [4]byte{127, 0, 0, 1},
		Speed:     10000,
		ServentID: testID(0x1F),
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
		t.Errorf("servent id = %x, want %x", dec.ServentID, qh.ServentID)
	}
	if len(dec.Hits) != 1 || dec.Hits[0].FileName != "file.mp3" || dec.Hits[0].FileSize != 12345 {
		t.Errorf("hit mismatch: %+v", dec.Hits)
	}
}

// TestDecodeQueryHitServentIDIsTrailing16Bytes pins the one positional
// invariant the spec gives for the servent identifier: it is the last 16
// bytes, after whatever vendor, extension and XML bytes sit between the
// last name and it. The fixture is a realistic Shareaza trailer, so a
// decoder that instead read the 16 bytes straight after the name would
// be caught.
func TestDecodeQueryHitServentIDIsTrailing16Bytes(t *testing.T) {
	payload := EncodeQueryHit(QueryHit{
		HitCount: 1,
		Port:     6346,
		IP:       [4]byte{10, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 4, FileSize: 32, FileName: "x"}},
	})
	payload = append(payload, 0) // name NUL is already there; this is the trailer's first byte

	want := testID(0xC3)
	// A vendor code, a public-size byte, flags, an XML block and its NUL,
	// then the identifier. None of it is parsed; the identifier must
	// still be found at the end.
	payload = append(payload, []byte("RAZA")...)
	payload = append(payload, 0x04, 0x01, 0x00, 0x01, 0x00, 0x00)
	payload = append(payload, 0x00)
	payload = append(payload, want[:]...)

	dec, err := DecodeQueryHit(payload)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.ServentID != want {
		t.Errorf("servent id = %x, want the trailing %x", dec.ServentID, want)
	}
	if got := dec.Hits[0].FileName; got != "x" {
		t.Errorf("filename = %q, want %q", got, "x")
	}
}

func TestFirewalledSource(t *testing.T) {
	cases := []struct {
		name string
		qh   QueryHit
		want bool
	}{
		{"reachable", QueryHit{IP: [4]byte{192, 168, 1, 2}, Port: 6346}, false},
		{"zero port", QueryHit{IP: [4]byte{192, 168, 1, 2}, Port: 0}, true},
		{"unspecified ip", QueryHit{IP: [4]byte{0, 0, 0, 0}, Port: 6346}, true},
		{"both", QueryHit{}, true},
	}
	for _, tc := range cases {
		if got := firewalledSource(tc.qh); got != tc.want {
			t.Errorf("%s: firewalledSource = %v, want %v", tc.name, got, tc.want)
		}
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
