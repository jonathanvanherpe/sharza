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

func TestEncodeDecodeQueryHit06Form(t *testing.T) {
	// 0.6 form: the responding servent's identifier is appended in
	// the last 16 bytes of the message.
	var sid [idSize]byte
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	qh := QueryHit{
		HitCount:  1,
		Port:      6346,
		IP:        [4]byte{127, 0, 0, 1},
		Speed:     10000,
		Hits:      []FileHit{{FileIndex: 1, FileSize: 12345, FileName: "file.mp3"}},
		ServentID: sid,
	}
	enc := EncodeQueryHit(qh)
	want := 11 + 8 + len("file.mp3") + 1 + idSize
	if len(enc) != want {
		t.Fatalf("length: got %d want %d", len(enc), want)
	}
	dec, err := DecodeQueryHit(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.ServentID != sid {
		t.Errorf("servent id: got %x want %x", dec.ServentID, sid)
	}
	if dec.Port != qh.Port || dec.IP != qh.IP || dec.Speed != qh.Speed {
		t.Errorf("header mismatch: %+v", dec)
	}
	if len(dec.Hits) != 1 || dec.Hits[0].FileName != "file.mp3" {
		t.Errorf("hit mismatch: %+v", dec.Hits)
	}
}

func TestDecodeQueryHitSkipsTrailerBeforeServentID(t *testing.T) {
	// A real 0.6 QUERYHIT may carry an EQHD extension block between
	// the result set and the trailing servent identifier. The decoder
	// must skip the trailer and take the servent id from the last 16
	// bytes.
	qh := QueryHit{
		HitCount:  1,
		Port:      6346,
		IP:        [4]byte{10, 1, 2, 3},
		Speed:     10000,
		Hits:      []FileHit{{FileIndex: 7, FileSize: 999, FileName: "a.mp3"}},
		ServentID: [idSize]byte{0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0x00},
	}
	enc := EncodeQueryHit(qh)
	// EQHD shape: payload-length byte followed by the payload,
	// wedged between the result set and the servent id.
	trailer := []byte{0x03, 0x01, 0x02, 0x03}
	msg := make([]byte, 0, len(enc)+len(trailer))
	msg = append(msg, enc[:len(enc)-idSize]...)
	msg = append(msg, trailer...)
	msg = append(msg, enc[len(enc)-idSize:]...)

	dec, err := DecodeQueryHit(msg)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.ServentID != qh.ServentID {
		t.Errorf("servent id: got %x want %x", dec.ServentID, qh.ServentID)
	}
	if len(dec.Hits) != 1 || dec.Hits[0].FileIndex != 7 || dec.Hits[0].FileName != "a.mp3" {
		t.Errorf("hit mismatch: %+v", dec.Hits)
	}
}

func TestDecodeQueryHit04FormHasNoServentID(t *testing.T) {
	// A pure 0.4 QUERYHIT ends exactly at the last hit's NUL, so the
	// servent id must stay zero, and with it zero the encode must not
	// gain any trailing bytes.
	qh := QueryHit{
		HitCount:  1,
		Port:      6346,
		IP:        [4]byte{192, 168, 0, 4},
		Speed:     1000,
		Hits:      []FileHit{{FileIndex: 3, FileSize: 100, FileName: "x.bin"}},
		ServentID: [idSize]byte{},
	}
	enc := EncodeQueryHit(qh)
	dec, err := DecodeQueryHit(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.ServentID != [idSize]byte{} {
		t.Errorf("servent id: got %x want zero", dec.ServentID)
	}
	if len(enc) != 11+8+len("x.bin")+1 {
		t.Errorf("0.4 form gained trailing bytes: %d", len(enc))
	}
}

func TestQueryHitFirewalled(t *testing.T) {
	firewalled := []QueryHit{
		{Port: 0, IP: [4]byte{192, 168, 0, 4}},      // zero port
		{Port: 6346, IP: [4]byte{0, 0, 0, 0}},       // unspecified ip
		{Port: 0, IP: [4]byte{0, 0, 0, 0}},          // both
	}
	open := []QueryHit{
		{Port: 6346, IP: [4]byte{192, 168, 0, 4}},
		{Port: 1, IP: [4]byte{127, 0, 0, 1}},
	}
	for i, qh := range firewalled {
		if !qh.Firewalled() {
			t.Errorf("case %d: %+v should be firewalled", i, qh)
		}
	}
	for i, qh := range open {
		if qh.Firewalled() {
			t.Errorf("case %d: %+v should not be firewalled", i, qh)
		}
	}
}

func TestDecodeQueryHitTruncated06TailLeavesServentIDZero(t *testing.T) {
	// A truncated 0.6 tail (fewer than 16 trailing bytes) is
	// ignorable: the result set decodes and the servent id stays zero.
	qh := QueryHit{
		HitCount:  1,
		Port:      6346,
		IP:        [4]byte{10, 0, 0, 1},
		Speed:     1000,
		Hits:      []FileHit{{FileIndex: 1, FileSize: 50, FileName: "y"}},
		ServentID: [idSize]byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10},
	}
	enc := EncodeQueryHit(qh)
	trunc := enc[:len(enc)-10] // cut the trailer, leave 6 id bytes
	dec, err := DecodeQueryHit(trunc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.ServentID != [idSize]byte{} {
		t.Errorf("servent id: got %x want zero", dec.ServentID)
	}
	if len(dec.Hits) != 1 || dec.Hits[0].FileName != "y" {
		t.Errorf("hit mismatch: %+v", dec.Hits)
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