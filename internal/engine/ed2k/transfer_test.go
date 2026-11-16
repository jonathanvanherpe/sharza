// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func TestRequestPartsRoundTrip(t *testing.T) {
	h := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	cases := []struct {
		name string
		rp   RequestParts
	}{
		{"zero", RequestParts{}},
		{"basic", RequestParts{Hash: h, Von: [3]uint32{10, 20, 30}, Bis: [3]uint32{11, 21, 31}}},
		{"alias-fields", RequestParts{FileHash: h, From: [3]uint32{1, 2, 3}, To: [3]uint32{4, 5, 6}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c.rp.Marshal()
			if len(b) != 40 {
				t.Fatalf("len = %d", len(b))
			}
			g, err := DecodeRequestParts(b)
			if err != nil {
				t.Fatal(err)
			}
			hh, vv, bb := c.rp.normalized()
			if g.Hash != hh {
				t.Fatalf("hash mismatch")
			}
			for i := 0; i < 3; i++ {
				if g.Von[i] != vv[i] || g.Bis[i] != bb[i] {
					t.Fatalf("range %d mismatch: %v/%v vs %v/%v", i, g.Von[i], g.Bis[i], vv[i], bb[i])
				}
			}
			if !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("re-encode mismatch")
			}
			// aliases
			if !bytes.Equal(c.rp.Encode(), b) {
				t.Fatal("Encode mismatch")
			}
			if !bytes.Equal(c.rp.Bytes(), b) {
				t.Fatal("Bytes mismatch")
			}
			g2, err := ParseRequestParts(b)
			if err != nil || g2.Hash != g.Hash {
				t.Fatal("ParseRequestParts mismatch")
			}
			// top-level helpers
			if !bytes.Equal(MarshalRequestParts(c.rp), EncodeRequestParts(c.rp)) {
				t.Fatal("top-level helper mismatch")
			}
			// method decode
			var r RequestParts
			if err := r.Decode(b); err != nil {
				t.Fatal(err)
			}
			if err := r.Unmarshal(b); err != nil {
				t.Fatal(err)
			}
			// binary marshaler
			mb, err := c.rp.MarshalBinary()
			if err != nil || !bytes.Equal(mb, b) {
				t.Fatal("MarshalBinary mismatch")
			}
		})
	}
}

func TestSendingPartRoundTrip(t *testing.T) {
	h := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	data := []byte{0xde, 0xad, 0xbe, 0xef}
	cases := []struct {
		name string
		sp   SendingPart
	}{
		{"zero", SendingPart{}},
		{"basic", SendingPart{Hash: h, Von: 100, Bis: 104, Data: data}},
		{"alias-fields", SendingPart{MD4: h, From: 5, To: 9, Body: []byte{1, 2, 3, 4}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			b := c.sp.Marshal()
			g, err := DecodeSendingPart(b)
			if err != nil {
				t.Fatal(err)
			}
			hh, vv, bb, dd := c.sp.normalized()
			if g.Hash != hh {
				t.Fatalf("hash mismatch")
			}
			if g.Von != vv || g.Bis != bb {
				t.Fatalf("range mismatch: %d/%d vs %d/%d", g.Von, g.Bis, vv, bb)
			}
			if !bytes.Equal(g.Data, dd) {
				t.Fatalf("data mismatch")
			}
			if !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("re-encode mismatch")
			}
			if !bytes.Equal(c.sp.Encode(), b) {
				t.Fatal("Encode mismatch")
			}
			if !bytes.Equal(c.sp.Bytes(), b) {
				t.Fatal("Bytes mismatch")
			}
			g2, err := ParseSendingPart(b)
			if err != nil || g2.Hash != g.Hash {
				t.Fatal("ParseSendingPart mismatch")
			}
			if !bytes.Equal(MarshalSendingPart(c.sp), EncodeSendingPart(c.sp)) {
				t.Fatal("top-level helper mismatch")
			}
			var s SendingPart
			if err := s.Decode(b); err != nil {
				t.Fatal(err)
			}
			if err := s.Unmarshal(b); err != nil {
				t.Fatal(err)
			}
			mb, err := c.sp.MarshalBinary()
			if err != nil || !bytes.Equal(mb, b) {
				t.Fatal("MarshalBinary mismatch")
			}
			// strict trailing: append byte -> error? SendingPart consumes rest, so append changes data; decode still ok but data longer.
			// malformed truncated
		})
	}
}

func TestRequestPartsMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		{0x00},
		make([]byte, 39),
		make([]byte, 41),
	}
	for i, c := range cases {
		if _, err := DecodeRequestParts(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
	b := RequestParts{Hash: [16]byte{1}, Von: [3]uint32{1, 2, 3}, Bis: [3]uint32{4, 5, 6}}.Marshal()
	if _, err := DecodeRequestParts(append(b, 0x00)); err == nil {
		t.Fatal("expected error on trailing bytes")
	}
	var r RequestParts
	if err := r.Decode(b); err != nil {
		t.Fatal(err)
	}
	if err := r.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(MarshalRequestParts(r), EncodeRequestParts(r)) {
		t.Fatal("top-level helper mismatch")
	}
}

func TestSendingPartMalformed(t *testing.T) {
	cases := [][]byte{
		{},
		make([]byte, 23),
	}
	for i, c := range cases {
		if _, err := DecodeSendingPart(c); err == nil {
			t.Fatalf("case %d: expected error", i)
		}
	}
	b := SendingPart{Hash: [16]byte{1}, Von: 1, Bis: 5, Data: []byte{1, 2, 3, 4}}.Marshal()
	if _, err := DecodeSendingPart(b[:23]); err == nil {
		t.Fatal("expected error on truncated")
	}
	var s SendingPart
	if err := s.Decode(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Unmarshal(b); err != nil {
		t.Fatal(err)
	}
}

func TestTransferAliasFieldsPopulated(t *testing.T) {
	h := [16]byte{7}
	b := RequestParts{Hash: h, Von: [3]uint32{1, 2, 3}, Bis: [3]uint32{4, 5, 6}}.Marshal()
	g, err := DecodeRequestParts(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.FileHash != h || g.MD4 != h {
		t.Fatal("hash alias not populated")
	}
	if g.Vons != g.Von || g.From != g.Von || g.To != g.Bis {
		t.Fatal("range alias not populated")
	}
	if g.Von1 != 1 || g.Von2 != 2 || g.Von3 != 3 || g.Bis1 != 4 {
		t.Fatal("scalar alias not populated")
	}

	data := []byte{9, 9}
	b2 := SendingPart{Hash: h, Von: 10, Bis: 12, Data: data}.Marshal()
	g2, err := DecodeSendingPart(b2)
	if err != nil {
		t.Fatal(err)
	}
	if g2.FileHash != h || g2.MD4 != h {
		t.Fatal("hash alias not populated")
	}
	if g2.From != 10 || g2.Start != 10 || g2.To != 12 || g2.End != 12 {
		t.Fatal("range alias not populated")
	}
	if !bytes.Equal(g2.Body, data) || !bytes.Equal(g2.Payload, data) {
		t.Fatal("data alias not populated")
	}
}

func FuzzRequestParts(f *testing.F) {
	f.Add([]byte{})
	f.Add(RequestParts{Hash: [16]byte{1}, Von: [3]uint32{1, 2, 3}, Bis: [3]uint32{4, 5, 6}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		rp, err := DecodeRequestParts(data)
		if err != nil {
			return
		}
		b := rp.Marshal()
		g, err := DecodeRequestParts(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzSendingPart(f *testing.F) {
	f.Add([]byte{})
	f.Add(SendingPart{Hash: [16]byte{1}, Von: 1, Bis: 5, Data: []byte{1, 2, 3, 4}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		sp, err := DecodeSendingPart(data)
		if err != nil {
			return
		}
		b := sp.Marshal()
		g, err := DecodeSendingPart(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzEd2kTransfer(f *testing.F) {
	f.Add([]byte{})
	f.Add(RequestParts{Hash: [16]byte{1}, Von: [3]uint32{1, 2, 3}, Bis: [3]uint32{4, 5, 6}}.Marshal())
	f.Add(SendingPart{Hash: [16]byte{1}, Von: 1, Bis: 5, Data: []byte{1, 2, 3, 4}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		if rp, err := DecodeRequestParts(data); err == nil {
			b := rp.Marshal()
			g, err := DecodeRequestParts(b)
			if err != nil || !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("request parts round-trip mismatch")
			}
		}
		if sp, err := DecodeSendingPart(data); err == nil {
			b := sp.Marshal()
			g, err := DecodeSendingPart(b)
			if err != nil || !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("sending part round-trip mismatch")
			}
		}
	})
}
