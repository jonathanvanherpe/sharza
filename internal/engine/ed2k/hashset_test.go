// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func TestHashSetRequestRoundTrip(t *testing.T) {
	h := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	r := HashSetRequest{Hash: h}
	b := r.Marshal()
	if len(b) != 16 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeHashSetRequest(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Hash != h || g.FileHash != h || g.MD4 != h {
		t.Fatalf("hash mismatch")
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip mismatch")
	}
	for _, rr := range []HashSetRequest{{FileHash: h}, {MD4: h}} {
		if !bytes.Equal(rr.Marshal(), b) {
			t.Fatal("alias mismatch")
		}
	}
	if _, err := DecodeHashSetRequest([]byte{1, 2}); err == nil {
		t.Fatal("expected truncated")
	}
	if _, err := DecodeHashSetRequest(make([]byte, 17)); err == nil {
		t.Fatal("expected trailing")
	}
}

func TestHashSetAnswerRoundTrip(t *testing.T) {
	hs := [][16]byte{{1}, {2}, {3}}
	a := HashSetAnswer{Count: 3, Hashes: hs}
	b := a.Marshal()
	if len(b) != 2+3*16 {
		t.Fatalf("len=%d", len(b))
	}
	g, err := DecodeHashSetAnswer(b)
	if err != nil {
		t.Fatal(err)
	}
	if g.Count != 3 {
		t.Fatalf("count=%d", g.Count)
	}
	if len(g.Hashes) != 3 {
		t.Fatalf("hashes=%d", len(g.Hashes))
	}
	if !bytes.Equal(g.Marshal(), b) {
		t.Fatal("round-trip mismatch")
	}
	// empty
	eb := HashSetAnswer{Count: 0}.Marshal()
	if len(eb) != 2 {
		t.Fatalf("empty len=%d", len(eb))
	}
	eg, err := DecodeHashSetAnswer(eb)
	if err != nil {
		t.Fatal(err)
	}
	if eg.Count != 0 || len(eg.Hashes) != 0 {
		t.Fatalf("empty count=%d", eg.Count)
	}
	if !bytes.Equal(eg.Marshal(), eb) {
		t.Fatal("empty round-trip")
	}
	// aliases
	for _, alias := range []HashSetAnswer{{NumHashes: 3, Hashes: hs}, {Hashes: hs}} {
		if !bytes.Equal(alias.Marshal(), b) {
			t.Fatal("alias mismatch")
		}
	}
	if _, err := DecodeHashSetAnswer([]byte{1}); err == nil {
		t.Fatal("expected truncated")
	}
	if _, err := DecodeHashSetAnswer(make([]byte, 3)); err == nil {
		t.Fatal("expected trailing")
	}
}

func TestHashSetAnswerAliases(t *testing.T) {
	hs := [][16]byte{{9}}
	b := HashSetAnswer{Count: 1, Hashes: hs}.Marshal()
	// count aliases
	for _, a := range []HashSetAnswer{
		{NumHashes: 1, Hashes: hs},
		{BlockCount: 1, Hashes: hs},
		{NumBlocks: 1, Hashes: hs},
	} {
		if !bytes.Equal(a.Marshal(), b) {
			t.Fatal("count alias mismatch")
		}
	}
	// hash slice aliases
	for _, a := range []HashSetAnswer{
		{Count: 1, Blocks: hs},
		{Count: 1, HashList: hs},
		{Count: 1, Entries: hs},
		{Count: 1, Items: hs},
		{Count: 1, Data: hs},
		{Count: 1, List: hs},
		{Count: 1, Values: hs},
	} {
		if !bytes.Equal(a.Marshal(), b) {
			t.Fatal("hash alias mismatch")
		}
	}
}

func TestOpcodeConstantsHashSet(t *testing.T) {
	if OP_HASHSETREQUEST != 0x51 {
		t.Fatal("OP_HASHSETREQUEST")
	}
	if OP_HASHSETANSWER != 0x52 {
		t.Fatal("OP_HASHSETANSWER")
	}
}

func FuzzHashSet(f *testing.F) {
	f.Add([]byte{})
	f.Add(HashSetRequest{Hash: [16]byte{1}}.Marshal())
	f.Add(HashSetAnswer{Count: 1, Hashes: [][16]byte{{1}}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		// request
		if r, err := DecodeHashSetRequest(data); err == nil {
			b := r.Marshal()
			g, err := DecodeHashSetRequest(b)
			if err != nil {
				t.Fatalf("request re-decode failed: %v", err)
			}
			if !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("request round-trip mismatch")
			}
		}
		// answer
		if a, err := DecodeHashSetAnswer(data); err == nil {
			b := a.Marshal()
			g, err := DecodeHashSetAnswer(b)
			if err != nil {
				t.Fatalf("answer re-decode failed: %v", err)
			}
			if !bytes.Equal(g.Marshal(), b) {
				t.Fatalf("answer round-trip mismatch")
			}
		}
	})
}
