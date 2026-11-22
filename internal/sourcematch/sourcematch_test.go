// SPDX-License-Identifier: GPL-3.0-or-later

package sourcematch

import (
	"bytes"
	"testing"
)

func TestNormalizeName(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"  Foo  Bar ", "foo bar"},
		{"FOO\t\tBAR\nBAZ", "foo bar baz"},
		{"", ""},
		{"a", "a"},
	}
	for _, c := range cases {
		if got := NormalizeName(c.in); got != c.want {
			t.Fatalf("NormalizeName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func makeSample(size int, fill byte) Sample {
	head := bytes.Repeat([]byte{fill}, size)
	if size > SampleSize {
		head = bytes.Repeat([]byte{fill}, SampleSize)
	}
	tail := bytes.Repeat([]byte{fill}, SampleSize)
	if size < SampleSize {
		tail = bytes.Repeat([]byte{fill}, size)
	}
	return Sample{Head: head, Tail: tail, Size: uint64(size)}
}

func TestNameSizeMatch(t *testing.T) {
	a := Candidate{Name: "Foo", Size: 100}
	b := Candidate{Name: "  foo  ", Size: 100}
	if !NameSizeMatch(a, b) {
		t.Fatal("expected name+size match")
	}
	b.Size = 101
	if NameSizeMatch(a, b) {
		t.Fatal("size mismatch should reject")
	}
	b = Candidate{Name: "bar", Size: 100}
	if NameSizeMatch(a, b) {
		t.Fatal("name mismatch should reject")
	}
}

func TestKnownHashMatch(t *testing.T) {
	a := Candidate{Hash: "ABC", HashAlgo: "sha1"}
	b := Candidate{Hash: "abc", HashAlgo: "sha1"}
	if !KnownHashMatch(a, b) {
		t.Fatal("expected hash match")
	}
	b.HashAlgo = "md4"
	if KnownHashMatch(a, b) {
		t.Fatal("algo mismatch should reject")
	}
	b = Candidate{Hash: "abc", HashAlgo: ""}
	if KnownHashMatch(a, b) {
		t.Fatal("empty algo should reject")
	}
}

func TestSampleMatch(t *testing.T) {
	s := SampleSize
	head := bytes.Repeat([]byte{1}, s)
	tail := bytes.Repeat([]byte{2}, s)
	sa := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	sb := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	if !SampleMatch(sa, sb) {
		t.Fatal("expected sample match")
	}
	// tampered head
	sb2 := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	sb2.Head[0] ^= 1
	if SampleMatch(sa, sb2) {
		t.Fatal("tampered head should reject")
	}
	// tampered tail
	sb3 := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	sb3.Tail[s-1] ^= 1
	if SampleMatch(sa, sb3) {
		t.Fatal("tampered tail should reject")
	}
	// size mismatch
	sb4 := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 3 * uint64(s)}
	if SampleMatch(sa, sb4) {
		t.Fatal("size mismatch should reject")
	}
	// zero size
	if SampleMatch(Sample{Head: head, Tail: tail, Size: 0}, sa) {
		t.Fatal("zero size should reject")
	}
}

func TestSampleMatchSmallFile(t *testing.T) {
	data := bytes.Repeat([]byte{7}, 1000)
	sa := Sample{Head: append([]byte{}, data...), Tail: append([]byte{}, data...), Size: 1000}
	sb := Sample{Head: append([]byte{}, data...), Tail: append([]byte{}, data...), Size: 1000}
	if !SampleMatch(sa, sb) {
		t.Fatal("small file sample should match")
	}
}

func TestMatchHashPinOverridesName(t *testing.T) {
	a := Candidate{Name: "foo", Size: 10, Hash: "h", HashAlgo: "sha1"}
	b := Candidate{Name: "bar", Size: 20, Hash: "H", HashAlgo: "sha1"}
	sa, sb := Sample{}, Sample{}
	r := Match(a, b, sa, sb)
	if !r.Match || r.Reason != "hash" {
		t.Fatalf("got %+v, want hash match", r)
	}
}

func TestMatchNameSizeSample(t *testing.T) {
	s := SampleSize
	head := bytes.Repeat([]byte{1}, s)
	tail := bytes.Repeat([]byte{2}, s)
	sa := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	sb := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	a := Candidate{Name: "foo", Size: 2 * uint64(s)}
	b := Candidate{Name: "  FOO ", Size: 2 * uint64(s)}
	r := Match(a, b, sa, sb)
	if !r.Match || r.Reason != "name+size+sample" {
		t.Fatalf("got %+v", r)
	}
}

func TestMatchTampered(t *testing.T) {
	s := SampleSize
	head := bytes.Repeat([]byte{1}, s)
	tail := bytes.Repeat([]byte{2}, s)
	sa := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	sb := Sample{Head: append([]byte{}, head...), Tail: append([]byte{}, tail...), Size: 2 * uint64(s)}
	sb.Head[5] ^= 1
	a := Candidate{Name: "foo", Size: 2 * uint64(s)}
	b := Candidate{Name: "foo", Size: 2 * uint64(s)}
	r := Match(a, b, sa, sb)
	if r.Match {
		t.Fatalf("tampered should reject: %+v", r)
	}
}

func TestMatchNameSizeOnly(t *testing.T) {
	a := Candidate{Name: "foo", Size: 10}
	b := Candidate{Name: "foo", Size: 10}
	r := Match(a, b, Sample{}, Sample{})
	if !r.Match || r.Reason != "name+size" {
		t.Fatalf("got %+v", r)
	}
}

func TestMatchNone(t *testing.T) {
	a := Candidate{Name: "foo", Size: 10}
	b := Candidate{Name: "bar", Size: 10}
	r := Match(a, b, Sample{}, Sample{})
	if r.Match || r.Reason != "none" {
		t.Fatalf("got %+v", r)
	}
}

func TestAliases(t *testing.T) {
	a := NewCandidate("foo", uint64(10), "net", "h", "sha1")
	b := NewCandidate("foo", 10)
	sa := NewSample(bytes.Repeat([]byte{1}, 5), bytes.Repeat([]byte{2}, 5), uint64(10))
	sb := NewSample(bytes.Repeat([]byte{1}, 5), bytes.Repeat([]byte{2}, 5), uint64(10))
	for _, fn := range []func(...interface{}) Result{SourceMatch, MatchSources, MatchCandidates} {
		r := fn(a, b, sa, sb)
		if !r.Match {
			t.Fatalf("alias returned false")
		}
	}
}

func FuzzSourceMatch(f *testing.F) {
	f.Add("foo", "foo", uint64(10), uint64(10))
	f.Fuzz(func(t *testing.T, name1, name2 string, size1, size2 uint64) {
		a := Candidate{Name: name1, Size: size1}
		b := Candidate{Name: name2, Size: size2}
		sa := Sample{Size: size1}
		sb := Sample{Size: size2}
		_ = Match(a, b, sa, sb)
		_ = NormalizeName(name1)
	})
}
