// SPDX-License-Identifier: GPL-3.0-or-later

// Package sourcematch implements sample-based source matching for Sharza's
// cross-network swarming: deciding whether two candidate sources (possibly on
// different networks) refer to the same file, using name/size, an optional
// known-hash pin, and a head/tail byte sample comparison.
//
// This package is intentionally standalone: it performs no I/O, holds no
// engine or store state, and is safe for concurrent use.
package sourcematch

import (
	"bytes"
	"fmt"
	"strings"
)

// SampleSize is the size of the head/tail sample used for verification.
const SampleSize = 64 * 1024

// Candidate describes a possible source for a file on some network.
type Candidate struct {
	Name     string
	Size     uint64
	Network  string
	Hash     string
	HashAlgo string
}

// Sample holds the head and tail bytes of a file plus its size.
type Sample struct {
	Head []byte
	Tail []byte
	Size uint64
}

// Result is the outcome of a source match attempt.
type Result struct {
	Match  bool
	Reason string
}

// NormalizeName lowercases, trims and collapses internal whitespace.
func NormalizeName(name string) string {
	return strings.ToLower(strings.Join(strings.Fields(name), " "))
}

// NameSizeMatch reports whether two candidates agree on normalized name and size.
func NameSizeMatch(a, b Candidate) bool {
	return NormalizeName(a.Name) == NormalizeName(b.Name) && a.Size == b.Size
}

// KnownHashMatch reports whether two candidates share a non-empty hash algorithm
// and a case-insensitively equal hash.
func KnownHashMatch(a, b Candidate) bool {
	if a.HashAlgo == "" || b.HashAlgo == "" {
		return false
	}
	if a.HashAlgo != b.HashAlgo {
		return false
	}
	return strings.EqualFold(a.Hash, b.Hash)
}

// SampleMatch reports whether two samples describe the same file content, using
// equal sizes (both greater than zero) and byte-equal head and tail slices.
// Overlapping head/tail regions for files shorter than 2*SampleSize are handled
// by comparing both slices as-is.
func SampleMatch(a, b Sample) bool {
	if a.Size == 0 || b.Size == 0 || a.Size != b.Size {
		return false
	}
	if !bytes.Equal(a.Head, b.Head) {
		return false
	}
	if !bytes.Equal(a.Tail, b.Tail) {
		return false
	}
	return true
}

// Match combines the source-matching rules: a known-hash pin first, then
// name+size, then head/tail sample verification.
func Match(a, b Candidate, sa, sb Sample) Result {
	if KnownHashMatch(a, b) {
		return Result{Match: true, Reason: "hash"}
	}
	if !NameSizeMatch(a, b) {
		return Result{Match: false, Reason: "none"}
	}
	hasSample := sa.Size > 0 || sb.Size > 0 || len(sa.Head) > 0 || len(sa.Tail) > 0 || len(sb.Head) > 0 || len(sb.Tail) > 0
	if !hasSample {
		return Result{Match: true, Reason: "name+size"}
	}
	if SampleMatch(sa, sb) {
		return Result{Match: true, Reason: "name+size+sample"}
	}
	return Result{Match: false, Reason: "none"}
}

// --- Conventional aliases ---

// SourceMatch is an alias-style entry point for Match.
func SourceMatch(args ...interface{}) Result {
	return matchVariadic(args)
}

// MatchSources is an alias-style entry point for Match.
func MatchSources(args ...interface{}) Result {
	return matchVariadic(args)
}

// MatchCandidates is an alias-style entry point for Match.
func MatchCandidates(args ...interface{}) Result {
	return matchVariadic(args)
}

func matchVariadic(args []interface{}) Result {
	var cands []Candidate
	var samples []Sample
	for _, a := range args {
		switch x := a.(type) {
		case Candidate:
			cands = append(cands, x)
		case Sample:
			samples = append(samples, x)
		}
	}
	var a, b Candidate
	if len(cands) > 0 {
		a = cands[0]
	}
	if len(cands) > 1 {
		b = cands[1]
	}
	var sa, sb Sample
	if len(samples) > 0 {
		sa = samples[0]
	}
	if len(samples) > 1 {
		sb = samples[1]
	}
	return Match(a, b, sa, sb)
}

// NewCandidate constructs a Candidate. Positional arguments map to
// Name, Size, Network, Hash, HashAlgo in order; a lone Candidate argument is
// returned as-is.
func NewCandidate(args ...interface{}) Candidate {
	if len(args) == 1 {
		if c, ok := args[0].(Candidate); ok {
			return c
		}
	}
	var c Candidate
	// Positional mapping.
	pos := 0
	for _, a := range args {
		switch pos {
		case 0:
			c.Name = toString(a)
			pos++
		case 1:
			c.Size = toUint64(a)
			pos++
		case 2:
			c.Network = toString(a)
			pos++
		case 3:
			c.Hash = toString(a)
			pos++
		case 4:
			c.HashAlgo = toString(a)
			pos++
		default:
			pos++
		}
	}
	return c
}

// NewSample constructs a Sample. []byte arguments fill Head then Tail in
// order; a numeric argument sets Size.
func NewSample(args ...interface{}) Sample {
	if len(args) == 1 {
		if s, ok := args[0].(Sample); ok {
			return s
		}
	}
	var s Sample
	headSet := false
	for _, a := range args {
		switch v := a.(type) {
		case Sample:
			return v
		case []byte:
			if !headSet {
				s.Head = v
				headSet = true
			} else {
				s.Tail = v
			}
		case string:
			b := []byte(v)
			if !headSet {
				s.Head = b
				headSet = true
			} else {
				s.Tail = b
			}
		default:
			s.Size = toUint64(v)
		}
	}
	return s
}

func toString(v interface{}) string {
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(v)
	}
}

func toUint64(v interface{}) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint:
		return uint64(x)
	case uint32:
		return uint64(x)
	case uint16:
		return uint64(x)
	case uint8:
		return uint64(x)
	case int:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case int64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case int32:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case float64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case float32:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case string:
		// best-effort parse
		var n uint64
		fmt.Sscan(x, &n)
		return n
	default:
		return 0
	}
}
