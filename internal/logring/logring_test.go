// SPDX-License-Identifier: GPL-3.0-or-later

package logring

import (
	"fmt"
	"regexp"
	"sync"
	"testing"
)

func TestBoundedDropsOldest(t *testing.T) {
	r := New(1000)
	for i := 0; i < 3000; i++ {
		if _, err := r.Write([]byte(fmt.Sprintf("%d\n", i))); err != nil {
			t.Fatalf("Write: %v", err)
		}
	}
	lines := r.Lines(0)
	if len(lines) != 1000 {
		t.Fatalf("Lines() = %d lines, want 1000", len(lines))
	}
	if lines[0] != "2000" {
		t.Errorf("oldest kept line = %q, want 2000 (oldest must be dropped)", lines[0])
	}
	if lines[len(lines)-1] != "2999" {
		t.Errorf("newest line = %q, want 2999", lines[len(lines)-1])
	}
}

func TestLinesLimitReturnsNewest(t *testing.T) {
	r := New(10)
	for i := 0; i < 10; i++ {
		r.Write([]byte(fmt.Sprintf("line %d\n", i)))
	}
	got := r.Lines(3)
	want := []string{"line 7", "line 8", "line 9"}
	if len(got) != len(want) {
		t.Fatalf("Lines(3) = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Lines(3)[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestPartialLinesAreBuffered(t *testing.T) {
	r := New(10)
	r.Write([]byte("a\nb\nc")) // c has no newline yet
	if got := r.Lines(0); len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Fatalf("Lines() after partial write = %v, want [a b]", got)
	}
	r.Write([]byte("d\n"))
	got := r.Lines(0)
	want := []string{"a", "b", "cd"} // completion joins the unterminated line
	if len(got) != len(want) {
		t.Fatalf("Lines() = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("Lines()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestCRLFIsStripped(t *testing.T) {
	r := New(2)
	r.Write([]byte("x\r\ny\r\n"))
	got := r.Lines(0)
	if len(got) != 2 || got[0] != "x" || got[1] != "y" {
		t.Fatalf("Lines() = %q, want [x y]", got)
	}
}

func TestEmptyLinesAreSkipped(t *testing.T) {
	r := New(5)
	r.Write([]byte("\n\nhello\n\n"))
	got := r.Lines(0)
	if len(got) != 1 || got[0] != "hello" {
		t.Fatalf("Lines() = %q, want [hello]", got)
	}
}

func TestWriteIsConcurrentAndBounded(t *testing.T) {
	r := New(64)
	var wg sync.WaitGroup
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < 500; i++ {
				if _, err := r.Write([]byte(fmt.Sprintf("g%d %d\n", g, i))); err != nil {
					t.Errorf("Write: %v", err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	if n := r.Len(); n > 64 {
		t.Fatalf("Len() = %d, want <= 64", n)
	}
	// Every retained line must be intact and from a valid goroutine: a torn
	// write would interleave chunks or leave a half line. Eviction of most
	// lines is the point of the bound, so nothing asserts a specific
	// goroutine survives.
	re := regexp.MustCompile(`^g[0-7] [0-9]+$`)
	for _, line := range r.Lines(0) {
		if !re.MatchString(line) {
			t.Errorf("retained line %q is not a whole, well-formed write", line)
		}
	}
}
