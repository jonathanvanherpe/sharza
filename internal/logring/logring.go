// SPDX-License-Identifier: GPL-3.0-or-later

// Package logring keeps a bounded buffer of recent log lines for the web UI
// to tail.
//
// The one hard rule is that a log sink must never block the process it is
// logging: a worker blocked on a full pipe is a daemon that dies in slow
// motion. Write therefore always succeeds and drops the oldest line instead
// of ever stalling the caller.
package logring

import (
	"strings"
	"sync"
)

// Ring is a fixed-capacity, concurrency-safe buffer of the newest lines.
type Ring struct {
	mu      sync.Mutex
	lines   []string
	max     int
	pending string
}

// New returns a Ring holding at most max lines.
func New(max int) *Ring {
	if max < 1 {
		max = 1
	}
	return &Ring{max: max}
}

// Write appends p to the ring as log lines, keeping at most the newest max.
// It implements io.Writer and never returns an error: logging must not fail
// the caller.
func (r *Ring) Write(p []byte) (int, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	chunk := r.pending + string(p)
	for len(chunk) > 0 {
		i := strings.IndexByte(chunk, '\n')
		if i < 0 {
			break
		}
		line := strings.TrimSuffix(chunk[:i], "\r")
		chunk = chunk[i+1:]
		if line != "" {
			r.append(line)
		}
	}
	r.pending = chunk
	return len(p), nil
}

// Lines returns up to limit of the newest lines, oldest first. A limit of 0
// or less returns everything the ring still holds.
func (r *Ring) Lines(limit int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	n := len(r.lines)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]string, 0, n)
	for i := len(r.lines) - n; i < len(r.lines); i++ {
		out = append(out, r.lines[i])
	}
	return out
}

// Len returns how many complete lines the ring holds.
func (r *Ring) Len() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.lines)
}

func (r *Ring) append(line string) {
	r.lines = append(r.lines, line)
	if len(r.lines) > r.max {
		r.lines = r.lines[len(r.lines)-r.max:]
	}
}
