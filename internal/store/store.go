// SPDX-License-Identifier: GPL-3.0-or-later

// Package store holds Sharza's authoritative state: jobs, settings and the
// migration mechanism that evolves the on-disk schema.
//
// The supervisor owns the only writable Store. Workers hold no state of their
// own and report upward, which is what makes "kill a worker" a non-event for
// the control plane.
package store

import (
	"errors"
	"fmt"
)

// ErrNotFound is returned when a lookup finds no such entity. Callers use it
// to distinguish "gone" from "broken", which matters because a missing job is
// a normal outcome of a race with another client.
var ErrNotFound = errors.New("not found")

// ErrClosed is returned once the store is closed.
var ErrClosed = errors.New("store is closed")

// State is the live job state, as opposed to configuration.
type State string

const (
	StateQueued    State = "queued"
	StateRunning   State = "running"
	StatePaused    State = "paused"
	StateCompleted State = "completed"
	StateFailed    State = "failed"
	StateRemoved   State = "removed"
)

// Valid reports whether s is a known state. An unrecognised state read back
// from disk is a bug, not a new value, so this is enforced on write.
func (s State) Valid() bool {
	switch s {
	case StateQueued, StateRunning, StatePaused, StateCompleted, StateFailed, StateRemoved:
		return true
	}
	return false
}

// Terminal reports whether the job can still change state on its own.
func (s State) Terminal() bool {
	return s == StateCompleted || s == StateFailed
}

// Job is one transfer. This is the union across every protocol, so it carries
// fields that only some networks populate; that is deliberate, because the
// cross-network swarming design needs one job identity, not one per protocol.
type Job struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	State    State  `json:"state"`
	Size     int64  `json:"size"`
	Complete int64  `json:"complete"`

	// URIs are the source locators as given by the client. Each protocol
	// keeps its own identifier alongside; see Source.
	URIs []string `json:"uris,omitempty"`

	// Sources are per-engine locators: e.g. a BT info hash and a piece
	// length, or an ed2k hash plus part count.
	Sources map[string]string `json:"sources,omitempty"`

	// Verified records whether the bytes are covered by a content hash.
	// A Gnutella-only job is false, and the UI must say so rather than
	// implying the same guarantee as a BitTorrent job.
	Verified bool `json:"verified"`

	Error string `json:"error,omitempty"`
}

// Validate checks a job for internal consistency. Called on write so a bad
// job cannot reach disk.
func (j *Job) Validate() error {
	if j.ID == "" {
		return fmt.Errorf("job has empty id")
	}
	if !j.State.Valid() {
		return fmt.Errorf("job %s: invalid state %q", j.ID, j.State)
	}
	if j.Complete < 0 {
		return fmt.Errorf("job %s: negative complete %d", j.ID, j.Complete)
	}
	if j.Size < 0 {
		return fmt.Errorf("job %s: negative size %d", j.ID, j.Size)
	}
	if j.Size > 0 && j.Complete > j.Size {
		return fmt.Errorf("job %s: complete %d exceeds size %d", j.ID, j.Complete, j.Size)
	}
	return nil
}

// Store is the supervisor's authoritative state.
//
// Implementations must be safe for concurrent use.
type Store interface {
	// Jobs returns all jobs not in StateRemoved, ordered by id.
	Jobs() ([]Job, error)

	// Job returns one job by id, or ErrNotFound.
	Job(id string) (Job, error)

	// AddJob inserts a new job. It returns ErrAlreadyExists if the id is
	// taken, so two clients racing to add the same job cannot silently
	// clobber each other.
	AddJob(j Job) error

	// UpdateJob replaces an existing job.
	UpdateJob(j Job) error

	// RemoveJob moves a job to StateRemoved rather than deleting the row,
	// so a client that is mid-poll sees the removal instead of a missing
	// id it cannot interpret.
	RemoveJob(id string) error

	// Setting reads one settings key.
	Setting(key string) (string, error)

	// SetSetting writes one settings key.
	SetSetting(key, value string) error

	// Settings returns the full settings snapshot.
	Settings() (map[string]string, error)

	// SchemaVersion reports the on-disk schema version after migrations.
	SchemaVersion() (int, error)

	// Close flushes and releases resources.
	Close() error
}

// ErrAlreadyExists is returned by AddJob for a duplicate id.
var ErrAlreadyExists = errors.New("already exists")
