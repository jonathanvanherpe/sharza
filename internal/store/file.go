// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
)

// FileStore is a dependency-free Store backed by a single JSON file.
//
// It exists to prove the control-plane contract during P0, before the SQLite
// driver is approved. SQLite is a human gate (new dependency), so this stands
// in rather than being reached around. It is deliberately not a performance
// store: every mutation rewrites the whole file under a lock.
type FileStore struct {
	mu sync.RWMutex

	path     string
	schema   *Schema
	jobs     map[string]Job
	order    []string
	settings map[string]string
	closed   bool
}

// FileStoreOptions configures Open.
type FileStoreOptions struct {
	// Path is the JSON file to hold state.
	Path string
}

type fileFormat struct {
	SchemaVersion int               `json:"schema_version"`
	Jobs          []Job             `json:"jobs"`
	Settings      map[string]string `json:"settings"`
}

var _ Store = (*FileStore)(nil)

// Open loads or creates a FileStore, running migrations.
func Open(opts FileStoreOptions) (*FileStore, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("store: path is required")
	}

	s := &FileStore{
		path:     opts.Path,
		schema:   &Schema{},
		jobs:     map[string]Job{},
		settings: map[string]string{},
	}

	if err := s.load(); err != nil {
		return nil, err
	}

	migrated, err := migrate(s.schema)
	if err != nil {
		return nil, fmt.Errorf("store %s: %w", opts.Path, err)
	}
	wasAt := s.schema.version
	s.schema = migrated
	if migrated.version != wasAt {
		if err := s.persist(); err != nil {
			return nil, err
		}
	}
	return s, nil
}

func (s *FileStore) load() error {
	data, err := os.ReadFile(s.path)
	if os.IsNotExist(err) {
		s.schema = &Schema{}
		return nil
	}
	if err != nil {
		return fmt.Errorf("store %s: %w", s.path, err)
	}
	if len(data) == 0 {
		s.schema = &Schema{}
		return nil
	}

	var f fileFormat
	if err := json.Unmarshal(data, &f); err != nil {
		return fmt.Errorf("store %s: corrupt state file: %w", s.path, err)
	}

	s.schema = &Schema{version: f.SchemaVersion}
	for _, j := range f.Jobs {
		if err := j.Validate(); err != nil {
			return fmt.Errorf("store %s: %w", s.path, err)
		}
		s.jobs[j.ID] = j
		s.order = append(s.order, j.ID)
	}
	if f.Settings != nil {
		s.settings = f.Settings
	}
	return nil
}

func (s *FileStore) persist() error {
	f := fileFormat{
		SchemaVersion: s.schema.version,
		Jobs:          s.jobsLocked(),
		Settings:      s.settingsLocked(),
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return fmt.Errorf("store %s: encode: %w", s.path, err)
	}

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("store %s: %w", s.path, err)
	}

	// Write to a sibling temp file and rename, so a crash mid-write cannot
	// leave a half-written state file where a valid one used to be.
	tmp, err := os.CreateTemp(dir, filepath.Base(s.path)+".tmp*")
	if err != nil {
		return fmt.Errorf("store %s: %w", s.path, err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("store %s: %w", s.path, err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return fmt.Errorf("store %s: sync: %w", s.path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("store %s: close: %w", s.path, err)
	}
	if err := os.Chmod(tmpName, 0o600); err != nil {
		return fmt.Errorf("store %s: chmod: %w", s.path, err)
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("store %s: rename: %w", s.path, err)
	}
	return nil
}

func (s *FileStore) jobsLocked() []Job {
	out := make([]Job, 0, len(s.jobs))
	for _, id := range s.order {
		j, ok := s.jobs[id]
		if !ok || j.State == StateRemoved {
			continue
		}
		out = append(out, j)
	}
	slices.SortFunc(out, func(a, b Job) int {
		if a.ID < b.ID {
			return -1
		}
		if a.ID > b.ID {
			return 1
		}
		return 0
	})
	return out
}

func (s *FileStore) settingsLocked() map[string]string {
	out := make(map[string]string, len(s.settings))
	for k, v := range s.settings {
		out[k] = v
	}
	return out
}

func (s *FileStore) Jobs() ([]Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	return s.jobsLocked(), nil
}

func (s *FileStore) Job(id string) (Job, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return Job{}, ErrClosed
	}
	j, ok := s.jobs[id]
	if !ok || j.State == StateRemoved {
		return Job{}, fmt.Errorf("job %s: %w", id, ErrNotFound)
	}
	return j, nil
}

func (s *FileStore) AddJob(j Job) error {
	if err := j.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	if existing, ok := s.jobs[j.ID]; ok && existing.State != StateRemoved {
		return fmt.Errorf("job %s: %w", j.ID, ErrAlreadyExists)
	}
	s.jobs[j.ID] = j
	s.order = append(s.order, j.ID)
	return s.persist()
}

func (s *FileStore) UpdateJob(j Job) error {
	if err := j.Validate(); err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	existing, ok := s.jobs[j.ID]
	if !ok || existing.State == StateRemoved {
		return fmt.Errorf("job %s: %w", j.ID, ErrNotFound)
	}
	if existing.State.Terminal() && !j.State.Terminal() {
		return fmt.Errorf("job %s: cannot leave terminal state %q for %q",
			j.ID, existing.State, j.State)
	}
	s.jobs[j.ID] = j
	return s.persist()
}

func (s *FileStore) RemoveJob(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	j, ok := s.jobs[id]
	if !ok || j.State == StateRemoved {
		return fmt.Errorf("job %s: %w", id, ErrNotFound)
	}
	j.State = StateRemoved
	s.jobs[id] = j
	return s.persist()
}

func (s *FileStore) Setting(key string) (string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return "", ErrClosed
	}
	v, ok := s.settings[key]
	if !ok {
		return "", fmt.Errorf("setting %s: %w", key, ErrNotFound)
	}
	return v, nil
}

func (s *FileStore) SetSetting(key, value string) error {
	if key == "" {
		return fmt.Errorf("store: empty setting key")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return ErrClosed
	}
	s.settings[key] = value
	return s.persist()
}

func (s *FileStore) Settings() (map[string]string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil, ErrClosed
	}
	return s.settingsLocked(), nil
}

func (s *FileStore) SchemaVersion() (int, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return 0, ErrClosed
	}
	return s.schema.version, nil
}

func (s *FileStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	return nil
}
