// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"fmt"
	"sort"
)

// Migration is one forward, irreversible schema step.
//
// Migrations are identified by version and must be append-only: once a
// version has shipped, its body may never change, because a database already
// at that version will never run it again, and an existing install cannot be
// distinguished from a broken one.
type Migration struct {
	Version int
	Name    string

	// Up transforms state from Version-1 to Version. It is given the
	// current schema version so it can decide whether it applies.
	Up func(s *Schema) error
}

// Schema is the mutable shape a migration operates on. Keeping this concrete
// and small is deliberate: the alternative, a SQL string per migration, would
// make the migration sequence untestable without a database.
type Schema struct {
	version int
	fields  map[string]any
}

// Version reports the current schema version.
func (s *Schema) Version() int { return s.version }

// Set records a schema-level field, for introspection by later migrations.
func (s *Schema) Set(key string, value any) {
	if s.fields == nil {
		s.fields = map[string]any{}
	}
	s.fields[key] = value
}

// Get reads a schema-level field.
func (s *Schema) Get(key string) (any, bool) {
	v, ok := s.fields[key]
	return v, ok
}

func (s *Schema) clone() *Schema {
	c := &Schema{version: s.version, fields: make(map[string]any, len(s.fields))}
	for k, v := range s.fields {
		c.fields[k] = v
	}
	return c
}

// migrations is the append-only registry. New migrations are appended here.
var migrations = []Migration{
	{
		Version: 1,
		Name:    "initial",
		Up: func(s *Schema) error {
			s.Set("jobs", true)
			s.Set("settings", true)
			return nil
		},
	},
}

// LatestVersion is the version a fresh database is created at.
func LatestVersion() int {
	if len(migrations) == 0 {
		return 0
	}
	highest := 0
	for _, m := range migrations {
		if m.Version > highest {
			highest = m.Version
		}
	}
	return highest
}

// migrate brings a schema at from to the latest version, applying each
// intermediate migration in order. It returns a new Schema; the input is not
// modified, so a failed migration leaves the caller with the original state
// and a half-migrated database can be detected rather than assumed away.
func migrate(from *Schema) (*Schema, error) {
	ordered := make([]Migration, len(migrations))
	copy(ordered, migrations)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Version < ordered[j].Version })

	if from.version > LatestVersion() {
		return nil, fmt.Errorf(
			"database schema version %d is newer than this build supports (%d): "+
				"upgrade Sharza or point it at a different database",
			from.version, LatestVersion())
	}

	cur := from.clone()
	for _, m := range ordered {
		if m.Version <= cur.version {
			continue
		}
		if err := m.Up(cur); err != nil {
			return nil, fmt.Errorf("migration %d (%s): %w", m.Version, m.Name, err)
		}
		cur.version = m.Version
	}
	return cur, nil
}
