// SPDX-License-Identifier: GPL-3.0-or-later

package role

import "testing"

func TestParse(t *testing.T) {
	t.Parallel()
	for _, r := range All() {
		got, err := Parse(string(r))
		if err != nil {
			t.Errorf("Parse(%q) = error %v, want success", r, err)
			continue
		}
		if got != r {
			t.Errorf("Parse(%q) = %q, want %q", r, got, r)
		}
	}
}

func TestParseRejectsUnknown(t *testing.T) {
	t.Parallel()
	// An empty role must not silently default to supervisor: defaulting
	// would let a typo start a supervisor that spawns three workers.
	for _, bad := range []string{"", "Supervisor", "bt2", " root", "root"} {
		if _, err := Parse(bad); err == nil {
			t.Errorf("Parse(%q) = nil error, want failure", bad)
		}
	}
}

func TestParseErrorMentionsValidRoles(t *testing.T) {
	t.Parallel()
	_, err := Parse("nope")
	if err == nil {
		t.Fatal("expected error")
	}
	for _, r := range All() {
		if !contains(err.Error(), string(r)) {
			t.Errorf("error %q does not mention valid role %q", err, r)
		}
	}
}

func TestIsWorker(t *testing.T) {
	t.Parallel()
	if IsWorker(Supervisor) {
		t.Error("supervisor must not be a worker")
	}
	for _, r := range WorkerRoles() {
		if !IsWorker(r) {
			t.Errorf("%q must be a worker", r)
		}
	}
}

func TestAllHasNoDuplicates(t *testing.T) {
	t.Parallel()
	seen := map[Role]bool{}
	for _, r := range All() {
		if seen[r] {
			t.Errorf("duplicate role %q in All()", r)
		}
		seen[r] = true
	}
}

func TestWorkerRolesSubsetOfAll(t *testing.T) {
	t.Parallel()
	all := map[Role]bool{}
	for _, r := range All() {
		all[r] = true
	}
	for _, r := range WorkerRoles() {
		if !all[r] {
			t.Errorf("worker role %q missing from All()", r)
		}
	}
}

func contains(haystack, needle string) bool {
	return len(needle) == 0 || (len(haystack) >= len(needle) && indexOf(haystack, needle) >= 0)
}

func indexOf(h, n string) int {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return i
		}
	}
	return -1
}
