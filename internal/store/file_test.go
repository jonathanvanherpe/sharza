// SPDX-License-Identifier: GPL-3.0-or-later

package store

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func newStore(t *testing.T) (*FileStore, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "state.json")
	s, err := Open(FileStoreOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s, path
}

func mustAdd(t *testing.T, s *FileStore, j Job) {
	t.Helper()
	if err := s.AddJob(j); err != nil {
		t.Fatalf("AddJob(%s): %v", j.ID, err)
	}
}

func TestOpenCreatesSchemaAtLatestVersion(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	got, err := s.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if got != LatestVersion() {
		t.Errorf("schema version = %d, want %d", got, LatestVersion())
	}
	if LatestVersion() < 1 {
		t.Fatal("no migrations registered; the registry is empty")
	}
}

func TestAddAndGetJob(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	want := Job{ID: "j1", Name: "thing", State: StateQueued, Size: 10, Complete: 3,
		URIs: []string{"magnet:?xt=urn:btih:x"}}
	mustAdd(t, s, want)

	got, err := s.Job("j1")
	if err != nil {
		t.Fatalf("Job: %v", err)
	}
	if got.ID != want.ID || got.State != want.State || got.Complete != want.Complete {
		t.Errorf("Job = %+v, want %+v", got, want)
	}
	if len(got.URIs) != 1 || got.URIs[0] != want.URIs[0] {
		t.Errorf("Job URIs = %v, want %v", got.URIs, want.URIs)
	}
}

func TestAddRejectsDuplicate(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	mustAdd(t, s, Job{ID: "j1", State: StateQueued})

	err := s.AddJob(Job{ID: "j1", State: StateQueued})
	if !errors.Is(err, ErrAlreadyExists) {
		t.Errorf("AddJob duplicate = %v, want ErrAlreadyExists", err)
	}

	// A removed id must be reusable, otherwise a re-add of the same
	// torrent after a remove would fail forever.
	if err := s.RemoveJob("j1"); err != nil {
		t.Fatalf("RemoveJob: %v", err)
	}
	if err := s.AddJob(Job{ID: "j1", State: StateQueued}); err != nil {
		t.Errorf("re-add after remove = %v, want success", err)
	}
}

func TestGetMissingJob(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	if _, err := s.Job("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Job(missing) = %v, want ErrNotFound", err)
	}
}

func TestUpdateMissingJob(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	err := s.UpdateJob(Job{ID: "nope", State: StateRunning})
	if !errors.Is(err, ErrNotFound) {
		t.Errorf("UpdateJob(missing) = %v, want ErrNotFound", err)
	}
}

func TestCannotLeaveTerminalState(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	mustAdd(t, s, Job{ID: "j1", State: StateCompleted})

	// A completed job reverting to running would look like a lost download
	// to every client watching it.
	err := s.UpdateJob(Job{ID: "j1", State: StateRunning})
	if err == nil {
		t.Error("UpdateJob completed->running = nil, want rejection")
	}
}

func TestRemoveHidesFromListingAndLookup(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	mustAdd(t, s, Job{ID: "j1", State: StateQueued})
	mustAdd(t, s, Job{ID: "j2", State: StateQueued})

	if err := s.RemoveJob("j1"); err != nil {
		t.Fatalf("RemoveJob: %v", err)
	}

	jobs, err := s.Jobs()
	if err != nil {
		t.Fatalf("Jobs: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != "j2" {
		t.Errorf("Jobs = %+v, want only j2", jobs)
	}
	if _, err := s.Job("j1"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Job(removed) = %v, want ErrNotFound", err)
	}
}

func TestRemoveMissingJob(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	if err := s.RemoveJob("nope"); !errors.Is(err, ErrNotFound) {
		t.Errorf("RemoveJob(missing) = %v, want ErrNotFound", err)
	}
}

func TestJobsSortedByID(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	for _, id := range []string{"c", "a", "b"} {
		mustAdd(t, s, Job{ID: id, State: StateQueued})
	}
	jobs, err := s.Jobs()
	if err != nil {
		t.Fatalf("Jobs: %v", err)
	}
	for i, want := range []string{"a", "b", "c"} {
		if jobs[i].ID != want {
			t.Fatalf("Jobs order = %+v, want a,b,c", jobs)
		}
	}
}

func TestValidateRejectsBadJobs(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	for name, j := range map[string]Job{
		"empty id":       {ID: "", State: StateQueued},
		"bad state":      {ID: "j", State: State("wat")},
		"negative bytes": {ID: "j", State: StateQueued, Complete: -1},
		"over complete":  {ID: "j", State: StateQueued, Size: 5, Complete: 6},
	} {
		if err := s.AddJob(j); err == nil {
			t.Errorf("AddJob(%s) = nil, want rejection", name)
		}
	}
}

func TestSettingsSnapshot(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	if err := s.SetSetting("dht", "off"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	v, err := s.Setting("dht")
	if err != nil {
		t.Fatalf("Setting: %v", err)
	}
	if v != "off" {
		t.Errorf("Setting(dht) = %q, want %q", v, "off")
	}

	snap, err := s.Settings()
	if err != nil {
		t.Fatalf("Settings: %v", err)
	}
	if snap["dht"] != "off" {
		t.Errorf("Settings snapshot = %v, want dht=off", snap)
	}

	// The snapshot must be a copy: mutating it cannot corrupt the store.
	snap["dht"] = "tampered"
	if again, _ := s.Settings(); again["dht"] != "off" {
		t.Errorf("settings mutated through the snapshot: %v", again)
	}
}

func TestMissingSetting(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	if _, err := s.Setting("absent"); !errors.Is(err, ErrNotFound) {
		t.Errorf("Setting(absent) = %v, want ErrNotFound", err)
	}
}

func TestEmptySettingKeyRejected(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	if err := s.SetSetting("", "x"); err == nil {
		t.Error("SetSetting(\"\") = nil, want rejection")
	}
}

// The P0 exit gate requires state to survive a restart.
func TestStateSurvivesRestart(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")

	first, err := Open(FileStoreOptions{Path: path})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	mustAdd(t, first, Job{
		ID: "j1", Name: "ubuntu.iso", State: StateRunning, Size: 1000, Complete: 400,
		URIs: []string{"magnet:?xt=urn:btih:abc"}, Verified: true,
	})
	if err := first.SetSetting("dht", "on"); err != nil {
		t.Fatalf("SetSetting: %v", err)
	}
	ver, err := first.SchemaVersion()
	if err != nil {
		t.Fatalf("SchemaVersion: %v", err)
	}
	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	second, err := Open(FileStoreOptions{Path: path})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer second.Close()

	j, err := second.Job("j1")
	if err != nil {
		t.Fatalf("Job after restart: %v", err)
	}
	if j.Complete != 400 || j.Size != 1000 || !j.Verified {
		t.Errorf("job after restart = %+v, want complete=400 size=1000 verified", j)
	}
	if len(j.URIs) != 1 {
		t.Errorf("URIs after restart = %v, want one entry", j.URIs)
	}
	if v, err := second.Setting("dht"); err != nil || v != "on" {
		t.Errorf("setting after restart = %q (%v), want on", v, err)
	}
	if got, _ := second.SchemaVersion(); got != ver {
		t.Errorf("schema version after restart = %d, want %d", got, ver)
	}
}

func TestCorruptStateFileIsReported(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "state.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	if _, err := Open(FileStoreOptions{Path: path}); err == nil {
		t.Error("Open on corrupt file = nil, want error")
	}
}

func TestOperationsAfterCloseFail(t *testing.T) {
	t.Parallel()
	s, _ := newStore(t)
	mustAdd(t, s, Job{ID: "j1", State: StateQueued})
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	if _, err := s.Jobs(); !errors.Is(err, ErrClosed) {
		t.Errorf("Jobs after Close = %v, want ErrClosed", err)
	}
	if _, err := s.Job("j1"); !errors.Is(err, ErrClosed) {
		t.Errorf("Job after Close = %v, want ErrClosed", err)
	}
	if err := s.AddJob(Job{ID: "j2", State: StateQueued}); !errors.Is(err, ErrClosed) {
		t.Errorf("AddJob after Close = %v, want ErrClosed", err)
	}
	if err := s.Close(); err != nil {
		t.Errorf("second Close = %v, want nil (idempotent)", err)
	}
}

func TestOpenRequiresPath(t *testing.T) {
	t.Parallel()
	if _, err := Open(FileStoreOptions{}); err == nil {
		t.Error("Open with empty path = nil, want error")
	}
}

func TestMigrateRefusesNewerSchema(t *testing.T) {
	t.Parallel()
	_, err := migrate(&Schema{version: LatestVersion() + 1})
	if err == nil {
		t.Error("migrate from a future version = nil, want error")
	}
}

func TestMigrateIsIdempotent(t *testing.T) {
	t.Parallel()
	once, err := migrate(&Schema{})
	if err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	twice, err := migrate(&Schema{version: once.version})
	if err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if twice.version != once.version {
		t.Errorf("second migrate moved %d -> %d, want no change",
			once.version, twice.version)
	}
}
