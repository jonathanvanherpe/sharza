// SPDX-License-Identifier: GPL-3.0-or-later

package supervisor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/role"
	"github.com/jonathanvanherpe/sharza/internal/rpc"
	"github.com/jonathanvanherpe/sharza/internal/store"
)

// harness is a running supervisor with a connected client.
type harness struct {
	t      *testing.T
	client *rpc.Client
	svc    *Service
	st     store.Store
	path   string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	dir := t.TempDir()
	st, err := store.Open(store.FileStoreOptions{
		Path: filepath.Join(dir, "state.json"),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	d := rpc.NewDispatcher()
	svc := New(st, d)

	path := filepath.Join(dir, "c.sock")
	srv := rpc.NewServer(d, path)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()

	c, err := rpc.Dial(path, 2*time.Second)
	if err != nil {
		t.Fatalf("Dial: %v", err)
	}

	h := &harness{t: t, client: c, svc: svc, st: st, path: path}
	t.Cleanup(func() {
		_ = c.Close()
		_ = srv.Close()
		_ = st.Close()
		cancel()
	})
	return h
}

func (h *harness) call(method string, params any, out any) error {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return h.client.Call(ctx, method, params, out)
}

func TestStatusReportsSupervisorAndSchema(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	var st Status
	if err := h.call(rpc.MethodStatus, nil, &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	if st.Role != role.Supervisor {
		t.Errorf("role = %q, want supervisor", st.Role)
	}
	if st.SchemaVersion != store.LatestVersion() {
		t.Errorf("schema_version = %d, want %d", st.SchemaVersion, store.LatestVersion())
	}
	if st.PID != selfPID() {
		t.Errorf("pid = %d, want %d", st.PID, selfPID())
	}
	if st.Version == "" {
		t.Error("version is blank; clients need it to report bugs")
	}
	// Every worker role must be listed even before it is running, so the
	// UI can distinguish "not started yet" from "unsupported role".
	if len(st.Workers) != len(role.WorkerRoles()) {
		t.Errorf("workers = %d entries, want %d", len(st.Workers), len(role.WorkerRoles()))
	}
}

func TestRolesAdvertisement(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	var r RolesReply
	if err := h.call(rpc.MethodRoles, nil, &r); err != nil {
		t.Fatalf("roles: %v", err)
	}
	if len(r.Available) != len(role.All()) {
		t.Errorf("available = %v, want %v", r.Available, role.All())
	}
	if len(r.Workers) != len(role.WorkerRoles()) {
		t.Errorf("workers = %v, want %v", r.Workers, role.WorkerRoles())
	}
}

func TestJobLifecycleOverRPC(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	var added AddJobReply
	if err := h.call(rpc.MethodJobsAdd, AddJobParams{
		Name:     "ubuntu.iso",
		Size:     1000,
		URIs:     []string{"magnet:?xt=urn:btih:deadbeef"},
		Verified: true,
	}, &added); err != nil {
		t.Fatalf("add: %v", err)
	}
	if added.Job.State != store.StateQueued {
		t.Errorf("new job state = %q, want queued", added.Job.State)
	}
	if added.Job.ID == "" {
		t.Fatal("server generated no job id")
	}
	if !added.Job.Verified {
		t.Error("verified flag lost on a content-hashed source")
	}
	id := added.Job.ID

	var listed []store.Job
	if err := h.call(rpc.MethodJobsList, nil, &listed); err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(listed) != 1 || listed[0].ID != id {
		t.Fatalf("list = %+v, want one job %s", listed, id)
	}

	for _, tc := range []struct {
		method string
		want   store.State
	}{
		{rpc.MethodJobsPause, store.StatePaused},
		{rpc.MethodJobsResume, store.StateQueued},
	} {
		var rep JobReply
		if err := h.call(tc.method, jobIDParams{ID: id}, &rep); err != nil {
			t.Fatalf("%s: %v", tc.method, err)
		}
		if rep.Job.State != tc.want {
			t.Errorf("%s: state = %q, want %q", tc.method, rep.Job.State, tc.want)
		}
	}

	var rem JobReply
	if err := h.call(rpc.MethodJobsRemove, jobIDParams{ID: id}, &rem); err != nil {
		t.Fatalf("remove: %v", err)
	}
	if rem.Job.State != store.StateRemoved {
		t.Errorf("remove: state = %q, want removed", rem.Job.State)
	}

	if err := h.call(rpc.MethodJobsList, nil, &listed); err != nil {
		t.Fatalf("list after remove: %v", err)
	}
	if len(listed) != 0 {
		t.Errorf("list after remove = %+v, want empty", listed)
	}
}

func TestAddRequiresURIs(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	err := h.call(rpc.MethodJobsAdd, AddJobParams{Name: "nothing"}, nil)
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != rpc.CodeInvalidParams {
		t.Errorf("add without uris = %v, want InvalidParams", err)
	}
}

func TestAddRejectsNegativeSize(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	err := h.call(rpc.MethodJobsAdd, AddJobParams{
		Size: -1, URIs: []string{"magnet:?x"},
	}, nil)
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != rpc.CodeInvalidParams {
		t.Errorf("add with negative size = %v, want InvalidParams", err)
	}
}

// A Gnutella-only job has no content hash, so claiming verification would be
// a lie the UI then repeats to the user.
func TestAddCannotSelfDeclareVerifiedWithoutEvidence(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	var rep AddJobReply
	if err := h.call(rpc.MethodJobsAdd, AddJobParams{
		Name:     "gnutella-only.bin",
		URIs:     []string{"g2://cid:0123456789abcdef"},
		Verified: true,
	}, &rep); err != nil {
		t.Fatalf("add: %v", err)
	}
	if rep.Job.Verified {
		t.Error("server accepted a self-declared verified job with no hash evidence")
	}
}

func TestMutationsOnMissingJobReportPrecondition(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	for _, m := range []string{
		rpc.MethodJobsPause, rpc.MethodJobsResume, rpc.MethodJobsRemove,
	} {
		err := h.call(m, jobIDParams{ID: "ghost"}, nil)
		var re *rpc.Error
		if !errors.As(err, &re) || re.Code != rpc.CodeFailedPrecond {
			t.Errorf("%s on a missing job = %v, want FailedPrecond", m, err)
		}
	}
}

func TestMutationsRequireID(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	for _, m := range []string{
		rpc.MethodJobsPause, rpc.MethodJobsResume, rpc.MethodJobsRemove,
	} {
		err := h.call(m, jobIDParams{}, nil)
		var re *rpc.Error
		if !errors.As(err, &re) || re.Code != rpc.CodeInvalidParams {
			t.Errorf("%s with no id = %v, want InvalidParams", m, err)
		}
	}
}

func TestCannotPauseCompletedJob(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	var added AddJobReply
	if err := h.call(rpc.MethodJobsAdd, AddJobParams{
		Name: "done.bin", Size: 10, URIs: []string{"magnet:?x"},
	}, &added); err != nil {
		t.Fatalf("add: %v", err)
	}

	j := added.Job
	j.State = store.StateCompleted
	if err := h.st.UpdateJob(j); err != nil {
		t.Fatalf("mark complete: %v", err)
	}

	err := h.call(rpc.MethodJobsPause, jobIDParams{ID: added.Job.ID}, nil)
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != rpc.CodeFailedPrecond {
		t.Errorf("pause completed job = %v, want FailedPrecond", err)
	}
}

func TestAddDuplicateIDIsRejected(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	p := AddJobParams{ID: "fixed-id", Name: "a.bin", URIs: []string{"magnet:?x"}}
	if err := h.call(rpc.MethodJobsAdd, p, nil); err != nil {
		t.Fatalf("first add: %v", err)
	}
	// A retry with the same id must fail loudly, not create a second job.
	err := h.call(rpc.MethodJobsAdd, p, nil)
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != rpc.CodeFailedPrecond {
		t.Errorf("duplicate add = %v, want FailedPrecond", err)
	}
}

func TestWorkerReporting(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	h.svc.ReportWorker(role.BT, 1234, true)
	h.svc.ReportWorker(role.ED2K, 1235, true)

	var st Status
	if err := h.call(rpc.MethodStatus, nil, &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	byRole := map[role.Role]WorkerStatus{}
	for _, w := range st.Workers {
		byRole[w.Role] = w
	}
	if w := byRole[role.BT]; !w.Alive || w.PID != 1234 {
		t.Errorf("bt worker = %+v, want alive pid 1234", w)
	}
	if w := byRole[role.G2]; w.Alive {
		t.Errorf("g2 worker = %+v, want not alive: never reported", w)
	}

	// A restart must be counted, because a worker that crash-loops looks
	// healthy in a liveness check alone.
	h.svc.ReportWorker(role.BT, 9999, false)
	h.svc.ReportWorker(role.BT, 9999, true)
	if err := h.call(rpc.MethodStatus, nil, &st); err != nil {
		t.Fatalf("status after restart: %v", err)
	}
	for _, w := range st.Workers {
		if w.Role == role.BT {
			if w.Rests != 1 || w.PID != 9999 || !w.Alive {
				t.Errorf("bt after restart = %+v, want rests=1 pid=9999 alive", w)
			}
		}
	}
}

// The P0 exit gate: state survives a restart of the daemon.
func TestStateSurvivesSupervisorRestart(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	statePath := filepath.Join(dir, "state.json")

	// First supervisor: create a job.
	{
		st, err := store.Open(store.FileStoreOptions{Path: statePath})
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		d := rpc.NewDispatcher()
		New(st, d)
		path := filepath.Join(dir, "c1.sock")
		srv := rpc.NewServer(d, path)
		if err := srv.Listen(); err != nil {
			t.Fatalf("listen: %v", err)
		}
		ctx, cancel := context.WithCancel(context.Background())
		go func() { _ = srv.Serve(ctx) }()

		c, err := rpc.Dial(path, 2*time.Second)
		if err != nil {
			t.Fatalf("dial: %v", err)
		}
		callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
		err = c.Call(callCtx, rpc.MethodJobsAdd, AddJobParams{
			Name: "persist-me.iso", Size: 42, URIs: []string{"magnet:?x"}, Verified: true,
		}, nil)
		callCancel()
		if err != nil {
			t.Fatalf("add: %v", err)
		}
		_ = c.Close()
		_ = srv.Close()
		_ = st.Close()
		cancel()
	}

	// Second supervisor on the same state: the job must still be there.
	st, err := store.Open(store.FileStoreOptions{Path: statePath})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	defer st.Close()
	d := rpc.NewDispatcher()
	New(st, d)
	path := filepath.Join(dir, "c2.sock")
	srv := rpc.NewServer(d, path)
	if err := srv.Listen(); err != nil {
		t.Fatalf("listen 2: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = srv.Serve(ctx) }()
	defer srv.Close()

	c, err := rpc.Dial(path, 2*time.Second)
	if err != nil {
		t.Fatalf("dial 2: %v", err)
	}
	defer c.Close()

	callCtx, callCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer callCancel()
	var jobs []store.Job
	if err := c.Call(callCtx, rpc.MethodJobsList, nil, &jobs); err != nil {
		t.Fatalf("list after restart: %v", err)
	}
	if len(jobs) != 1 || jobs[0].Name != "persist-me.iso" || jobs[0].Size != 42 {
		t.Errorf("jobs after restart = %+v, want the single 42-byte persist-me.iso", jobs)
	}
}

func TestSocketPathIsUnreachableAfterServerClose(t *testing.T) {
	t.Parallel()
	// Covered in the rpc package, where the server is constructed directly;
	// repeating it here would only exercise the test harness.
	t.Skip("covered by TestClosedServerRefusesConnections in internal/rpc")
}

func TestNewJobIDIsUnique(t *testing.T) {
	t.Parallel()
	seen := map[string]bool{}
	for i := 0; i < 1000; i++ {
		id := NewJobID()
		if id == "" {
			t.Fatal("empty job id")
		}
		if seen[id] {
			t.Fatalf("duplicate job id %s after %d draws", id, i)
		}
		seen[id] = true
	}
}

func TestReportWorkerUnknownRoleIsIgnoredNotPanicked(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	// A stale report from a role this build dropped must not corrupt state.
	h.svc.ReportWorker(role.Role("legacy"), 1, true)

	var st Status
	if err := h.call(rpc.MethodStatus, nil, &st); err != nil {
		t.Fatalf("status: %v", err)
	}
	if len(st.Workers) != len(role.WorkerRoles()) {
		t.Errorf("workers = %d, want %d", len(st.Workers), len(role.WorkerRoles()))
	}
}

func TestStateFilePermissionsAreOwnerOnly(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	if err := h.call(rpc.MethodJobsAdd, AddJobParams{
		Name: "secret.bin", URIs: []string{"magnet:?x"},
	}, nil); err != nil {
		t.Fatalf("add: %v", err)
	}
	_ = h.st.Close()

	fi, err := os.Stat(filepath.Join(filepath.Dir(h.path), "state.json"))
	if err != nil {
		t.Fatalf("stat state file: %v", err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("state file mode = %04o, want 0600: it holds the user's whole queue", perm)
	}
}

func TestDecodeParamsRejectsGarbage(t *testing.T) {
	t.Parallel()
	var out struct{ A int }
	err := decodeParams(json.RawMessage(`{"A":`), &out)
	var re *rpc.Error
	if !errors.As(err, &re) || re.Code != rpc.CodeInvalidParams {
		t.Errorf("decode garbage = %v, want InvalidParams", err)
	}
	if err := decodeParams(nil, &out); err == nil {
		t.Error("decode nil params = nil, want error")
	}
}
func TestVerifiedOnlyForHashedSources(t *testing.T) {
	t.Parallel()
	cases := map[string]bool{
		"magnet:?xt=urn:btih:0123456789abcdef":                 true,
		"magnet:?dn=x&xt=urn:btmh:1220aaaa":                    true,
		"bitinfohash:0123456789abcdef":                         true,
		"urn:btih:0123456789abcdef":                            true,
		"ed2k://|file|de-k9jc7nc0ckd7l6m1n3x0dgwuz2f7hk|1234|": true,
		"https://example.org/x.torrent":                        true,
		"http://example.org/x.torrent":                         true,
		"g2://cid:0123456789abcdef":                            false,
		"gnutella://0123456789abcdef":                          false,
		"g1://0123456789abcdef":                                false,
		"https://example.org/file.iso":                         false,
		"":                                                     false,
	}
	for uri, want := range cases {
		if got := uriHashed(uri); got != want {
			t.Errorf("uriHashed(%q) = %v, want %v", uri, got, want)
		}
	}
}

func TestAllSourcesHashedRequiresEverySource(t *testing.T) {
	t.Parallel()
	// One unhashed source makes the whole job unverifiable: the bytes may
	// come from whichever source won, not just the hashed one.
	if allSourcesHashed([]string{"magnet:?xt=urn:btih:aa", "g2://cid:bb"}) {
		t.Error("a mixed source set was called hashed")
	}
	if allSourcesHashed(nil) {
		t.Error("empty source set was called hashed")
	}
	if !allSourcesHashed([]string{"magnet:?xt=urn:btih:aa", "magnet:?xt=urn:btih:bb"}) {
		t.Error("two hashed sources were not called hashed")
	}
}
