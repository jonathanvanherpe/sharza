// SPDX-License-Identifier: GPL-3.0-or-later

package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/logring"
	"github.com/jonathanvanherpe/sharza/internal/rpc"
	"github.com/jonathanvanherpe/sharza/internal/store"
	"github.com/jonathanvanherpe/sharza/internal/supervisor"
	"github.com/jonathanvanherpe/sharza/internal/version"
)

// testDaemon is a full control plane served in process: store, service, RPC
// server on a temp socket, and the web mux on an httptest server. It exists so
// the HTTP-to-RPC proxy is proven end to end without spawning processes.
type testDaemon struct {
	ts   *httptest.Server
	st   store.Store
	svc  *supervisor.Service
	ring *logring.Ring
}

func newTestDaemon(t *testing.T) *testDaemon {
	t.Helper()

	st, err := store.Open(store.FileStoreOptions{
		Path: filepath.Join(t.TempDir(), "state.json"),
	})
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}

	disp := rpc.NewDispatcher()
	svc := supervisor.New(st, disp)

	sock := filepath.Join(t.TempDir(), "c.sock")
	srv := rpc.NewServer(disp, sock)
	if err := srv.Listen(); err != nil {
		t.Fatalf("Listen: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	go func() { _ = srv.Serve(ctx) }()

	ring := logring.New(100)
	svc.AttachLogs(ring)

	ts := httptest.NewServer(NewMux(sock))

	t.Cleanup(func() {
		ts.Close()
		_ = srv.Close()
		_ = st.Close()
		cancel()
	})
	return &testDaemon{ts: ts, st: st, svc: svc, ring: ring}
}

// get decodes a GET response body, failing the test if the status is
// unexpected. The kind of body varies by endpoint: status and jobs mutations
// are objects, the jobs list is an array.
func (d *testDaemon) get(t *testing.T, path string, wantCode int) any {
	t.Helper()
	r, err := http.Get(d.ts.URL + path)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer r.Body.Close()
	if r.StatusCode != wantCode {
		t.Fatalf("GET %s = %d, want %d", path, r.StatusCode, wantCode)
	}
	var body any
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		t.Fatalf("GET %s: decode body: %v", path, err)
	}
	return body
}

// post sends a POST with an optional JSON body.
func (d *testDaemon) post(t *testing.T, path, body string, wantCode int) any {
	t.Helper()
	req, err := http.NewRequest(http.MethodPost, d.ts.URL+path, strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	if body != "" {
		req.Header.Set("Content-Type", "application/json")
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("POST %s: %v", path, err)
	}
	defer r.Body.Close()
	if r.StatusCode != wantCode {
		t.Fatalf("POST %s = %d, want %d", path, r.StatusCode, wantCode)
	}
	if r.StatusCode == http.StatusNoContent {
		return nil
	}
	var out any
	if err := json.NewDecoder(r.Body).Decode(&out); err != nil {
		t.Fatalf("POST %s: decode body: %v", path, err)
	}
	return out
}

func TestStatusEndpoint(t *testing.T) {
	d := newTestDaemon(t)

	body := d.get(t, "/api/status", http.StatusOK).(map[string]any)

	if body["version"] != version.Version {
		t.Errorf("version = %v, want %s", body["version"], version.Version)
	}
	if body["role"] != "supervisor" {
		t.Errorf("role = %v, want supervisor", body["role"])
	}
	workers, ok := body["workers"].([]any)
	if !ok || len(workers) != 3 {
		t.Errorf("workers = %v, want three entries", body["workers"])
	}
	if body["jobs"] != float64(0) {
		t.Errorf("jobs = %v, want 0", body["jobs"])
	}
}

func TestAddPauseResumeRemoveViaAPI(t *testing.T) {
	d := newTestDaemon(t)

	// Add.
	added := d.post(t, "/api/jobs",
		`{"name":"a.bin","uris":["magnet:?xt=urn:btih:x"]}`, http.StatusOK).(map[string]any)
	job, _ := added["job"].(map[string]any)
	id, _ := job["id"].(string)
	if id == "" {
		t.Fatalf("add reply = %v, want a job id", added)
	}
	if job["state"] != "queued" {
		t.Errorf("new job state = %v, want queued", job["state"])
	}

	// Pause.
	paused := d.post(t, "/api/jobs/"+id+"/pause", "", http.StatusOK).(map[string]any)
	if paused["job"].(map[string]any)["state"] != "paused" {
		t.Errorf("paused job = %v, want paused", paused["job"])
	}

	// Resume.
	resumed := d.post(t, "/api/jobs/"+id+"/resume", "", http.StatusOK).(map[string]any)
	if resumed["job"].(map[string]any)["state"] != "queued" {
		t.Errorf("resumed job = %v, want queued", resumed["job"])
	}

	// Remove: the job leaves the list, because removed jobs are unpublished.
	d.post(t, "/api/jobs/"+id+"/remove", "", http.StatusOK)
	if jobs := d.get(t, "/api/jobs", http.StatusOK).([]any); len(jobs) != 0 {
		t.Errorf("jobs after remove = %d, want 0 (removed must not be listed)", len(jobs))
	}
}

func TestBadJobBodyIsBadRequest(t *testing.T) {
	d := newTestDaemon(t)

	d.post(t, "/api/jobs", `{not json`, http.StatusBadRequest)
	d.post(t, "/api/jobs", `{"uris":[]}`, http.StatusBadRequest)
}

func TestJobsEndpointListsStoreJobs(t *testing.T) {
	d := newTestDaemon(t)

	if err := d.st.AddJob(store.Job{ID: "j1", Name: "one", State: store.StateQueued}); err != nil {
		t.Fatalf("AddJob: %v", err)
	}
	jobs := d.get(t, "/api/jobs", http.StatusOK).([]any)
	if len(jobs) != 1 {
		t.Fatalf("jobs = %v, want one entry", jobs)
	}
}

func TestRolesMutateWithoutSupervisorFails(t *testing.T) {
	d := newTestDaemon(t)

	// No worker set is attached in this harness, so the toggles must answer
	// with a conflict the UI can show, not pretend a pause happened.
	for _, path := range []string{"/api/roles/bt/pause", "/api/roles/bt/resume"} {
		r := d.post(t, path, "", http.StatusConflict).(map[string]any)
		if !strings.Contains(r["error"].(string), "supervisor") {
			t.Errorf("POST %s error = %v, want it to name the missing supervisor", path, r["error"])
		}
	}
}

func TestLogsEndpointReturnsRingLines(t *testing.T) {
	d := newTestDaemon(t)

	if _, err := d.ring.Write([]byte("one\ntwo\nthree\n")); err != nil {
		t.Fatalf("ring write: %v", err)
	}
	body := d.get(t, "/api/logs?limit=10", http.StatusOK).(map[string]any)
	lines, ok := body["lines"].([]any)
	if !ok || len(lines) != 3 {
		t.Fatalf("lines = %v, want three", body["lines"])
	}
	if lines[0] != "one" || lines[2] != "three" {
		t.Errorf("lines = %v, want [one two three] in order", lines)
	}

	// A bad limit is rejected before it reaches the daemon.
	req, err := http.NewRequest(http.MethodGet, d.ts.URL+"/api/logs?limit=banana", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /api/logs?limit=banana: %v", err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Errorf("GET /api/logs?limit=banana = %d, want 400", r.StatusCode)
	}
}

// The default tail (no limit param) must not error when the ring is empty.
func TestLogsEndpointWithEmptyRing(t *testing.T) {
	d := newTestDaemon(t)

	body := d.get(t, "/api/logs", http.StatusOK).(map[string]any)
	if lines, ok := body["lines"].([]any); !ok || len(lines) != 0 {
		t.Errorf("lines = %v, want []", body["lines"])
	}
}

// The static shell must still be served at / after the API grew.
func TestShellIsServed(t *testing.T) {
	d := newTestDaemon(t)

	r, err := http.Get(d.ts.URL + "/")
	if err != nil {
		t.Fatalf("GET /: %v", err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("GET / = %d, want 200", r.StatusCode)
	}
	if ct := r.Header.Get("Cache-Control"); ct != "no-store" {
		t.Errorf("Cache-Control = %q, want no-store", ct)
	}
}
