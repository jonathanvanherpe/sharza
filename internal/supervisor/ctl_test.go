// SPDX-License-Identifier: GPL-3.0-or-later

package supervisor

// The other process tests in this package drive the daemon's own RPC client
// (fetchStatus) or report worker state directly. None of them exercises the
// user-facing client the P0 exit gate actually names: "RPC answers over UDS
// from sharza-ctl". These tests run the real binary against a real supervisor
// and assert on its stdout and exit code, so they prove the contract a user
// scripts against rather than the in-process one the daemon trusts.
//
// They are deliberately not parallel: each one starts a supervisor that spawns
// workers and reserves a port, and a gate that is only true on an idle machine
// is not a gate.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/role"
	"github.com/jonathanvanherpe/sharza/internal/store"
)

var (
	ctlOnce sync.Once
	ctlPath string
	ctlDir  string
	ctlErr  error
)

// buildCtl builds cmd/sharza-ctl once per test binary, mirroring buildDaemon.
// The CLI is a separate executable and must be tested as one: calling its
// internals from the test would not prove the shipped binary answers over the
// socket.
func buildCtl(t *testing.T) string {
	t.Helper()
	toolchain := goTool(t)

	ctlOnce.Do(func() {
		wd, err := os.Getwd()
		if err != nil {
			ctlErr = fmt.Errorf("working directory: %w", err)
			return
		}
		if _, err := os.Stat(filepath.Join(wd, "..", "..", "cmd", "sharza-ctl")); err != nil {
			ctlErr = fmt.Errorf("expected the test to run in internal/supervisor, got %s: %w", wd, err)
			return
		}

		ctlDir, err = os.MkdirTemp("", "sharza-ctl-test-")
		if err != nil {
			ctlErr = fmt.Errorf("temp dir for the ctl binary: %w", err)
			return
		}
		out := filepath.Join(ctlDir, "sharza-ctl")

		cmd := exec.Command(toolchain, "build", "-o", out, "../../cmd/sharza-ctl")
		cmd.Dir = wd
		var log bytes.Buffer
		cmd.Stdout = &log
		cmd.Stderr = &log
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			ctlErr = fmt.Errorf("start go build: %w", err)
			return
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				ctlErr = fmt.Errorf("go build ../../cmd/sharza-ctl: %w\n%s", err, log.String())
				return
			}
		case <-time.After(5 * time.Minute):
			_ = cmd.Process.Kill()
			<-done
			ctlErr = fmt.Errorf("go build ../../cmd/sharza-ctl: no result after 5m")
			return
		}
		ctlPath = out
	})

	if ctlErr != nil {
		t.Fatalf("build sharza-ctl: %v", ctlErr)
	}
	return ctlPath
}

// runCtl runs the built client and returns its stdout, stderr and exit code.
// A non-zero exit is a result to assert on, not a test failure; a process that
// cannot be run at all is a failure, because that says the fixture is broken
// rather than the client.
func runCtl(t *testing.T, bin string, args ...string) (stdout, stderr string, code int) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, bin, args...)
	var out, errb syncBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("sharza-ctl %v did not finish within 30s\nstdout:\n%s\nstderr:\n%s",
			args, out.String(), errb.String())
	}
	if err != nil {
		var ee *exec.ExitError
		if !errors.As(err, &ee) {
			t.Fatalf("run sharza-ctl %v: %v", args, err)
		}
		code = ee.ExitCode()
	}
	return out.String(), errb.String(), code
}

// ctlField returns the value of a "key value" line in the tabwriter output, so
// assertions do not depend on the exact column width.
func ctlField(out, key string) (string, bool) {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == key {
			return fields[1], true
		}
	}
	return "", false
}

// addJobID pulls the id out of the "added <id> (<name>)" line.
func addJobID(out string) string {
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "added" {
			return fields[1]
		}
	}
	return ""
}

// ctlJobCount counts data rows in the "jobs" table: the header is one line and
// "no jobs" is the empty case.
func ctlJobCount(out string) int {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) == 0 || strings.TrimSpace(lines[0]) == "" {
		return 0
	}
	if strings.HasPrefix(strings.TrimSpace(lines[0]), "ID") {
		return len(lines) - 1
	}
	return 0
}

// ctlJobState finds the row for id and returns its state column, failing the
// test if the job is absent. The id never contains spaces, so column positions
// are stable even for jobs whose names do.
func ctlJobState(t *testing.T, out, id string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[0] == id {
			return fields[2]
		}
	}
	t.Fatalf("job %s not found in sharza-ctl jobs output:\n%s", id, out)
	return ""
}

// TestSharzaCtlAnswersOverUDS is the P0 exit-gate bullet the daemon-side tests
// do not cover. It starts a genuine supervisor and asks a genuine client for
// status, a job add, a listing and a pause/resume, asserting only on what the
// client prints and returns.
func TestSharzaCtlAnswersOverUDS(t *testing.T) {
	bin := buildCtl(t)
	inst := startInstance(t, fastRestart)

	// The CLI must dial a bound socket, so wait for the supervisor to be
	// serving before running it. Without this the test can lose a race
	// with Listen and fail for a reason that is not the client.
	waitStatus(t, inst.sock, startupTimeout, allWorkersAlive)

	// status: the supervisor's own pid, its role and the schema version.
	out, errOut, code := runCtl(t, bin, "-config", inst.cfgPath, "status")
	if code != 0 {
		t.Fatalf("sharza-ctl status exit %d, want 0\nstdout:\n%s\nstderr:\n%s", code, out, errOut)
	}
	if got, ok := ctlField(out, "role"); !ok || got != string(role.Supervisor) {
		t.Errorf("status role = %q (found %v), want %q\n%s", got, ok, role.Supervisor, out)
	}
	wantPID := strconv.Itoa(inst.d.cmd.Process.Pid)
	if got, ok := ctlField(out, "pid"); !ok || got != wantPID {
		t.Errorf("status pid = %q (found %v), want the supervisor's own pid %s\n%s",
			got, ok, wantPID, out)
	}
	if got, ok := ctlField(out, "schema"); !ok || got != fmt.Sprintf("v%d", store.LatestVersion()) {
		t.Errorf("status schema = %q (found %v), want v%d\n%s", got, ok, store.LatestVersion(), out)
	}

	// -json status must be valid JSON and carry the same pid.
	jout, jerr, jcode := runCtl(t, bin, "-config", inst.cfgPath, "-json", "status")
	if jcode != 0 {
		t.Fatalf("sharza-ctl -json status exit %d, want 0\nstdout:\n%s\nstderr:\n%s", jcode, jout, jerr)
	}
	var st Status
	if err := json.Unmarshal([]byte(jout), &st); err != nil {
		t.Fatalf("decode -json status: %v\nstdout:\n%s", err, jout)
	}
	if st.PID != inst.d.cmd.Process.Pid {
		t.Errorf("-json status pid = %d, want %d", st.PID, inst.d.cmd.Process.Pid)
	}

	// add then jobs: exactly the job that was added.
	const magnet = "magnet:?xt=urn:btih:0123456789abcdef0123456789abcdef01234567&dn=sharza-test"
	aout, aerr, acode := runCtl(t, bin, "-config", inst.cfgPath, "add", magnet)
	if acode != 0 {
		t.Fatalf("sharza-ctl add exit %d, want 0\nstdout:\n%s\nstderr:\n%s", acode, aout, aerr)
	}
	id := addJobID(aout)
	if id == "" {
		t.Fatalf("could not read the job id from add output:\n%s", aout)
	}

	jout, jerr, jcode = runCtl(t, bin, "-config", inst.cfgPath, "jobs")
	if jcode != 0 {
		t.Fatalf("sharza-ctl jobs exit %d, want 0\nstdout:\n%s\nstderr:\n%s", jcode, jout, jerr)
	}
	if n := ctlJobCount(jout); n != 1 {
		t.Errorf("jobs lists %d rows, want exactly 1:\n%s", n, jout)
	}
	if got := ctlJobState(t, jout, id); got != string(store.StateQueued) {
		t.Errorf("job %s state = %q, want %q\n%s", id, got, store.StateQueued, jout)
	}

	// pause reflects in the listing.
	if pout, perr, pcode := runCtl(t, bin, "-config", inst.cfgPath, "pause", id); pcode != 0 {
		t.Fatalf("sharza-ctl pause %s exit %d, want 0\nstdout:\n%s\nstderr:\n%s",
			id, pcode, pout, perr)
	}
	jout, jerr, jcode = runCtl(t, bin, "-config", inst.cfgPath, "jobs")
	if jcode != 0 {
		t.Fatalf("sharza-ctl jobs after pause exit %d, want 0\nstdout:\n%s\nstderr:\n%s", jcode, jout, jerr)
	}
	if got := ctlJobState(t, jout, id); got != string(store.StatePaused) {
		t.Errorf("after pause, job %s state = %q, want %q\n%s", id, got, store.StatePaused, jout)
	}

	// resume reflects in the listing.
	if rout, rerr, rcode := runCtl(t, bin, "-config", inst.cfgPath, "resume", id); rcode != 0 {
		t.Fatalf("sharza-ctl resume %s exit %d, want 0\nstdout:\n%s\nstderr:\n%s",
			id, rcode, rout, rerr)
	}
	jout, jerr, jcode = runCtl(t, bin, "-config", inst.cfgPath, "jobs")
	if jcode != 0 {
		t.Fatalf("sharza-ctl jobs after resume exit %d, want 0\nstdout:\n%s\nstderr:\n%s", jcode, jout, jerr)
	}
	if got := ctlJobState(t, jout, id); got != string(store.StateQueued) {
		t.Errorf("after resume, job %s state = %q, want %q\n%s", id, got, store.StateQueued, jout)
	}
}

// TestSharzaCtlReportsUnavailableDaemon covers the failure path a user is far
// more likely to hit than the happy one: no daemon on the socket. The client
// must exit non-zero and say what to do about it, not leave a bare dial error.
func TestSharzaCtlReportsUnavailableDaemon(t *testing.T) {
	bin := buildCtl(t)
	sock := filepath.Join(t.TempDir(), "definitely-not-running.sock")

	out, errOut, code := runCtl(t, bin, "-socket", sock, "status")
	if code == 0 {
		t.Fatalf("sharza-ctl status against a missing socket exited 0, want non-zero\nstdout:\n%s\nstderr:\n%s",
			out, errOut)
	}
	if !strings.Contains(errOut, "is sharzad running?") {
		t.Errorf("stderr does not tell the user how to recover; want %q in:\n%s",
			"is sharzad running?", errOut)
	}
}
