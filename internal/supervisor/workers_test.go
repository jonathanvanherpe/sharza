// SPDX-License-Identifier: GPL-3.0-or-later

package supervisor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/config"
	"github.com/jonathanvanherpe/sharza/internal/role"
	"github.com/jonathanvanherpe/sharza/internal/rpc"
)

// Everything else in this package drives ReportWorker directly, which proves
// the bookkeeping in Service but says nothing about whether a supervisor spawns
// processes at all, restarts a killed one, survives alongside another instance,
// or leaves no orphans behind. The P0 exit gate is a claim about process
// behaviour, so it is asserted against the real binary: build it once, run it,
// talk to it over its own RPC socket, and signal it.
//
// These tests are deliberately not parallel. Each one kills processes and
// reserves a port, and a gate that is only true on an idle machine is not a
// gate.

const (
	// cfgSocketName is the control socket inside a test state dir. It is the
	// same name the daemon's own defaults use; the tests spell it out rather
	// than depending on the defaults, because the point is to pin the socket
	// per instance.
	cfgSocketName = "sharzad.sock"

	// fastRestart is the worker_restart_delay every test configures. It is
	// well under WorkerRestartDelay (2s) so a respawn observed inside a 2s
	// budget proves the configured delay is the one being used, not the
	// built-in default.
	fastRestart = "200ms"

	// startupTimeout allows for building the binary, spawning three workers
	// and each worker finding the control socket.
	startupTimeout = 20 * time.Second
)

// ---------------------------------------------------------------------------
// Toolchain
// ---------------------------------------------------------------------------

var (
	daemonOnce sync.Once
	daemonPath string
	daemonDir  string
	daemonErr  error
)

// findGoTool locates the Go toolchain, or returns "" if there is none.
//
// exec.LookPath alone is not enough here: on a host where the toolchain is only
// exported by an interactive shell, a bare PATH lookup would skip the whole
// exit gate in exactly the environment the gate exists to police. So the same
// well-known locations the build harness tries are tried too.
func findGoTool() string {
	if p, err := exec.LookPath("go"); err == nil {
		return p
	}

	var candidates []string
	if root := os.Getenv("GOROOT"); root != "" {
		candidates = append(candidates, filepath.Join(root, "bin", "go"))
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates, filepath.Join(home, "sdk", "go", "bin", "go"))
	}
	candidates = append(candidates, "/usr/local/go/bin/go", "/usr/bin/go")
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c
		}
	}
	return ""
}

// goTool is findGoTool for tests: a missing toolchain is an environment skip,
// stated as such, because a silent pass of the exit gate is worse than a
// missing one.
func goTool(t *testing.T) string {
	t.Helper()
	if p := findGoTool(); p != "" {
		return p
	}
	t.Skipf("no Go toolchain found (PATH, $GOROOT/bin, ~/sdk/go/bin, /usr/local/go/bin, /usr/bin): " +
		"environment skip, the process-level supervisor gate needs one to build the daemon")
	return ""
}

// A resolver that invents a path would fail later with a build error nobody can
// read as "no toolchain here". It must return nothing instead — or, when the
// host ships a real toolchain in a well-known location, that executable.
//
// The environment below has no toolchain in PATH, HOME or GOROOT, so the only
// way findGoTool can return non-empty is a system location such as /usr/bin/go
// on a runner image. That is discovery, not a guess, and the assertion is that
// whatever it returns really is an executable file.
func TestMissingToolchainIsReportedNotGuessed(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	t.Setenv("GOROOT", t.TempDir())

	got := findGoTool()
	if got == "" {
		return
	}
	fi, err := os.Stat(got)
	if err != nil || fi.IsDir() || fi.Mode()&0o111 == 0 {
		t.Fatalf("findGoTool() = %q with no toolchain in PATH, HOME or GOROOT: "+
			"not an executable file, want \"\" or a real toolchain", got)
	}
}

// TestMain removes the shared build directory. The binary is built once for the
// whole run rather than once per test, because rebuilding it per test would
// make the suite take minutes instead of seconds.
func TestMain(m *testing.M) {
	code := m.Run()
	if daemonDir != "" {
		_ = os.RemoveAll(daemonDir)
	}
	// ctlDir is owned by ctl_test.go's buildCtl; the shared TestMain is the
	// only hook that runs after every test in the package.
	if ctlDir != "" {
		_ = os.RemoveAll(ctlDir)
	}
	os.Exit(code)
}

// buildDaemon builds cmd/sharzad once per test binary and returns the path to
// the executable.
func buildDaemon(t *testing.T) string {
	t.Helper()
	toolchain := goTool(t)

	daemonOnce.Do(func() {
		// go test runs the binary with the package source directory as the
		// working directory, which is what makes the relative package path
		// below resolve. Assert it rather than build something unexpected.
		wd, err := os.Getwd()
		if err != nil {
			daemonErr = fmt.Errorf("working directory: %w", err)
			return
		}
		if _, err := os.Stat(filepath.Join(wd, "..", "..", "cmd", "sharzad")); err != nil {
			daemonErr = fmt.Errorf("expected the test to run in internal/supervisor, got %s: %w", wd, err)
			return
		}

		daemonDir, err = os.MkdirTemp("", "sharza-supervisor-test-")
		if err != nil {
			daemonErr = fmt.Errorf("temp dir for the daemon binary: %w", err)
			return
		}
		out := filepath.Join(daemonDir, "sharzad")

		cmd := exec.Command(toolchain, "build", "-o", out, "../../cmd/sharzad")
		cmd.Dir = wd
		var log bytes.Buffer
		cmd.Stdout = &log
		cmd.Stderr = &log
		// A cold build cache can take a while; a hung one should fail rather
		// than hang the suite.
		done := make(chan error, 1)
		if err := cmd.Start(); err != nil {
			daemonErr = fmt.Errorf("start go build: %w", err)
			return
		}
		go func() { done <- cmd.Wait() }()
		select {
		case err := <-done:
			if err != nil {
				daemonErr = fmt.Errorf("go build ../../cmd/sharzad: %w\n%s", err, log.String())
				return
			}
		case <-time.After(5 * time.Minute):
			_ = cmd.Process.Kill()
			<-done
			daemonErr = fmt.Errorf("go build ../../cmd/sharzad: no result after 5m")
			return
		}
		daemonPath = out
	})

	if daemonErr != nil {
		t.Fatalf("build the daemon: %v", daemonErr)
	}
	return daemonPath
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// freePort reserves a loopback port and releases it again.
//
// The config package insists on a loopback web listener, so the test picks one
// rather than asking the daemon to bind port 0 and reporting back: weakening
// checkLoopback to make the test easier is exactly the change that must not
// happen.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve a loopback port: %v", err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	if err := ln.Close(); err != nil {
		t.Fatalf("release port %d: %v", port, err)
	}
	return port
}

// writeConfig writes a config for one instance into dir and returns its path.
//
// dir is a per-test t.TempDir, so a test never reads or writes the user's real
// state directory and two instances can never collide on a socket.
func writeConfig(t *testing.T, dir, restartDelay string) string {
	t.Helper()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create state dir %s: %v", dir, err)
	}

	cfg := config.Config{
		StateDir:           dir,
		SocketPath:         filepath.Join(dir, cfgSocketName),
		WebListen:          fmt.Sprintf("127.0.0.1:%d", freePort(t)),
		WorkerRoles:        []role.Role{role.BT, role.ED2K, role.G2},
		WorkerRestartDelay: restartDelay,
	}
	body, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		t.Fatalf("encode config: %v", err)
	}

	path := filepath.Join(dir, "sharza.json")
	if err := os.WriteFile(path, append(body, '\n'), 0o600); err != nil {
		t.Fatalf("write config %s: %v", path, err)
	}
	return path
}

// syncBuffer collects a child process's output. exec.Cmd writes from its own
// goroutine while the test reads it, so the lock is required rather than
// decorative.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

// daemon is one running supervisor process.
type daemon struct {
	cmd      *exec.Cmd
	log      *syncBuffer
	sock     string
	waitOnce sync.Once
	waitDone chan struct{}
	waitErr  error
}

// reap is called once, from a goroutine, so the process is never waited for
// twice and callers can all observe the same exit.
func (d *daemon) reap() {
	d.waitOnce.Do(func() {
		d.waitErr = d.cmd.Wait()
		close(d.waitDone)
	})
}

// waitExit waits for the supervisor to exit, failing the test if it does not.
func (d *daemon) waitExit(t *testing.T, timeout time.Duration) error {
	t.Helper()
	select {
	case <-d.waitDone:
		return d.waitErr
	case <-time.After(timeout):
		t.Fatalf("supervisor pid %d still running after %s\nlog:\n%s",
			d.cmd.Process.Pid, timeout, d.log.String())
		return nil
	}
}

// killGroup stops the supervisor and, if it will not go, everything it is
// supervising. It runs from t.Cleanup on failure as well as on success: a
// test that panics half way through must not leave a daemon behind to fight
// the next run for ports.
func (d *daemon) killGroup(t *testing.T) {
	t.Helper()
	pid := d.cmd.Process.Pid
	// Negative pid signals the supervisor's process group. Its workers are in
	// their own groups, so this reaches the supervisor, and the supervisor
	// stops its workers the way it always does.
	_ = syscall.Kill(-pid, syscall.SIGTERM)

	select {
	case <-d.waitDone:
		return
	case <-time.After(10 * time.Second):
	}

	// A supervisor that will not shut down cleanly still must not leave
	// processes behind, so sweep the workers it last reported before killing
	// it outright.
	if st, err := fetchStatus(d.sock); err == nil {
		for _, w := range st.Workers {
			if w.PID > 0 {
				_ = syscall.Kill(-w.PID, syscall.SIGKILL)
			}
		}
	}
	_ = syscall.Kill(-pid, syscall.SIGKILL)
	<-d.waitDone
}

// instance is a supervisor with its own state dir, config and control socket.
type instance struct {
	cfgPath string
	sock    string
	d       *daemon
}

// startInstance writes a config into a fresh temp dir and runs a supervisor
// against it.
func startInstance(t *testing.T, restartDelay string) *instance {
	t.Helper()
	bin := buildDaemon(t)

	dir := t.TempDir()
	cfgPath := writeConfig(t, dir, restartDelay)
	sock := filepath.Join(dir, cfgSocketName)

	log := &syncBuffer{}
	cmd := exec.Command(bin, "--role=supervisor", "--config="+cfgPath)
	cmd.Stdout = log
	cmd.Stderr = log
	// Its own process group, so cleanup can signal the supervisor without
	// signalling the test runner.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start supervisor: %v", err)
	}

	d := &daemon{cmd: cmd, log: log, sock: sock, waitDone: make(chan struct{})}
	go d.reap()

	inst := &instance{cfgPath: cfgPath, sock: sock, d: d}

	// Registered before the kill, so it runs after it (cleanups are LIFO) and
	// therefore reports the log of a process that is really gone.
	t.Cleanup(func() {
		if t.Failed() {
			t.Logf("supervisor pid %d log:\n%s", cmd.Process.Pid, log.String())
		}
	})
	t.Cleanup(func() { d.killGroup(t) })

	return inst
}

// ---------------------------------------------------------------------------
// Talking to a live daemon
// ---------------------------------------------------------------------------

// fetchStatus makes one sharza.status call over the control socket.
func fetchStatus(sock string) (Status, error) {
	c, err := rpc.Dial(sock, 500*time.Millisecond)
	if err != nil {
		return Status{}, err
	}
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var st Status
	if err := c.Call(ctx, rpc.MethodStatus, nil, &st); err != nil {
		return Status{}, err
	}
	return st, nil
}

// waitStatus polls sharza.status until pred holds and returns that status.
//
// A timeout is a failure, never a skip. The gate is about what the daemon
// actually does at the process level, so "it never got there" is the finding,
// not an excuse to pass.
func waitStatus(t *testing.T, sock string, timeout time.Duration, pred func(Status) bool) Status {
	t.Helper()
	deadline := time.Now().Add(timeout)

	var last Status
	var lastErr error
	var polls int
	for {
		polls++
		st, err := fetchStatus(sock)
		switch {
		case err != nil:
			lastErr = err
		case pred(st):
			return st
		default:
			last = st
		}
		if time.Now().After(deadline) {
			t.Fatalf("condition not met within %s after %d status polls\nlast status: %+v\nlast error: %v",
				timeout, polls, last, lastErr)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func workersByRole(st Status) map[role.Role]WorkerStatus {
	by := map[role.Role]WorkerStatus{}
	for _, w := range st.Workers {
		by[w.Role] = w
	}
	return by
}

// allWorkersAlive is the predicate for "every configured worker is up".
func allWorkersAlive(st Status) bool {
	by := workersByRole(st)
	for _, r := range role.WorkerRoles() {
		w, ok := by[r]
		if !ok || !w.Alive || w.PID <= 0 {
			return false
		}
	}
	return true
}

// workerPIDs returns the pids of the workers reported alive.
func workerPIDs(st Status) []int {
	pids := make([]int, 0, len(st.Workers))
	for _, w := range st.Workers {
		if w.PID > 0 {
			pids = append(pids, w.PID)
		}
	}
	return pids
}

// processAlive reports whether a pid still exists. Signal 0 does the existence
// check without delivering anything.
func processAlive(pid int) bool { return syscall.Kill(pid, 0) == nil }

// The process tests prove the configured delay is used end to end. This covers
// the branch they cannot reach: the daemon's config validation rejects a bad
// value before StartWorkers ever sees one, so the "no silent fallback" promise
// would otherwise be unproven.
func TestRestartDelayFallsBackOnlyWhenUnset(t *testing.T) {
	for _, tc := range []struct {
		name    string
		set     string
		want    time.Duration
		wantErr bool
	}{
		{"unset uses the built-in default", "", WorkerRestartDelay, false},
		{"a configured delay is used as given", "250ms", 250 * time.Millisecond, false},
		{"a sub-second delay survives", fastRestart, 200 * time.Millisecond, false},
		{"an unparseable delay is an error, not a fallback", "abc", 0, true},
		{"a bare number is an error too", "100", 0, true},
	} {
		got, err := restartDelay(&config.Config{WorkerRestartDelay: tc.set})
		if tc.wantErr {
			if err == nil {
				t.Errorf("%s: restartDelay(%q) = %v, want an error", tc.name, tc.set, got)
			} else if !strings.Contains(err.Error(), "worker_restart_delay") {
				t.Errorf("%s: error does not name the field: %v", tc.name, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%s: restartDelay(%q) = %v", tc.name, tc.set, err)
			continue
		}
		if got != tc.want {
			t.Errorf("%s: restartDelay(%q) = %v, want %v", tc.name, tc.set, got, tc.want)
		}
	}
}

// ---------------------------------------------------------------------------
// The gate
// ---------------------------------------------------------------------------

func TestSupervisorSpawnsThreeWorkers(t *testing.T) {
	inst := startInstance(t, fastRestart)

	st := waitStatus(t, inst.sock, startupTimeout, allWorkersAlive)

	if st.Role != role.Supervisor {
		t.Errorf("role = %q, want supervisor", st.Role)
	}
	if st.PID != inst.d.cmd.Process.Pid {
		t.Errorf("status pid = %d, want the supervisor's own pid %d", st.PID, inst.d.cmd.Process.Pid)
	}
	if len(st.Workers) != len(role.WorkerRoles()) {
		t.Fatalf("workers = %d entries, want %d: %+v", len(st.Workers), len(role.WorkerRoles()), st.Workers)
	}

	seen := map[int]role.Role{}
	for _, w := range st.Workers {
		if w.PID <= 0 {
			t.Errorf("worker %s is alive with pid %d", w.Role, w.PID)
			continue
		}
		if prev, dup := seen[w.PID]; dup {
			t.Errorf("workers %s and %s share pid %d: they are not three processes", prev, w.Role, w.PID)
		}
		seen[w.PID] = w.Role

		// The supervisor reports a pid, but "alive" in the RPC reply only
		// means the supervisor believed Start succeeded. Check the pid
		// really is a live process.
		if err := syscall.Kill(w.PID, 0); err != nil {
			t.Errorf("worker %s pid %d is not a live process: %v", w.Role, w.PID, err)
		}
	}
}

// Killing one worker must cost that network and nothing else. It is the
// property that makes the worker split worth having, so it is asserted against
// real processes rather than inferred from the restart counter.
func TestKilledWorkerIsRespawnedAndOthersUntouched(t *testing.T) {
	inst := startInstance(t, fastRestart)

	before := waitStatus(t, inst.sock, startupTimeout, allWorkersAlive)
	beforeByRole := workersByRole(before)
	btPID := beforeByRole[role.BT].PID

	if err := syscall.Kill(btPID, syscall.SIGKILL); err != nil {
		t.Fatalf("SIGKILL the bt worker (pid %d): %v", btPID, err)
	}

	// The budget is 2s while the configured delay is 200ms, so this passes
	// only if worker_restart_delay is honoured rather than hardcoded to
	// WorkerRestartDelay (2s).
	after := waitStatus(t, inst.sock, 2*time.Second, func(st Status) bool {
		w, ok := workersByRole(st)[role.BT]
		return ok && w.Alive && w.PID != btPID && w.Rests == 1
	})
	afterByRole := workersByRole(after)

	bt := afterByRole[role.BT]
	if bt.PID == btPID {
		t.Errorf("bt worker pid is still %d after a SIGKILL: it was not respawned", btPID)
	}
	if !bt.Alive {
		t.Errorf("bt worker = %+v, want alive", bt)
	}
	if bt.Rests != 1 {
		t.Errorf("bt worker rests = %d, want exactly 1: one kill, one respawn", bt.Rests)
	}
	if err := syscall.Kill(bt.PID, 0); err != nil {
		t.Errorf("respawned bt worker pid %d is not alive: %v", bt.PID, err)
	}

	// The other two networks must not have noticed.
	for _, r := range []role.Role{role.ED2K, role.G2} {
		w, ok := afterByRole[r]
		if !ok {
			t.Errorf("worker %s missing from status: %+v", r, after.Workers)
			continue
		}
		if w.PID != beforeByRole[r].PID {
			t.Errorf("%s worker pid = %d, want the original %d: an unrelated worker was restarted",
				r, w.PID, beforeByRole[r].PID)
		}
		if !w.Alive {
			t.Errorf("%s worker = %+v, want alive", r, w)
		}
		if w.Rests != 0 {
			t.Errorf("%s worker rests = %d, want 0: only bt was killed", r, w.Rests)
		}
	}

	if after.PID != before.PID {
		t.Errorf("supervisor pid changed from %d to %d: the supervisor did not survive a worker death",
			before.PID, after.PID)
	}
}

// Two instances must be able to run at once without sharing a socket, a state
// file or a worker. This is the multi-user case: one user's daemon must not
// be reachable from, or confused with, another's.
func TestTwoInstancesRunSideBySide(t *testing.T) {
	a := startInstance(t, fastRestart)
	b := startInstance(t, fastRestart)

	if a.sock == b.sock {
		t.Fatalf("both instances use socket %s", a.sock)
	}
	if a.cfgPath == b.cfgPath || filepath.Dir(a.cfgPath) == filepath.Dir(b.cfgPath) {
		t.Fatalf("both instances share a config or state dir: %s and %s", a.cfgPath, b.cfgPath)
	}
	if a.d.cmd.Process.Pid == b.d.cmd.Process.Pid {
		t.Fatalf("both instances are pid %d", a.d.cmd.Process.Pid)
	}

	stA := waitStatus(t, a.sock, startupTimeout, allWorkersAlive)
	stB := waitStatus(t, b.sock, startupTimeout, allWorkersAlive)

	for _, tc := range []struct {
		name string
		inst *instance
		st   Status
	}{
		{"first", a, stA},
		{"second", b, stB},
	} {
		if tc.st.PID != tc.inst.d.cmd.Process.Pid {
			t.Errorf("%s instance reports pid %d, want its own %d", tc.name, tc.st.PID, tc.inst.d.cmd.Process.Pid)
		}
		if tc.st.Role != role.Supervisor {
			t.Errorf("%s instance role = %q, want supervisor", tc.name, tc.st.Role)
		}
		if len(tc.st.Workers) != len(role.WorkerRoles()) {
			t.Errorf("%s instance lists %d workers, want %d", tc.name, len(tc.st.Workers), len(role.WorkerRoles()))
		}
		for _, w := range tc.st.Workers {
			if !w.Alive || w.PID <= 0 {
				t.Errorf("%s instance worker %s = %+v, want alive", tc.name, w.Role, w)
			}
		}
	}

	// Six live workers across two daemons, all different processes.
	owner := map[int]string{}
	for _, tc := range []struct {
		name string
		st   Status
	}{{"first", stA}, {"second", stB}} {
		for _, pid := range workerPIDs(tc.st) {
			if other, dup := owner[pid]; dup {
				t.Errorf("pid %d is claimed by both the %s and %s instance", pid, other, tc.name)
			}
			owner[pid] = tc.name
		}
	}
	if len(owner) != 2*len(role.WorkerRoles()) {
		t.Errorf("live worker pids = %d, want %d", len(owner), 2*len(role.WorkerRoles()))
	}
}

// "No orphans" is the invariant P2's VPN story rests on too, so it is asserted
// here rather than assumed: once the supervisor is gone, no worker it started
// may still be running.
func TestStopLeavesNoOrphanWorkers(t *testing.T) {
	inst := startInstance(t, fastRestart)

	st := waitStatus(t, inst.sock, startupTimeout, allWorkersAlive)
	pids := workerPIDs(st)
	if len(pids) != len(role.WorkerRoles()) {
		t.Fatalf("live worker pids = %v, want %d", pids, len(role.WorkerRoles()))
	}

	// SIGTERM is how systemd stops the service.
	if err := syscall.Kill(inst.d.cmd.Process.Pid, syscall.SIGTERM); err != nil {
		t.Fatalf("SIGTERM the supervisor (pid %d): %v", inst.d.cmd.Process.Pid, err)
	}
	// A clean shutdown exits 0; an error here means the daemon treats a
	// normal stop as a failure, which systemd would record as a bad stop.
	if err := inst.d.waitExit(t, 20*time.Second); err != nil {
		t.Fatalf("supervisor exited with %v after SIGTERM, want a clean exit\nlog:\n%s",
			err, inst.d.log.String())
	}

	deadline := time.Now().Add(10 * time.Second)
	for _, pid := range pids {
		for processAlive(pid) {
			if time.Now().After(deadline) {
				t.Fatalf("worker pid %d survived the supervisor for over 10s after SIGTERM: "+
					"an orphan keeps a network engine running with no control plane",
					pid)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
}

// TestStopLeavesNoOrphanWorkerDescendants is the test that can actually fail
// when Stop's process-group handling breaks.
//
// TestStopLeavesNoOrphanWorkers checks that the workers themselves are gone,
// but the real worker is a leaf: no grandchildren, so signalling the worker's
// pid and signalling its process group are indistinguishable. That test passes
// whether Stop uses kill(-pid) or kill(pid), which was confirmed by mutating
// Stop to signal single pids and watching it stay green. A test that cannot
// detect the bug it names is worse than no test, because it reads as coverage.
//
// This one runs a worker that grows a grandchild inheriting the worker's
// process group, which is the shape a real engine takes once P2 gives it a VPN
// helper. Signal the group and both die; signal the pid and the grandchild
// survives with the engine's traffic and no control plane.
func TestStopLeavesNoOrphanWorkerDescendants(t *testing.T) {
	bin := buildForker(t)

	cfg := config.Default()
	cfg.StateDir = t.TempDir()
	// One role is enough and keeps the failure legible: the invariant is
	// about descendants, not about how many workers there are.
	cfg.WorkerRoles = []role.Role{role.BT}
	if err := cfg.Validate(); err != nil {
		t.Fatalf("config: %v", err)
	}

	// The forker reports the pids of the worker the supervisor spawns. It has
	// to be the supervisor's own worker: a copy started by the test would be a
	// process Stop knows nothing about, so it would survive a correct
	// implementation and the test would fail for the wrong reason.
	pidfile := filepath.Join(t.TempDir(), "forker.pids")
	t.Setenv("SHARZA_TEST_PIDFILE", pidfile)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	var mu sync.Mutex
	reported := map[role.Role]int{}
	sup, err := StartWorkers(ctx, cfg, func(r role.Role, pid int, _ bool) {
		mu.Lock()
		reported[r] = pid
		mu.Unlock()
	}, bin, nil)
	if err != nil {
		t.Fatalf("StartWorkers: %v", err)
	}

	workerPID, grandchildPID := waitForForkerPids(t, pidfile)

	// The supervisor's own view of the worker must match, or the pids in the
	// file belong to something else and the assertion below proves nothing.
	mu.Lock()
	supervisorPID := reported[role.BT]
	mu.Unlock()
	if supervisorPID != workerPID {
		t.Fatalf("supervisor reports worker pid %d but the pidfile says %d; "+
			"the test is measuring the wrong process", supervisorPID, workerPID)
	}

	if !processAlive(grandchildPID) {
		t.Fatalf("grandchild pid %d is already dead; the test would be vacuous", grandchildPID)
	}

	sup.Stop()

	// Both, not just the worker: a surviving grandchild is the exact failure
	// mode this exists to catch.
	for name, pid := range map[string]int{"worker": workerPID, "grandchild": grandchildPID} {
		if !waitUntilDead(t, pid, 10*time.Second) {
			t.Errorf("%s pid %d outlived Stop: Stop signalled a single pid instead of "+
				"the worker's process group, so descendants survive and keep engine "+
				"traffic alive with no control plane", name, pid)
		}
	}
}

// buildForker compiles the fake worker that grows a grandchild.
func buildForker(t *testing.T) string {
	t.Helper()
	toolchain := goTool(t)

	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	dir, err := os.MkdirTemp("", "sharza-forker-")
	if err != nil {
		t.Fatalf("temp dir: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	out := filepath.Join(dir, "forker")
	cmd := exec.Command(toolchain, "build", "-o", out, "./testdata/forker")
	cmd.Dir = wd
	var log bytes.Buffer
	cmd.Stdout = &log
	cmd.Stderr = &log
	if err := cmd.Run(); err != nil {
		t.Fatalf("build forker: %v\n%s", err, log.String())
	}
	return out
}

// waitForForkerPids reads the pids the spawned worker reported.
func waitForForkerPids(t *testing.T, pidfile string) (worker, grandchild int) {
	t.Helper()

	deadline := time.Now().Add(30 * time.Second)
	for {
		if data, err := os.ReadFile(pidfile); err == nil && len(data) > 0 {
			line := strings.TrimSpace(strings.SplitN(string(data), "\n", 2)[0])
			fields := strings.Fields(line)
			if len(fields) != 3 || fields[0] != "worker" {
				t.Fatalf("unexpected pidfile line %q, want \"worker <pid> <grandchild-pid>\"", line)
			}
			worker, err = strconv.Atoi(fields[1])
			if err != nil {
				t.Fatalf("worker pid %q: %v", fields[1], err)
			}
			grandchild, err = strconv.Atoi(fields[2])
			if err != nil {
				t.Fatalf("grandchild pid %q: %v", fields[2], err)
			}
			return worker, grandchild
		}
		if time.Now().After(deadline) {
			t.Fatalf("the forked worker never reported its pids; nothing to assert against")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func waitUntilDead(t *testing.T, pid int, within time.Duration) bool {
	t.Helper()
	deadline := time.Now().Add(within)
	for processAlive(pid) {
		if time.Now().After(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
	return true
}

// rpcRolesCall makes one roles RPC call against a live daemon.
func rpcRolesCall(t *testing.T, sock, method string, r role.Role) error {
	t.Helper()
	c, err := rpc.Dial(sock, 500*time.Millisecond)
	if err != nil {
		return err
	}
	defer c.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return c.Call(ctx, method, RoleParam{Role: r}, nil)
}

// Pausing a network must stop its worker and keep it stopped across the
// restart boundary, while the other networks keep running. It is what the web
// UI's network toggles do, so it is asserted against real processes: a pause
// that only lasts until the next respawn would show as a toggle that does not
// stay toggled.
func TestPausedWorkerStaysDownUntilResumed(t *testing.T) {
	inst := startInstance(t, fastRestart)

	before := waitStatus(t, inst.sock, startupTimeout, allWorkersAlive)
	beforeByRole := workersByRole(before)
	btPID := beforeByRole[role.BT].PID

	if err := rpcRolesCall(t, inst.sock, rpc.MethodRolesPause, role.BT); err != nil {
		t.Fatalf("pause bt: %v", err)
	}

	// The kill lands, the worker reports dead, and status must show the
	// paused flag alongside the dead worker.
	waitStatus(t, inst.sock, 5*time.Second, func(st Status) bool {
		w, ok := workersByRole(st)[role.BT]
		return ok && !w.Alive && w.Paused
	})

	// Several restart delays (200ms each) go by without the worker coming
	// back: a pause must hold across the respawn path, not just until the
	// process exits.
	delay, err := time.ParseDuration(fastRestart)
	if err != nil {
		t.Fatalf("parse %s: %v", fastRestart, err)
	}
	time.Sleep(3 * delay)

	st := waitStatus(t, inst.sock, 5*time.Second, func(st Status) bool {
		w, ok := workersByRole(st)[role.BT]
		return ok && !w.Alive && w.Paused
	})
	by := workersByRole(st)

	// The other two networks must not have noticed the pause.
	for _, r := range []role.Role{role.ED2K, role.G2} {
		w, ok := by[r]
		if !ok {
			t.Errorf("worker %s missing from status: %+v", r, st.Workers)
			continue
		}
		if w.PID != beforeByRole[r].PID {
			t.Errorf("%s worker pid = %d, want the original %d: pausing bt touched another network",
				r, w.PID, beforeByRole[r].PID)
		}
		if !w.Alive {
			t.Errorf("%s worker = %+v, want still alive", r, w)
		}
	}

	if err := rpcRolesCall(t, inst.sock, rpc.MethodRolesResume, role.BT); err != nil {
		t.Fatalf("resume bt: %v", err)
	}

	// The resumed worker is a fresh process, alive and unpaused.
	resumed := waitStatus(t, inst.sock, 5*time.Second, func(st Status) bool {
		w, ok := workersByRole(st)[role.BT]
		return ok && w.Alive && !w.Paused && w.PID != btPID
	})
	resumedBT := workersByRole(resumed)[role.BT]
	if err := syscall.Kill(resumedBT.PID, 0); err != nil {
		t.Errorf("resumed bt worker pid %d is not a live process: %v", resumedBT.PID, err)
	}
}
