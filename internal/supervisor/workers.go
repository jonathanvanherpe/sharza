// SPDX-License-Identifier: GPL-3.0-or-later

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/config"
	"github.com/jonathanvanherpe/sharza/internal/role"
)

// ErrUnknownRole reports a pause/resume request for a role this supervisor
// does not manage.
var ErrUnknownRole = errors.New("unknown role")

// WorkerRestartDelay is the default pause before respawning a worker. It is
// long enough that a worker failing at startup does not spin the CPU, and
// short enough that a crash is not noticed as an outage.
const WorkerRestartDelay = 2 * time.Second

// ReportWorkerFunc is how the Supervisor tells the RPC service about liveness.
type ReportWorkerFunc func(role.Role, int, bool)

// Supervisor owns the worker processes.
//
// It deliberately does not do health probing: a worker that is alive but
// useless cannot be distinguished from a healthy one without protocol-level
// checks that do not exist yet. Liveness plus restart counting is honest about
// what is known.
type Supervisor struct {
	svc     ReportWorkerFunc
	bin     string
	cfgPath string
	roles   []role.Role
	delay   time.Duration
	logs    io.Writer // worker stdio sink; nil keeps the inherited stdio

	mu      sync.Mutex
	workers map[role.Role]*managed
	paused  map[role.Role]bool
	// spawnMu serializes spawn, pause and resume for one role, so a respawn
	// never races a pause that is deciding to kill the worker it spawns.
	spawnMu map[role.Role]*sync.Mutex
	wg      sync.WaitGroup
	stopped bool
}

type managed struct {
	cmd  *exec.Cmd
	done chan struct{}
}

// StartWorkers spawns one process per configured worker role. Worker output
// is written to out when it is non-nil; a nil out keeps the inherited stdio,
// which is the right choice for tests that want the previous behaviour.
func StartWorkers(
	ctx context.Context,
	cfg *config.Config,
	svc ReportWorkerFunc,
	bin string,
	out io.Writer,
) (*Supervisor, error) {
	if err := cfg.EnsureDirs(); err != nil {
		return nil, err
	}

	delay, err := restartDelay(cfg)
	if err != nil {
		return nil, err
	}

	s := &Supervisor{
		svc:     svc,
		bin:     bin,
		cfgPath: cfgPathOf(cfg),
		roles:   cfg.WorkerRoles,
		delay:   delay,
		logs:    out,
		workers: map[role.Role]*managed{},
		paused:  map[role.Role]bool{},
		spawnMu: map[role.Role]*sync.Mutex{},
	}
	for _, r := range s.roles {
		s.spawnMu[r] = &sync.Mutex{}
	}

	for _, r := range s.roles {
		if err := s.spawn(ctx, r); err != nil {
			s.Stop()
			return nil, fmt.Errorf("spawn %s worker: %w", r, err)
		}
	}
	return s, nil
}

// cfgPathOf recovers the config path a worker should inherit. The supervisor
// may have been started with defaults, in which case there is no file and the
// worker resolves the same defaults itself.
func cfgPathOf(cfg *config.Config) string { return cfg.ConfigPath }

// restartDelay resolves how long to wait before respawning a dead worker.
//
// An empty setting means the built-in default, which is what a supervisor
// started without a config file gets. An unparseable setting is an error
// rather than a fallback: silently substituting the default would hand the
// operator a restart rate they did not ask for, and the only symptom would be
// workers respawning on a schedule nobody chose.
func restartDelay(cfg *config.Config) (time.Duration, error) {
	if cfg.WorkerRestartDelay == "" {
		return WorkerRestartDelay, nil
	}
	d, err := time.ParseDuration(cfg.WorkerRestartDelay)
	if err != nil {
		return 0, fmt.Errorf("worker_restart_delay %q is not a duration: %w",
			cfg.WorkerRestartDelay, err)
	}
	return d, nil
}

// spawn starts one worker and arranges for it to be restarted if it exits.
// It is serialised per role: callers that must not race a spawn (pause,
// resume, stop) hold the role's spawnMu.
func (s *Supervisor) spawn(ctx context.Context, r role.Role) error {
	s.spawnMu[r].Lock()
	defer s.spawnMu[r].Unlock()
	return s.spawnUnlocked(ctx, r)
}

// spawnUnlocked assumes the caller holds s.spawnMu[r].
func (s *Supervisor) spawnUnlocked(ctx context.Context, r role.Role) error {
	cmd := exec.Command(s.bin, "--role="+string(r))
	if s.cfgPath != "" {
		cmd.Args = append(cmd.Args, "--config="+s.cfgPath)
	}
	cmd.Env = append(cmd.Environ(), "SHARZA_ROLE="+string(r))
	// Worker output goes to the log sink when one is configured so the web
	// UI can tail it; otherwise share the supervisor's stdio so logs land in
	// the journal instead of in a pipe nobody reads. A pipe nobody reads
	// fills up and blocks the worker, which is a wonderfully subtle way to
	// hang a daemon.
	cmd.Stdin = nil
	cmd.Stdout = s.logs
	cmd.Stderr = s.logs
	// A process group lets Stop kill the whole worker tree, so a worker
	// that spawns helpers does not leave orphans behind.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return err
	}

	m := &managed{cmd: cmd, done: make(chan struct{})}
	s.mu.Lock()
	s.workers[r] = m
	stopped := s.stopped
	s.mu.Unlock()

	// The supervisor may have been stopped while the kill was landing; a
	// worker that arrives after the stop snapshot must not outlive it.
	if stopped {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}

	s.svc(r, cmd.Process.Pid, true)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := cmd.Wait()
		close(m.done)

		s.svc(r, 0, false)

		// Whether the world still wants a respawn, checked without holding
		// the role lock across the restart delay. The lock is only held for
		// the gate checks and the spawn itself, so a pause never blocks on a
		// worker that is mid-delay.
		gated := func() bool {
			s.spawnMu[r].Lock()
			defer s.spawnMu[r].Unlock()
			s.mu.Lock()
			defer s.mu.Unlock()
			return !s.stopped && !s.paused[r] && s.workers[r] == m && ctx.Err() == nil
		}

		if !gated() {
			return
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			// A worker that cannot start will loop forever without this
			// pause, because its exit is immediate.
			select {
			case <-ctx.Done():
				return
			case <-time.After(s.delay):
			}
		}
		if !gated() {
			return
		}
		if err := s.spawn(ctx, r); err != nil {
			// Losing a worker silently is worse than saying so.
			s.svc(r, 0, false)
			s.notef("worker %s failed to respawn: %v", r, err)
		}
	}()

	return nil
}

// PauseRole stops the worker for r and keeps it down until ResumeRole, even
// across crashes: the respawn path skips a paused role entirely.
func (s *Supervisor) PauseRole(r role.Role) error {
	lm, err := s.roleLock(r)
	if err != nil {
		return err
	}
	lm.Lock()
	defer lm.Unlock()

	s.mu.Lock()
	s.paused[r] = true
	m := s.workers[r]
	s.mu.Unlock()

	if m != nil && m.cmd.Process != nil {
		_ = syscall.Kill(-m.cmd.Process.Pid, syscall.SIGTERM)
		s.notef("worker %s paused", r)
	}
	return nil
}

// ResumeRole starts the worker for r again. Resuming a role that is not
// paused is a no-op.
func (s *Supervisor) ResumeRole(ctx context.Context, r role.Role) error {
	lm, err := s.roleLock(r)
	if err != nil {
		return err
	}
	lm.Lock()
	defer lm.Unlock()

	s.mu.Lock()
	if !s.paused[r] {
		s.mu.Unlock()
		return nil
	}
	s.paused[r] = false
	s.mu.Unlock()

	if err := s.spawnUnlocked(ctx, r); err != nil {
		s.notef("worker %s failed to resume: %v", r, err)
		return err
	}
	s.notef("worker %s resumed", r)
	return nil
}

// IsRolePaused reports whether r is paused. Unknown roles report false.
func (s *Supervisor) IsRolePaused(r role.Role) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.paused[r]
}

// roleLock returns the spawnMu for r, or an error when this supervisor does
// not manage r.
func (s *Supervisor) roleLock(r role.Role) (*sync.Mutex, error) {
	lm, ok := s.spawnMu[r]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownRole, r)
	}
	return lm, nil
}

// notef writes a supervisor line to the log sink, when one is configured.
func (s *Supervisor) notef(format string, args ...any) {
	if s.logs != nil {
		fmt.Fprintf(s.logs, "[sharzad] "+format+"\n", args...)
	}
}

// Stop terminates all workers and waits for them.
func (s *Supervisor) Stop() {
	s.mu.Lock()
	if s.stopped {
		s.mu.Unlock()
		return
	}
	s.stopped = true
	workers := make([]*managed, 0, len(s.workers))
	for _, m := range s.workers {
		workers = append(workers, m)
	}
	s.mu.Unlock()

	for _, m := range workers {
		if m.cmd.Process != nil {
			// Negative pid signals the whole process group.
			_ = syscall.Kill(-m.cmd.Process.Pid, syscall.SIGTERM)
		}
	}

	// Bounded wait: a worker that ignores SIGTERM must not stop the
	// supervisor from exiting.
	done := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		for _, m := range workers {
			if m.cmd.Process != nil {
				_ = syscall.Kill(-m.cmd.Process.Pid, syscall.SIGKILL)
			}
		}
		<-done
	}
}
