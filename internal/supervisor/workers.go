// SPDX-License-Identifier: GPL-3.0-or-later

package supervisor

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"sync"
	"syscall"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/config"
	"github.com/jonathanvanherpe/sharza/internal/role"
)

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

	mu      sync.Mutex
	workers map[role.Role]*managed
	wg      sync.WaitGroup
	stopped bool
}

type managed struct {
	cmd  *exec.Cmd
	done chan struct{}
}

// StartWorkers spawns one process per configured worker role.
func StartWorkers(
	ctx context.Context,
	cfg *config.Config,
	svc ReportWorkerFunc,
	bin string,
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
		workers: map[role.Role]*managed{},
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
func (s *Supervisor) spawn(ctx context.Context, r role.Role) error {
	cmd := exec.Command(s.bin, "--role="+string(r))
	if s.cfgPath != "" {
		cmd.Args = append(cmd.Args, "--config="+s.cfgPath)
	}
	cmd.Env = append(cmd.Environ(), "SHARZA_ROLE="+string(r))
	// Share the supervisor's stdio so worker logs land in the journal
	// instead of in a pipe nobody reads. A pipe nobody reads fills up and
	// blocks the worker, which is a wonderfully subtle way to hang a
	// daemon.
	cmd.Stdin = nil
	cmd.Stdout = nil
	cmd.Stderr = nil
	// A process group lets Stop kill the whole worker tree, so a worker
	// that spawns helpers does not leave orphans behind.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return err
	}

	m := &managed{cmd: cmd, done: make(chan struct{})}
	s.mu.Lock()
	s.workers[r] = m
	s.mu.Unlock()

	s.svc(r, cmd.Process.Pid, true)

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		err := cmd.Wait()
		close(m.done)

		s.svc(r, 0, false)

		s.mu.Lock()
		stopped := s.stopped
		s.mu.Unlock()
		if stopped {
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
		if ctx.Err() != nil {
			return
		}
		if err := s.spawn(ctx, r); err != nil {
			// Losing a worker silently is worse than saying so.
			s.svc(r, 0, false)
		}
	}()

	return nil
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
