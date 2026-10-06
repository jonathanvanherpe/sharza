// SPDX-License-Identifier: GPL-3.0-or-later

// Command sharzad is the Sharza daemon. One binary, several roles:
//
//	sharzad --role=supervisor   control plane, RPC endpoint, store, web UI
//	sharzad --role=bt           BitTorrent worker
//	sharzad --role=ed2k         eDonkey2000 worker
//	sharzad --role=g2           Gnutella/Gnutella2 worker
//
// Workers are spawned by the supervisor and never run standalone in normal
// operation. The supervisor binds the control socket; workers talk to it over
// the same RPC surface and hold no authoritative state.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/config"
	"github.com/jonathanvanherpe/sharza/internal/role"
	"github.com/jonathanvanherpe/sharza/internal/rpc"
	"github.com/jonathanvanherpe/sharza/internal/store"
	"github.com/jonathanvanherpe/sharza/internal/supervisor"
	"github.com/jonathanvanherpe/sharza/internal/version"
	"github.com/jonathanvanherpe/sharza/internal/web"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "sharzad: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		roleFlag  = flag.String("role", string(role.Supervisor), "process role")
		cfgFlag   = flag.String("config", "", "path to the config file")
		verFlag   = flag.Bool("version", false, "print version and exit")
		noWorkers = flag.Bool("no-workers", false, "run the supervisor without spawning workers")
	)
	flag.Parse()

	if *verFlag {
		fmt.Printf("sharzad %s (%s)\n", version.Version, version.Commit)
		return nil
	}

	r, err := role.Parse(*roleFlag)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(),
		os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch {
	case r == role.Supervisor:
		return runSupervisor(ctx, *cfgFlag, *noWorkers)
	case role.IsWorker(r):
		return runWorker(ctx, r, *cfgFlag)
	default:
		return fmt.Errorf("unhandled role %q", r)
	}
}

func runSupervisor(ctx context.Context, cfgPath string, noWorkers bool) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	st, err := store.Open(store.FileStoreOptions{Path: cfg.StatePath()})
	if err != nil {
		return err
	}
	defer st.Close()

	disp := rpc.NewDispatcher()
	svc := supervisor.New(st, disp)

	srv := rpc.NewServer(disp, cfg.SocketPath)
	if err := srv.Listen(); err != nil {
		return err
	}
	defer srv.Close()

	srvErr := make(chan error, 1)
	go func() { srvErr <- srv.Serve(ctx) }()

	var sup *supervisor.Supervisor
	if !noWorkers {
		// os.Executable, not os.Args[0]: a worker spawned under a bare
		// name is resolved through PATH, and the daemon is routinely
		// started as "sharzad" from systemd with no useful PATH.
		self, err := os.Executable()
		if err != nil {
			return fmt.Errorf("locate own executable to spawn workers: %w", err)
		}
		sup, err = supervisor.StartWorkers(ctx, cfg, svc.ReportWorker, self)
		if err != nil {
			return fmt.Errorf("start workers: %w", err)
		}
		defer sup.Stop()
	} else {
		svc.ReportAllWorkersDown()
	}

	httpSrv, err := web.Serve(ctx, cfg.WebListen, cfg.SocketPath)
	if err != nil {
		return err
	}
	defer httpSrv.Close()

	fmt.Fprintf(os.Stderr,
		"sharzad: supervisor pid=%d socket=%s web=%s state=%s schema=%d workers=%v\n",
		os.Getpid(), cfg.SocketPath, cfg.WebListen, cfg.StatePath(),
		mustSchemaVersion(st), cfg.WorkerRoles)

	select {
	case <-ctx.Done():
		fmt.Fprintln(os.Stderr, "sharzad: shutting down")
		return nil
	case err := <-srvErr:
		return err
	}
}

func runWorker(ctx context.Context, r role.Role, cfgPath string) error {
	cfg, err := config.Load(cfgPath)
	if err != nil {
		return err
	}

	// A worker is useless without the control plane, and must not linger
	// as a zombie that looks healthy to the user. Give up quickly and let
	// the supervisor restart us instead.
	if err := awaitSupervisor(ctx, cfg); err != nil {
		return fmt.Errorf("%s worker: %w", r, err)
	}

	fmt.Fprintf(os.Stderr, "sharzad: %s worker pid=%d\n", r, os.Getpid())
	<-ctx.Done()
	fmt.Fprintf(os.Stderr, "sharzad: %s worker stopped\n", r)
	return nil
}

func awaitSupervisor(ctx context.Context, cfg *config.Config) error {
	const (
		interval = 250 * time.Millisecond
		timeout  = 30 * time.Second
	)
	deadline := time.Now().Add(timeout)
	for {
		c, err := rpc.Dial(cfg.SocketPath, interval)
		if err == nil {
			_ = c.Close()
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("supervisor socket %s unreachable after %s: %w",
				cfg.SocketPath, timeout, err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(interval):
		}
	}
}

func mustSchemaVersion(st store.Store) int {
	v, err := st.SchemaVersion()
	if err != nil {
		return -1
	}
	return v
}
