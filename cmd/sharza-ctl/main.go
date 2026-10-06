// SPDX-License-Identifier: GPL-3.0-or-later

// Command sharza-ctl is the Sharza command-line client. It is a thin,
// scriptable front end over the same RPC surface the web UI uses; it holds no
// state of its own and can run on a different host from the daemon.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/config"
	"github.com/jonathanvanherpe/sharza/internal/rpc"
	"github.com/jonathanvanherpe/sharza/internal/store"
	"github.com/jonathanvanherpe/sharza/internal/supervisor"
	"github.com/jonathanvanherpe/sharza/internal/version"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		fmt.Fprintf(os.Stderr, "sharza-ctl: %v\n", err)
		if rpc.IsUnavailable(err) {
			// The most common failure by far. Say what to do about it
			// rather than leaving a connection error as the last word.
			fmt.Fprintln(os.Stderr,
				"hint: is sharzad running? try `systemctl --user status sharzad`")
		}
		os.Exit(1)
	}
}

var errUsage = errors.New("usage")

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errUsage
	}

	fs := flag.NewFlagSet("sharza-ctl", flag.ContinueOnError)
	cfgFlag := fs.String("config", "", "path to the config file")
	sockFlag := fs.String("socket", "", "control socket path (overrides the config)")
	jsonFlag := fs.Bool("json", false, "emit raw JSON instead of a table")
	timeout := fs.Duration("timeout", 10*time.Second, "RPC timeout")

	// Flags may appear before or after the subcommand. FlagSet.Parse stops
	// at the first non-flag argument, which is exactly the subcommand, so
	// the verb can be recovered and the remainder re-parsed. Rolling this by
	// hand is a trap: a boolean flag like -json has no value, and any
	// splitter that cannot tell that swallows the subcommand.
	if err := fs.Parse(args); err != nil {
		return err
	}
	rest := fs.Args()
	if len(rest) == 0 {
		usage()
		return errUsage
	}
	verb, tail := rest[0], rest[1:]
	if !isVerb(verb) {
		usage()
		return fmt.Errorf("%w: unknown command %q", errUsage, verb)
	}
	if err := fs.Parse(tail); err != nil {
		return err
	}

	if verb == "add" && fs.NArg() == 0 {
		usage()
		return errUsage
	}

	cfg, err := config.Load(*cfgFlag)
	if err != nil {
		return err
	}
	sock := cfg.SocketPath
	if *sockFlag != "" {
		sock = *sockFlag
	}

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()

	c, err := rpc.Dial(sock, *timeout)
	if err != nil {
		return err
	}
	defer c.Close()

	switch verb {
	case "status":
		return cmdStatus(ctx, c, *jsonFlag)
	case "roles":
		return cmdRoles(ctx, c, *jsonFlag)
	case "jobs", "ls":
		return cmdJobs(ctx, c, *jsonFlag)
	case "add":
		return cmdAdd(ctx, c, fs.Args(), *jsonFlag)
	case "pause":
		return cmdMutate(ctx, c, rpc.MethodJobsPause, fs.Args(), *jsonFlag)
	case "resume":
		return cmdMutate(ctx, c, rpc.MethodJobsResume, fs.Args(), *jsonFlag)
	case "remove", "rm":
		return cmdMutate(ctx, c, rpc.MethodJobsRemove, fs.Args(), *jsonFlag)
	case "version":
		fmt.Printf("sharza-ctl %s (%s)\n", version.Version, version.Commit)
		return nil
	default:
		usage()
		return fmt.Errorf("%w: unknown command %q", errUsage, verb)
	}
}

func isVerb(s string) bool {
	switch s {
	case "status", "roles", "jobs", "ls", "add", "pause", "resume", "remove", "rm", "version":
		return true
	}
	return false
}

func usage() {
	fmt.Fprint(os.Stderr, `sharza-ctl - Sharza command-line client

Usage:
  sharza-ctl [flags] <command> [args]

Commands:
  status              supervisor status, workers, schema version
  roles               roles this build supports
  jobs                list jobs
  add <uri> [uri...]  queue a job
  pause <id>...       pause jobs
  resume <id>...      resume jobs
  remove <id>...      remove jobs
  version             print client version

Flags:
  -config <path>      config file
  -socket <path>      control socket (overrides the config)
  -json               raw JSON output
  -timeout <dur>      RPC timeout (default 10s)

Exit status is non-zero on failure, so this is safe to script.
`)
}

func cmdStatus(ctx context.Context, c *rpc.Client, asJSON bool) error {
	var st supervisor.Status
	if err := c.Call(ctx, rpc.MethodStatus, nil, &st); err != nil {
		return err
	}
	if asJSON {
		return emit(st)
	}

	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintf(tw, "version\t%s (%s)\n", st.Version, st.Commit)
	fmt.Fprintf(tw, "role\t%s\n", st.Role)
	fmt.Fprintf(tw, "pid\t%d\n", st.PID)
	fmt.Fprintf(tw, "uptime\t%s\n", time.Duration(st.UptimeSeconds*float64(time.Second)).Round(time.Second))
	fmt.Fprintf(tw, "schema\tv%d\n", st.SchemaVersion)
	fmt.Fprintf(tw, "jobs\t%d\n", st.Jobs)
	fmt.Fprintln(tw, "\nworkers")
	fmt.Fprintf(tw, "  ROLE\tPID\tSTATE\tRESTS\tUP\n")
	for _, w := range st.Workers {
		state := "down"
		if w.Alive {
			state = "up"
		}
		pid := "-"
		if w.PID != 0 {
			pid = fmt.Sprintf("%d", w.PID)
		}
		up := "-"
		if w.Alive && !w.StartedAt.IsZero() {
			up = time.Since(w.StartedAt).Round(time.Second).String()
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%d\t%s\n", w.Role, pid, state, w.Rests, up)
	}
	return tw.Flush()
}

func cmdRoles(ctx context.Context, c *rpc.Client, asJSON bool) error {
	var r supervisor.RolesReply
	if err := c.Call(ctx, rpc.MethodRoles, nil, &r); err != nil {
		return err
	}
	if asJSON {
		return emit(r)
	}
	fmt.Println("available:")
	for _, x := range r.Available {
		fmt.Printf("  %s\n", x)
	}
	fmt.Println("workers:")
	for _, x := range r.Workers {
		fmt.Printf("  %s\n", x)
	}
	return nil
}

func cmdJobs(ctx context.Context, c *rpc.Client, asJSON bool) error {
	var jobs []store.Job
	if err := c.Call(ctx, rpc.MethodJobsList, nil, &jobs); err != nil {
		return err
	}
	if asJSON {
		return emit(jobs)
	}
	if len(jobs) == 0 {
		fmt.Println("no jobs")
		return nil
	}
	tw := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "ID\tNAME\tSTATE\tPROGRESS\tVERIFIED\tSIZE")
	for _, j := range jobs {
		verified := "no"
		if j.Verified {
			verified = "yes"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d/%d\t%s\t%d\n",
			j.ID, j.Name, j.State, j.Complete, j.Size, verified, j.Size)
	}
	return tw.Flush()
}

func cmdAdd(ctx context.Context, c *rpc.Client, uris []string, asJSON bool) error {
	if len(uris) == 0 {
		return fmt.Errorf("%w: add needs at least one uri", errUsage)
	}
	// The server decides whether the job is verifiable; the client does not
	// get to assert it. See supervisor.uriHashed.
	var rep supervisor.AddJobReply
	if err := c.Call(ctx, rpc.MethodJobsAdd, supervisor.AddJobParams{
		URIs: uris,
	}, &rep); err != nil {
		return err
	}
	if asJSON {
		return emit(rep)
	}
	fmt.Printf("added %s (%s)\n", rep.Job.ID, rep.Job.Name)
	if !rep.Job.Verified {
		fmt.Println("note: no content hash, so this job cannot be verified")
	}
	return nil
}

func cmdMutate(ctx context.Context, c *rpc.Client, method string, ids []string, asJSON bool) error {
	if len(ids) == 0 {
		return fmt.Errorf("%w: %s needs at least one job id", errUsage, method)
	}
	// Every id is attempted even if one fails, so a typo in the middle of a
	// list does not silently skip the jobs after it. Failures are collected
	// and reported at the end.
	var results []supervisor.JobReply
	var failures []string
	for _, id := range ids {
		var rep supervisor.JobReply
		if err := c.Call(ctx, method, map[string]string{"id": id}, &rep); err != nil {
			failures = append(failures, fmt.Sprintf("%s: %v", id, err))
			continue
		}
		results = append(results, rep)
	}
	if asJSON {
		if err := emit(results); err != nil {
			return err
		}
	} else {
		for _, r := range results {
			fmt.Printf("%s -> %s\n", r.Job.ID, r.Job.State)
		}
	}
	if len(failures) > 0 {
		return fmt.Errorf("%d of %d failed:\n  %s",
			len(failures), len(ids), strings.Join(failures, "\n  "))
	}
	return nil
}

func emit(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}
