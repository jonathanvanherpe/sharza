// SPDX-License-Identifier: GPL-3.0-or-later

// Command forker is a fake worker for TestStopLeavesNoOrphanWorkers.
//
// It exists because the real worker is a leaf, and the distinction the test
// turns on is between signalling a process group and signalling a single pid.
// With a leaf process the two are indistinguishable, so a test written against
// the real worker passes whether the supervisor gets this right or wrong. That
// is the worst property a test can have: it looks like it guards the
// invariant and it cannot.
//
// So this stands in for the worker and deliberately grows a grandchild that
// inherits the worker's process group, which is how a real engine's VPN helper
// or storage thread would sit. Under P2 that grandchild is holding the
// engine's traffic, which is why Setpgid and kill(-pid) exist at all.
//
// The grandchild is left signalable on purpose: the supervisor's SIGTERM
// should clear it promptly, so the test stays fast and the assertion is
// sharp. If the group signal is missing, it survives and the test fails.
//
// It reports its pids to $SHARZA_TEST_PIDFILE, one line per process. The
// supervisor deliberately leaves a worker's stdio nil, so stdout is not a
// channel the test can read; and the test needs the pids of the worker
// StartWorkers spawned, not of a second copy it started itself.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"time"
)

const pidfileEnv = "SHARZA_TEST_PIDFILE"

func main() {
	// No SysProcAttr: the grandchild inherits the worker's process group, so
	// the group-directed signal in Stop() reaches it. Setting its own group
	// here would hide the very bug this program is built to expose.
	child := exec.Command("/bin/sh", "-c", "while true; do sleep 1; done")
	if err := child.Start(); err != nil {
		fmt.Fprintf(os.Stderr, "forker: start grandchild: %v\n", err)
		os.Exit(1)
	}

	line := fmt.Sprintf("worker %d %d\n", os.Getpid(), child.Process.Pid)
	fmt.Print(line)

	if path := os.Getenv(pidfileEnv); path != "" {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forker: open pidfile: %v\n", err)
			os.Exit(1)
		}
		// Write in one call: the test reads concurrently, and a torn line
		// would show up as a parse failure rather than a test failure.
		if _, err := f.WriteString(line); err != nil {
			fmt.Fprintf(os.Stderr, "forker: write pidfile: %v\n", err)
			os.Exit(1)
		}
		_ = f.Close()
	}

	// Hold the group open. If the worker exits on its own the grandchild is
	// reparented and the test would be measuring something other than what it
	// claims to measure.
	for {
		time.Sleep(time.Second)
	}
}
