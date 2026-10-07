# Handoff

Items noticed during a cycle and what became of them. Anything still open is
under **Open questions** at the bottom and is a maintainer decision, not a
blocker.

## Resolved in this cycle

### `go list -deps` reported `runtime/cgo` for a daemon with no cgo

The cgo check was `go list -deps ./cmd/sharzad | grep -E '^(C|runtime/cgo)$'`.
On any host with `CGO_ENABLED=1`, which is the default, that prints
`runtime/cgo`: the standard library's own `net` package has cgo files. It said
nothing about the daemon and would have failed on a pristine checkout.

The check is now `CGO_ENABLED=0 go list -deps`, which prints nothing on a clean
tree, plus a `CGO_ENABLED=0 go build ./...` to prove the cross-compile rather
than just asserting it. Fixed in `.opencode/command/verify.md` and in the
harness gate.

The general lesson is the one the handoff exists to record: a check that fails
for a reason unrelated to the tree is worse than no check, because it teaches
the reader to ignore it.

### `worker_restart_delay` was advertised in config and never read

The field existed, `Validate` did not look at it, and `StartWorkers` used the
`WorkerRestartDelay` constant unconditionally. An operator setting
`worker_restart_delay: 10s` got 2s and no warning.

`StartWorkers` now resolves the setting, `Validate` rejects an unparseable
value at startup rather than at the first worker death, and it rejects zero and
negative values too. That last one is not taste: the default's doc comment says
the delay is what stops a worker failing at startup from spinning the CPU, so
`"0s"` configures precisely the behaviour the default exists to prevent.

### `docs/ARCHITECTURE.md` claimed TOML; the code parses JSON

Corrected to `.json` in the naming table and in the native-Linux principle.
The doc was aspirational and the code never followed. Flagged here because the
same drift will reappear the moment packaging or a CLI starts writing config
files.

### The Go toolchain is not on `PATH` in a non-interactive shell

It is only exported by an interactive `zshrc`. The supervisor tests resolve it
explicitly (`$GO`, `$GOROOT/bin`, `~/sdk/go/bin`, the system paths) before
deciding to skip.

This matters more than it looks. A bare `exec.LookPath("go")` would have made
every process-level test skip, and **a skip reads as a pass in a CI log**. A
suite that silently stops testing because it cannot find the compiler is
indistinguishable from a suite that is green.

### The `sharza-ctl` half of the P0 exit gate is now demonstrated

`internal/supervisor/ctl_test.go` builds `cmd/sharza-ctl` once (mirroring
`buildDaemon`) and runs the real binary against a real supervisor over its UDS.
`TestSharzaCtlAnswersOverUDS` asserts status (pid, role, schema), `-json
status`, add, jobs, pause and resume from stdout and the exit code;
`TestSharzaCtlReportsUnavailableDaemon` asserts the non-zero exit and the
`is sharzad running?` hint when no daemon is there.

The assertions were checked against a deliberate mutation: making the client
dial a bogus socket turned `TestSharzaCtlAnswersOverUDS` red (a dial error,
not a compile error), then was reverted. A CLI test that passes with the socket
path ignored would have been worse than none.

## Open questions

### The process-level orphan test was vacuous, and is now not

`TestStopLeavesNoOrphanWorkers` asserts that workers are gone after the
supervisor stops, which is the invariant P2's VPN work rests on. It was
untestable as written: the real worker is a leaf, so signalling its pid and
signalling its process group are indistinguishable. Confirmed by mutating
`Stop` to signal single pids and watching the test stay green.

`TestStopLeavesNoOrphanWorkerDescendants` now runs a worker that grows a
grandchild inheriting the worker's process group. Signalling the group clears
both; signalling the pid leaves the grandchild alive holding engine traffic
with no control plane. The mutation test now fails as it should.

The worker now also asserts that the pid the supervisor *reports* is the pid in
the fixture's pidfile. An earlier version of this test started its own copy of
the fake worker to read pids from, and consequently failed against correct code
for the reason that `Stop` had never heard of it.

### The tests build `sharzad` with `go build` per suite, not per test

Deliberate: one `sync.Once` build shared by the package. It is a
test-compilation cost paid once, but it does mean a rebuild is not triggered if
the daemon source changes mid-run.

### No oracle clients yet

No protocol engine exists, so nothing is compared against `amuled`,
`qBittorrent` or `gtk-gnutella`. That becomes a real gap the moment P1 lands,
at which point differential testing against a known-good client should be
part of the exit gate rather than an afterthought. With the 2026-10-07
reorder, P1 is Gnutella/Gnutella2, so gtk-gnutella is the first oracle
needed.
