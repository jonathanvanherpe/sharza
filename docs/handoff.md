# Handoff

Items that were noticed during a cycle but deliberately left alone, with the
reason. Nothing here is a blocker; each is a decision for the maintainer.

## Open questions

### `go list -deps ./cmd/sharzad` reports `runtime/cgo` even though the daemon has no cgo

The P0 gate's cgo check is `go list -deps ./cmd/sharzad | grep -E '^(C|runtime/cgo)$'`.
On any host with `CGO_ENABLED=1` (the default) that prints `runtime/cgo`, because
the standard library's own `net` package has cgo files there
(`go list -deps -f '{{.CgoFiles}}' ./cmd/sharzad` shows `net cgo=[cgo_linux.go ...]`).
It is pre-existing: `HEAD` before this cycle prints it too, and no dependency was
added.

`CGO_ENABLED=0 go list -deps ./cmd/sharzad` prints nothing, which is the shape the
check intends to assert (no cgo in the daemon itself, it still cross-compiles).
Worth changing the gate to prefix `CGO_ENABLED=0`, otherwise it fails for a reason
that has nothing to do with the tree.

### Should `Validate` reject a non-positive `worker_restart_delay`?

`"-1s"` and `"0s"` parse, so they are accepted. A negative delay makes
`time.After` fire immediately, which is exactly the spin the
`WorkerRestartDelay` doc comment exists to prevent. This cycle's brief scoped
validation to "must be a duration", so only parseability is checked. Worth
deciding separately whether the floor should be `>= 0` or `> 0`.

### The Go toolchain is not on `PATH` in a non-interactive shell

`harness/sharza-dev.mjs` resolves `go` explicitly (`$GO`, `$GOROOT/bin`,
`~/sdk/go/bin`, `/usr/local/go/bin`, `/usr/bin`) because the toolchain here is
only exported by an interactive zshrc. The new process-level supervisor tests
resolve it the same way before skipping, rather than using `exec.LookPath("go")`
alone. With a bare lookup, `go test ./...` run by the harness would have skipped
all four exit-gate tests as "no go found", and a skip reads as a pass in a CI log.

If the toolchain ever *is* missing, the skip says so in those words rather than
passing quietly.

### `docs/ARCHITECTURE.md` says the config is TOML; the code parses JSON

Pre-existing, not touched: the naming table lists `/etc/sharza/sharza.toml` and
`~/.config/sharza/sharza.toml`, while `internal/config` decodes JSON with
`DisallowUnknownFields`. Worth deciding which one is real before packaging or a
CLI starts writing config files.

### The P0 exit gate also mentions `sharza-ctl`

`docs/ROADMAP.md` gates P0 on "RPC answers over UDS from `sharza-ctl`". This cycle
covered the supervisor lifecycle half of the gate; `sharza-ctl` is not exercised
by these tests, so the bullet is not yet fully demonstrated.