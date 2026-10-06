---
description: Run the full verification gate for Sharza. Use before claiming any change is done, and as the final step of a build cycle.
---

Run the verification gate for Sharza and report the result honestly. Do not
work around a failure to make the gate pass.

```sh
go build ./...
go vet ./...
go test ./...
```

Then the hygiene checks:

```sh
# SPDX header on every Go file (no rg on this host; grep is the portable one)
grep -rL 'SPDX-License-Identifier: GPL-3.0-or-later' --include='*.go' . || echo "(all files carry it)"

# no cgo in the daemon (must print nothing)
# CGO_ENABLED=0 is load-bearing, not decoration. With the default
# CGO_ENABLED=1 this prints runtime/cgo on any host, because the standard
# library's own net package has cgo files. That is a false positive that has
# nothing to do with the daemon, and a gate that cries wolf is a gate people
# learn to ignore.
CGO_ENABLED=0 go list -deps ./cmd/sharzad | grep -E '^(C|runtime/cgo)$' || echo "(no cgo)"

# and it must actually cross-compile with cgo off
CGO_ENABLED=0 go build ./...

# module path is correct
go list -m
```

Then confirm the tests actually assert something:

```sh
go test -run xxxNONExxx ./... 2>&1 | tail -20
```

This is a canary: if real tests report as "no tests to run", the suite is
vacuous and the real run above proved nothing.

The canary cannot tell you a test is *meaningful*, only that it exists. A test
that passes whether or not the code is correct is worse than no test, because
it reads as coverage. When you add a test that guards an invariant, break the
code on purpose and confirm the test fails before you believe it.

`go` is not on `PATH` in a non-interactive shell here. It lives in
`~/sdk/go/bin/go`. Use that absolute path unless you have checked.

Report per check: command, exit status, and what it means. Distinguish clearly
between **failing**, **passing**, and **skipped because the environment cannot
support it**. A skipped check must say so loudly, because a silent skip reads
exactly like a pass.

If something fails, stop and report it. Do not commit a partial result and do
not weaken a check to get to green. If the environment genuinely cannot run a
check (no netns, no oracle client installed), say that explicitly instead of
marking it passed.