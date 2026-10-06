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
# SPDX header on every Go file
rg -L 'SPDX-License-Identifier: GPL-3.0-or-later' --glob '*.go'

# no cgo in the daemon (must print nothing)
go list -deps ./cmd/sharzad | grep -E '^(C|runtime/cgo)$'

# module path is correct
go list -m
```

Then confirm the tests actually assert something:

```sh
go test -run xxxNONExxx ./... 2>&1 | tail -20
```

This is a canary: if real tests report as "no tests to run", the suite is
vacuous and the real run above proved nothing.

Report per check: command, exit status, and what it means. Distinguish clearly
between **failing**, **passing**, and **skipped because the environment cannot
support it**. A skipped check must say so loudly, because a silent skip reads
exactly like a pass.

If something fails, stop and report it. Do not commit a partial result and do
not weaken a check to get to green. If the environment genuinely cannot run a
check (no netns, no oracle client installed), say that explicitly instead of
marking it passed.