# Sharza development harness

Runs the agentic build loop: pick the next roadmap item, branch, build it with
an agent, verify independently, and open a branch for review.

**The harness never merges to `main`.** Every cycle ends on an
`agent/<task-id>` branch. Merging is the maintainer's job. That is the whole
reason this is a harness and not a bot with write access.

## Usage

```sh
node harness/sharza-dev.mjs --dry-run     # plan only, change nothing
node harness/sharza-dev.mjs --once        # one full cycle
node harness/sharza-dev.mjs --status      # show state and cooldowns
node harness/sharza-dev.mjs --task "..."  # skip selection, use this brief
node harness/sharza-dev.mjs --test-notify # send one real notification
```

State lives in `harness/.state/` and is gitignored.

## One cycle

1. **Select.** A strong model runs `/next-task` and returns a brief. If the
   item is `human-gate`, the agent stops instead of building it.
2. **Branch.** `agent/<date>-<slug>` from `origin/main`, so a cycle never
   builds on an unmerged branch and the MR diff stays reviewable.
3. **Build.** A routed model implements the brief in a fresh session. It is
   told not to commit or push.
4. **Verify.** `go build`, `go vet`, `go test` run **by the harness**, not
   taken from the agent's report. An agent that says it verified something is
   a claim, not evidence.
5. **Commit and push** only if verification passed and something changed.

A cycle that fails verification does not commit. It pushes nothing, leaves the
branch for inspection, and notifies.

## Model routing

`router.mjs` discovers models at runtime via `opencode models` rather than
hardcoding a list, because ids and availability change.

| tier | tools | candidates |
| --- | --- | --- |
| `strong` | yes | `opencode/big-pickle`, then Gemini flash/pro |
| `fast` | yes | older Gemini flash, free OpenCode models |
| `local-weak` | **no** | Ollama models |

`local-weak` is marked tool-free on purpose. The local models are weak at tool
use and will report having edited files they never touched. Handing one an
edit task produces a confident, broken result.

There is no spending cap. Quota is a rate limit to ride, not a budget to
enforce; on a 429 or equivalent the model goes into a 30-minute cooldown in
`harness/.state/cooldowns.json` and the next cycle routes around it.

## Permissions

The agent runs with `opencode run --auto`, which auto-approves anything *not
explicitly denied*. The denials in `opencode.json` are therefore the real
safety boundary, not the flag. They cover `sudo`, forced pushes, pushes to
`main`, `rm -rf` of the repo or home, `dd`, `mkfs`, piping curl into a shell,
and service stop/restart/disable.

Outside that, edits, builds, tests and pushes to `agent/*` branches are all
allowed unattended, because an agent that stops to ask about every file write
is not worth running.

## IPv4

`ntfy.mjs` uses `node:http` with an IPv4-pinned DNS lookup rather than
`fetch`. This host has no global IPv6 route, and Node's fetch/undici turns the
resulting IPv6 `ENETUNREACH` into an `AggregateError [ETIMEDOUT]` for the whole
request against a dual-stack host. That silently ate an earlier notification.
Keep the custom lookup if this file is edited.

## Human gates

These stop and ask via ntfy rather than proceeding:

- network namespaces and other privileged code
- new dependencies and any licence change
- SQLite schema migrations
- anything changing the RPC surface

The SQLite driver (`modernc.org/sqlite`) is currently the open gate. `P0` uses
a dependency-free JSON store so the control plane could be proven without it;
swap in the SQLite implementation behind the same `store.Store` interface once
the dependency is approved.

## Files

- `sharza-dev.mjs` — the cycle
- `router.mjs` — model discovery and routing
- `ntfy.mjs` — notifications, IPv4-pinned