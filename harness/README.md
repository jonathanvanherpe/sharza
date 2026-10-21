# Sharza development harness

Runs the agentic build loop: pick the next roadmap item, branch, build it with
an agent, verify independently, and open a branch for review.

**The harness never merges to `main`.** Every cycle ends on an
`agent/<task-id>` branch and opens a pull request against `main` for review.
Merging is the maintainer's job. That is the whole reason this is a harness
and not a bot with write access.

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
5. **Commit, push, and open a pull request** only if verification passed and
   something changed. The pull request targets `main`, for the maintainer to
   review and merge.

A cycle that fails verification does not commit. It pushes nothing, leaves the
branch for inspection, and notifies.

## Pull requests

After a successful push the harness opens a pull request against `main`
(`github.mjs`). It needs a GitHub token in `GITHUB_TOKEN` (or `GH_TOKEN`) with
`pull_requests: write` and `contents: read` on the repository. Without one the
pull request cannot be created; the cycle still pushes its branch and the
notification falls back to a compare URL a human can open. The token is read
from the environment, which the `sharza-dev.service` unit supplies via
`~/.config/opencode/github.env` (`GITHUB_TOKEN=...`).

## Model routing

`router.mjs` discovers models at runtime via `opencode models` rather than
hardcoding a list, because ids and availability change.

| tier | tools | candidate order |
| --- | --- | --- |
| `strong` | yes | Go Haiku 5.5, then Go DeepSeek/MiMo/GLM flash and other Go models; non-Go fallbacks last |
| `fast` | yes | free Go MiniMax/Beam/LongCat, then low-cost Go flash models; non-Go fallbacks last |
| `local-weak` | **no** | Ollama models |

Which tier is tried first depends on the brief. `classifyDifficulty()` scores
each brief as `easy` or `normal` with a bias toward `normal`: an `easy` cycle
starts at `fast`, a `normal` one starts at `strong`, and both climb only when
the preferred tier is unreachable. The classifier is deliberately conservative
and can be overridden with `SHARZA_DIFFICULTY=easy|normal`.

The Go candidates are ordered by task difficulty and current model availability.
OpenCode enforces the Go plan's model-specific usage allowances; on a quota
failure, the affected model is cooled down for 30 minutes and the next cycle
tries the next available candidate. The harness does not read or predict live
allowance balances. Non-Go providers, including Google, are only configured as
last-resort fallbacks. Project subagents inherit the routed model rather than
pinning themselves to a separate provider.

`local-weak` is marked tool-free on purpose. The local models are weak at tool
use and will report having edited files they never touched. Handing one an
edit task produces a confident, broken result; it is only ever selected for
work routed with `needsTools: false`, where it is preferred because it is free.

There is no spending cap. Quota is a rate limit to ride, not a budget to
enforce; on a 429 or equivalent the model goes into a 30-minute cooldown in
`harness/.state/cooldowns.json` and the next cycle routes around it. The cycle
records that cooldown itself: when a build run fails, `reportCooldown()` scans
the run's stderr and the tail of stdout (opencode reports provider errors as
JSON events there) and writes the entry if the failure looks quota-shaped.

## Permissions

The agent runs with `opencode run --auto` from the repository working
directory (V2 uses `cwd` as the project location; do not pass the removed V1
`--dir` flag). `--auto` approves anything *not explicitly denied*. The denials
in `opencode.json` are therefore the real safety boundary, not the flag. They
cover `sudo`, forced pushes, pushes to `main`, `rm -rf` of the repo or home,
`dd`, `mkfs`, piping curl into a shell, and service stop/restart/disable.

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
- `github.mjs` — opens the pull request, IPv4-pinned
