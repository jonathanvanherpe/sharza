# Sharza

Linux-native multi-protocol P2P client: BitTorrent, eDonkey2000/Kad and
Gnutella/Gnutella2 at once, with a daemon-first architecture and
namespace-based VPN isolation.

Read `docs/ARCHITECTURE.md` before changing anything structural. Read
`docs/ROADMAP.md` to find out what to work on next.

Read `docs/handoff.md` for what the last cycle left undecided. It records open
questions and the reasoning behind recent decisions, so it is the fastest way
to find out what is deliberately unfinished rather than accidentally broken.

## Building

Go 1.27+ at `~/sdk/go`.

```sh
~/sdk/go/bin/go build ./...
~/sdk/go/bin/go test ./...
```

**`go` is not on `PATH` in a non-interactive shell.** The toolchain is only
exported by an interactive `zshrc`, so a bare `go` fails in a script, a
systemd unit or an agent's subprocess. Use the absolute path, or resolve it
first. This is worth stating plainly because the failure looks like a build
error rather than a missing PATH, and a test suite that cannot find the
compiler skips itself — and a skip reads as a pass in a CI log.

## The build is agentic

This project is developed largely by autonomous agents. There is a harness in
`harness/` that picks the next roadmap item, runs an agent against it, and
verifies the result independently before committing anything.

```sh
node harness/sharza-dev.mjs --dry-run   # plan only
node harness/sharza-dev.mjs --once      # one full cycle
node harness/sharza-dev.mjs --status    # past cycles and model cooldowns
```

The harness is strictly one-shot. It has no scheduler, no loop and no timer,
so it will not start anything on its own.

**Agents may merge to `main`.** Every cycle lands on an `agent/<task-id>`
branch; once the verify gate and any live check pass, the cycle may
fast-forward it into `main` and push (`git merge --ff-only` from `main`,
or `git push origin <branch>:main`). Fast-forward only — force pushes and
`git reset --hard` stay blocked, so history is never rewritten.

**`origin` is `git@github.com:jonathanvanherpe/sharza.git`.** The harness
pushes its branch there after verification, and a cycle that ran entirely
on the machine can do the same; the branch is mergeable as one click.

**The agent's own report is not evidence.** The harness re-runs build, vet,
test, the cgo-free build and the SPDX check itself, and refuses to commit when
they fail. When you add a test that guards an invariant, break the code on
purpose and confirm the test fails before you believe it: a test that passes
whether or not the code is correct is worse than no test, because it reads as
coverage.

If you are an agent: run `go build ./...`, `go vet ./...`, `go test ./...` and
the SPDX header check before you consider anything done. Read
`docs/ARCHITECTURE.md` for the load-bearing decisions, especially the canonical
block map, and do not "improve" it without understanding why each engine maps
the way it does.

## Protocol references

Read-only reference checkouts live in `~/Projects/sharza-references/`,
deliberately outside this repository. Shareaza is GPLv2 and is read as
reference and oracle only; no code is copied from it. Do not vendor any of it
into the tree.

- `shareaza/` — Gnutella2 reference implementation (GPLv2)
- `g2-spec/` — the published G2 specification at g2.doxu.org

Oracles for differential testing, none of which are linked or shipped:

- `amuled` (aMule) for eDonkey
- `gtk-gnutella` for Gnutella
- qBittorrent or Transmission for BitTorrent

## Licence

GPL-3.0-or-later. `internal/engine/bt` wraps MPL-2.0 code and is kept as a
clean boundary so the MPL surface stays isolated.