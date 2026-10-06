# Sharza

Linux-native multi-protocol P2P client: BitTorrent, eDonkey2000/Kad and
Gnutella/Gnutella2 at once, with a daemon-first architecture and
namespace-based VPN isolation.

Read `docs/ARCHITECTURE.md` before changing anything structural. Read
`docs/ROADMAP.md` to find out what to work on next.

## Building

Go 1.27+ at `~/sdk/go` (the `go` symlink points at the active release).

```sh
go build ./...
go test ./...
```

## The build is agentic

This project is developed largely by autonomous agents. There is a harness in
`harness/` that picks the next roadmap item, runs an agent against it, verifies
the result and opens a merge request.

**Agents never merge to `main`.** Every cycle lands on an
`agent/<task-id>` branch with a merge request. The maintainer merges.

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