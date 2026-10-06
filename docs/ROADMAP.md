# Sharza Roadmap

Phases are ordered by **verifiability**, not by importance. A protocol can
only be developed safely if there is something to test it against, so the
networks with live populations and reference clients come first. Gnutella
ships last despite being the most sentimental part of the project, because
its protocol can be correct and still have nobody to talk to.

Each phase lists an exit gate. A phase is done when its gate passes, not when
its code compiles.

## Human gates

Items marked `human-gate: true` require a decision from the maintainer before
an autonomous agent proceeds. They ask via ntfy and wait.

Categories held behind a human gate:

- network namespace and other privileged code
- dependency additions and any licence change
- SQLite schema migrations
- anything that changes the RPC surface (clients depend on it)

Everything else is safe for the build harness to do unattended.

---

## P0 — Skeleton

`human-gate: false`

Supervisor, worker roles, RPC, store and CLI. No protocols at all. This
exists to prove the client-server contract before any protocol complexity
lands on top of it.

- `sharzad` binary with `--role` dispatch, role reporting over RPC
- UDS RPC with JSON-RPC, WebSocket event channel, filesystem-permission auth
- SQLite store with migrations and a settings snapshot
- `sharza-ctl` covering status, jobs, add, pause, remove
- embedded web UI shell, status page only
- systemd units: `sharzad.service`, `sharzad@.service`

**Exit gate:** two instances start, one supervises three workers, RPC answers
over UDS from `sharza-ctl`, state survives a restart, and killing a worker
leaves the supervisor and other workers healthy.

---

## P1 — BitTorrent

`human-gate: false`

Real downloads. First protocol with a live population, so it validates the
whole pipeline end to end early.

- `internal/engine/bt` on `anacrolix/torrent`
- magnet and `.torrent` handling, save/resume, recheck
- rate limits, per-job and global
- full job list, add, pause, resume, remove in web UI and CLI
- differential test against qBittorrent or Transmission on a local swarm

**Exit gate:** a torrent downloads to completion with verified pieces,
survives a daemon restart with no re-download, and completes a differential
exchange against the oracle.

---

## P2 — VPN kill-switch

`human-gate: true` (privileged code)

The first point at which the VPN goal is actually met.

- `sharzad-vpn-netns.service`, namespace preparation helper
- Vopono integration, documented setup
- worker drop-in with `NetworkNamespacePath=`
- verify tunnel-down causes zero traffic on the host interface

**Exit gate:** with the tunnel up, all worker traffic egresses via the VPN;
with the tunnel killed mid-transfer, traffic stops with none observed on the
host interface; the web UI stays reachable throughout both.

---

## P3 — Cross-network swarming, Level 1

`human-gate: false`

Parallel race across engines over a shared verified block store. Most of the
practical value of swarming is here, and it forces the eDonkey engine.

- canonical block map, default 1 MiB
- block scheduler with lease accounting
- verified block store, per-network verification
- range mapping for BitTorrent pieces
- sample-based source matching, name/size plus head/tail comparison

**Exit gate:** one file requested via two networks completes faster than
either network alone, with no duplicate fetching and every block verified.

---

## P4 — eDonkey2000 and Kad

`human-gate: false`

The largest single chunk of hand-written protocol work: ed2k TCP, Kad UDP,
obfuscation, AICH.

- server list handling, low-id and high-id states
- Kad bootstrap, routing, and source discovery
- obfuscated connection, AICH verification
- `.part.met` parsing and writing
- range mapping onto the canonical block map
- differential test against `amuled`

**Exit gate:** connects to a server, joins Kad, downloads a file verified
against its `.part.met`, and exchanges data with `amuled` on a local netns.

---

## P5 — Gnutella and Gnutella2

`human-gate: false`

Feature-flagged and off by default. Reference material is the g2.doxu.org
specification read alongside Shareaza's implementation.

- Gnutella 0.6: handshake, ping/pong, query routing, push, browse, download
- Gnutella2: tree packet codec, UDP transceiver, hub topology, query hash
  tables, `PART` completeness advertisement
- HTTP transfer layer for G2, and honest reporting of partial availability
- differential test against gtk-gnutella
- explicit **unverified job** state where a job is Gnutella-only

**Exit gate:** connects to at least one real Gnutella node, completes a
search and a download, exchanges blocks with gtk-gnutella, and the
unverified state is visible in the UI when no verifiable source exists.

**Honest risk:** swarm population may be too small for the last gate to pass.
That is an accepted outcome, not a blocker; it is why the phase is flagged.

**Do not build a G2 block mapper.** Shareaza's G2 has no fractional-transfer
header; see the correction in `docs/ARCHITECTURE.md`. G2 is a whole-file
source, not a block-mapped engine. Scope creep here would be building a
LimeWire-only extension no live peer will use.

---

## P6 — Desktop GUI and per-job VPN

`human-gate: true` (new apt dependencies, privileged routing)

- `sharza-desktop`, native shell over the existing web frontend
- per-job network namespaces, so one download can use the VPN and another
  deliberately not
- packaging: distro packages, Flathome notes

**Exit gate:** the desktop client drives the full feature set through the
existing RPC; two jobs route through different namespaces simultaneously.

---

## Later, unsequenced

Not committed. Recorded so the ideas are not lost.

- HTTP and FTP source search
- Direct Connect
- Soulseek, the largest remaining decentralized file-sharing network and a
  good candidate for restoring real decentralized search
- cross-seeding between a job and an existing local copy
- Level 2 leased scheduling, once Level 1 shows where contention actually is
- seeding-only mode with port-forward checks