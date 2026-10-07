# Sharza Roadmap

Phases are ordered by maintainer priority, balanced against verifiability.
Gnutella/Gnutella2 is deliberately first: it is the project's origin — Sharza
is the Shareaza successor — and its honest risk, a small live population, is
accepted rather than a blocker. Stage two and three of the engines follow
(BitTorrent, then eDonkey2000/Kad), with cross-network swarming once two
block-mapped engines exist to race against each other.

Every protocol phase still needs something to test against. The references
are: the g2.doxu.org specification read alongside Shareaza's implementation
for Gnutella/G2, gtk-gnutella as oracle, qBittorrent or Transmission for
BitTorrent, and amuled for eDonkey.

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

Settled decisions from the maintainer (2026-10-07): the BitTorrent engine may
use `anacrolix/torrent` (MPL-2.0) behind the existing `internal/engine/bt`
clean boundary — **use a library until it limits what we can do**. Gnutella/G2
has no usable library, so it is hand-rolled from the G2 spec and Shareaza
reference from the start.

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

## P1 — Gnutella and Gnutella2

`human-gate: false`

The first real engine, and the project's origin. Reference material is the
g2.doxu.org specification read alongside Shareaza's implementation.

- Gnutella 0.6: handshake, ping/pong, query routing, push, browse, download
- Gnutella2: tree packet codec, UDP transceiver, hub topology, query hash
  tables, `PART` completeness advertisement
- HTTP transfer layer for G2, and honest reporting of partial availability
- differential test against gtk-gnutella
- explicit **unverified job** state where a job is Gnutella-only
- full job list, add, pause, resume, remove in web UI and CLI against a real
  engine (this is the first phase the UI controls something real)

**Exit gate:** connects to at least one real Gnutella node, completes a
search and a download, exchanges blocks with gtk-gnutella, and the
unverified state is visible in the UI when no verifiable source exists.

**Honest risk:** swarm population may be too small for the last gate to pass.
That is an accepted outcome, not a blocker.

**Do not build a G2 block mapper.** Shareaza's G2 has no fractional-transfer
header; see the correction in `docs/ARCHITECTURE.md`. G2 is a whole-file
source, not a block-mapped engine. Scope creep here would be building a
LimeWire-only extension no live peer will use.

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

## P3 — BitTorrent

`human-gate: false`

Second real engine. `internal/engine/bt` wraps `anacrolix/torrent` (MPL-2.0,
maintainer-approved) behind the existing clean boundary. The choice is
provisional per the settled policy: use the library until it limits what we
can do, then fork or hand-roll what it cannot express.

- magnet and `.torrent` handling, save/resume, recheck
- rate limits, per-job and global
- verified piece checksums against the job's hash
- differential test against qBittorrent or Transmission on a local swarm

**Exit gate:** a torrent downloads to completion with verified pieces,
survives a daemon restart with no re-download, and completes a differential
exchange against the oracle.

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

## P5 — Cross-network swarming, Level 1

`human-gate: false`

Parallel race across the two block-mapped engines (BitTorrent and
eDonkey2000) over a shared verified block store. Gnutella/G2 joins as a
whole-file source. Most of the practical value of swarming is here.

- canonical block map, default 1 MiB
- block scheduler with lease accounting
- verified block store, per-network verification
- range mapping for BitTorrent pieces
- sample-based source matching, name/size plus head/tail comparison

**Exit gate:** one file requested via two networks completes faster than
either network alone, with no duplicate fetching and every block verified.

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