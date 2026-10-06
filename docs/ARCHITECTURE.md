# Sharza Architecture

Sharza is a Linux-native, multi-protocol P2P file sharing client with a
daemon-first architecture. It speaks BitTorrent, eDonkey2000/Kad and
Gnutella/Gnutella2 simultaneously, and can fetch a single logical file from
more than one network at the same time.

## Naming

| Surface | Name |
| --- | --- |
| Project / brand | **Sharza** |
| Daemon binary | `sharzad` |
| CLI | `sharza-ctl` |
| Desktop GUI | `sharza-desktop` |
| Go module | `github.com/jonathanvanherpe/sharza` |
| Supervisor unit | `sharzad.service` |
| Worker units | `sharzad@bt.service`, `sharzad@ed2k.service`, `sharzad@g2.service` |
| VPN namespace unit | `sharzad-vpn-netns.service` |
| Config | `/etc/sharza/sharza.toml`, `~/.config/sharza/sharza.toml` |
| State | `/var/lib/sharzad`, `~/.local/state/sharzad` |
| RPC socket | `/run/sharzad/rpc.sock` |
| Netns | `/run/netns/sharza-vpn` |
| SPDX | `GPL-3.0-or-later` |

The name is a deliberate nod to Shareaza (2002-2017), which ran the same four
networks from Windows. Sharza is an independent GPL-3.0-or-later project; it
shares no code with Shareaza or its forks.

## Design goals, in priority order

1. **Every byte goes through the VPN if the operator says so.** This is a
   correctness property, not a preference.
2. **One download, many networks.** A file request fans out across protocols.
   This is the feature Shareaza was known for and the reason it has no
   modern equivalent.
3. **Headless-first.** The daemon is the product; the UI is a client of it.
   Nothing requires a GUI, a terminal, or a display server.
4. **Native Linux.** systemd, netns, TOML config, distro packaging. No
   cross-platform abstraction layer.

## Process model

One binary, many roles:

```
sharzad --role=supervisor    control plane: RPC, web UI, store, scheduler
sharzad --role=bt            data plane: BitTorrent peers, trackers, DHT
sharzad --role=ed2k          data plane: eDonkey2000 + Kad
sharzad --role=g2            data plane: Gnutella + Gnutella2
```

**Why one binary rather than three.** Separate per-engine binaries mean N
packages, N upgrade paths and N ways for versions to skew while a worker is
attached to a stale library. A single binary gives one version string and one
artifact. Role separation is still preserved at the process level, which is
the only place it actually matters, because the isolation boundary is the
process.

The supervisor supervises workers by restarting them on exit, and exposes the
set of live workers over RPC. A worker that dies takes only its own network
down.

### Supervisor and data plane

The split is deliberate and is what makes the VPN guarantee achievable. The
supervisor holds the RPC socket, the web UI and the store. Workers hold only
peer sockets. Two consequences follow:

- The web UI and RPC stay reachable even when the VPN is down, so an operator
  can see *why* nothing is transferring.
- Killing a worker cannot corrupt control-plane state, because workers do not
  write the store.

### systemd units

`sharzad.service` runs the supervisor. `sharzad@.service` is a template
instantiated per worker:

```ini
[Service]
ExecStart=/usr/bin/sharzad --role=%i
```

A template unit matters because it lets a single drop-in give any worker its
own network namespace, which is what the VPN integration needs.

## VPN integration

Requirements, in order of strength:

1. All peer traffic leaves via a chosen interface.
2. When the tunnel drops, traffic stops entirely. No silent fallback to the
   host's default route.
3. The control plane remains reachable.

The approach is a Linux **network namespace**, not interface binding.

Interface binding (`SO_BINDTODEVICE`, qBittorrent's "network interface")
setting) satisfies (1) in the happy path and fails (2). Real deployments leak
when the tunnel drops, because a bound socket fails closed for new
connections while existing sockets and the DNS resolver and tracker announces
still reach the real interface. Setting an *invalid* bind to force a fail-closed
behaviour is fragile and breaks loudly on legitimate reconnects.

The namespace approach:

- The worker runs in `/run/netns/sharza-vpn`, wired via
  `NetworkNamespacePath=` in its unit drop-in.
- All its sockets are physically incapable of using the host's default route.
  There is no configuration to get wrong, and no leak window.
- The supervisor stays in the root namespace, so (3) is automatic.

The namespace and its tun device are prepared by a separate privileged helper
unit, `sharzad-vpn-netns.service`. **The daemon never requires privilege
itself**, which keeps the unprivileged case working and means a broken tunnel
cannot escalate.

Sharza does not implement its own VPN client. It integrates with **Vopono**,
which already creates the namespace, runs OpenVPN/WireGuard inside it and
installs nftables leak protection, including the post-tunnel-down handling.
Reimplementing that is out of scope and would be worse.

Later phases route *individual jobs* into their own namespaces. The process
boundary that already exists is what makes that a configuration change rather
than a redesign.

## Cross-network swarming

This is the core novel component.

### The canonical block map

Every job owns a block map: a bitmap over the file divided into fixed-size
canonical blocks (1 MiB default, configurable). The block size is chosen to
align with the eDonkey part size so that network maps onto the map without
loss.

Each engine implements an adapter translating canonical block ranges to and
from its native transfer unit, and receives block leases from the scheduler.

| Network | Native transfer unit | Range mapping |
| --- | --- | --- |
| BitTorrent | Pieces, 16 KiB - 4 MiB | Set of pieces overlapping a canonical block |
| eDonkey2000 | Fixed ~9500 KiB parts, each with an MD4 in `.part.met` | Near 1:1 by construction |
| Gnutella2 | HTTP transfer, `PART` completeness hint | File level; announced partials only |
| Gnutella 1 | Whole file plus byte range | File level only, no block participation |

**Correction (verified against Shareaza `G2Packet.h`).** This design originally
claimed Gnutella2 exposes a fractional-transfer header, `UFTT`/`UFSet`, which
made G2 the motivation for the 1 MiB canonical block. That is wrong.
`UFSet`/`UFGet`/`UFTT` are **LimeWire's** Gnutella2 extension, not Shareaza's,
and a full-tree `rg -i UFTT shareaza/` returns zero hits. Shareaza's G2
(`/QH2`, in `G2Packet.h` and `G2Packet.cpp`) is a different dialect that carries
neither.

What Shareaza's G2 actually has is `G2_PACKET_PARTIAL` (`PART`, comment
`/QH2/H/PART - Partial Content Tag`). Reading its only writer,
`CLocalSearch::AddHitG2` in `LocalSearch.cpp:880-900`, the payload is not a
block map at all: it is the count of *already complete bytes*, written as a
big-endian `DWORD` when the total is under 4 GiB and a `QWORD` otherwise. It
exists so a querying peer can discard you as a source for a range it still
needs. Data itself moves over HTTP, not over the G2 UDP packet layer.

The consequences are worth stating plainly, because they change the design:

- G2 cannot advertise *which* blocks it holds, only *how much*. It therefore
  cannot participate in block-level swarming.
- The 1 MiB canonical block is kept because it aligns with the eDonkey part
  and BitTorrent pieces, **not** because of G2.
- G2 joins Level 1 swarming only as a whole-file source, competing with Gnutella
  1 rather than with the block-mapped engines.

So the swarming story rests on BitTorrent and eDonkey. G2 remains a network
worth speaking, because it carries live peers and browse/search traffic, but it
must not be presented as the fractional-transfer engine it is not.

### Two levels

**Level 1 (parallel, shared verified store).** All engines race on the same
job. Whichever engine completes a verified block first keeps it; the others
discover it is done and move on. This is what mlDonkey calls *swarming*, and
it is where most of the practical benefit is.

**Level 2 (leased).** A central scheduler partitions the work and issues
explicit leases, so no two engines fetch the same block. This is the endgame,
needed only when engines disagree strongly about which part of a file is
cheapest to fetch.

Level 1 first. Level 2 is an optimisation over an already-correct Level 1.

### Content identity is the hard part

Networks do not agree on how to name a file. BitTorrent identifies by SHA-1
piece hashes, eDonkey by an MD4 tree, Gnutella has no content addressing at
all. Combining sources therefore requires two separate mechanisms.

**Verification** of bytes already fetched:

- If a job has a BitTorrent source, SHA-1 piece hashes verify everything any
  engine produced.
- If it has an eDonkey source, the MD4 per part in `.part.met` does the same.
- **A Gnutella-only job cannot be verified.** Gnutella supplies no
  per-block hashes. The UI must label such a job unverified, and the
  scheduler must not treat its blocks as trustworthy for a job that also has a
  verifiable source.

**Matching** two candidate sources as the same file is a separate problem,
since the networks' hashes are not comparable. The approach:

1. Match candidates on name and size.
2. Sample-verify before committing: compare the first and last 64 KiB of each
   candidate's first available block.
3. Where available, pin identity to a user-supplied known hash (SHA-1 or MD4).

Step 2 exists to prevent splicing two different files into one corrupt
output. It is a heuristic, not a proof, and the roadmap treats it as
replaceable.

## Protocol notes

### BitTorrent

Handled by `github.com/anacrolix/torrent`: v1.61.0, MPL-2.0, actively
maintained, in production since 2014. Covers protocol encryption, DHT, PEX,
uTP, WebTorrent, web seeds, BTv2 and holepunching, with blob/file/mmap/sqlite
storage backends.

MPL-2.0 is compatible with GPL-3.0, so this dependency does not constrain the
project licence. `internal/engine/bt` is kept as a clean boundary so the
MPL-licensed surface is isolated from the rest of the tree.

**Rejected: a hand-written libtorrent FFI shim.** libtorrent-rasterbar is the
reference C++ implementation and is genuinely well-tested. The Go bindings
are all dead (the `libtorrent` crate stopped in 2022; `lt-rs` is negligible;
`PeterDing/libtorrent-rasterbar-rs` is stale since 2025). Writing a shim means
cgo against C++ with boost, exceptions, and callbacks from C++ worker threads
into Go, which is a real deadlock hazard needing a strict handoff discipline.
It also forfeits cross-compilation and forces boost onto every target's
runtime. For a project whose differentiator is cross-network block
scheduling, `anacrolix/torrent`'s piece-priority control is more valuable than
libtorrent's extra feature surface.

### eDonkey2000 and Kad

Hand-written. Roughly 6-10k lines covering the ed2k TCP protocol, Kad over
UDP, obfuscation and AICH.

Hand-written rather than wrapped from `aMule` (GPL) for one decisive reason:
block-level cooperation. An external client with its own piece picker cannot
participate in the canonical block map, which would make Level 1 swarming
across ed2k and BitTorrent impossible. `amuled` remains a differential oracle
in tests, which is where its value is.

### Gnutella and Gnutella2

Hand-written, feature-flagged, off by default.

Gnutella2's published specification at g2.doxu.org covers the wire format, UDP
transceiver, packet structure, query hash tables and the search architecture.
It is thin in places and, being Shareaza's own design, is most usefully read
alongside a working implementation.

The practical risk is **swarm population, not protocol correctness**. The
protocol can be implemented correctly and still find no peers. gtk-gnutella
(v1.3.1, maintained) is the differential oracle. Gnutella ships behind a flag
and is best-effort by design.

Shareaza's source is GPLv2 and is kept at
`~/Projects/sharza-references/`, deliberately outside this repository. It is
read as reference and test oracle. No code is copied from it; a C++ to Go
rewrite makes incidental copying implausible, and the "or later" clause on
this project exists for patent protection, not to pull in GPLv2 fragments.

## RPC

- Unix domain socket at `/run/sharzad/rpc.sock` for local access. Filesystem
  permissions are the primary access control, matching how transmission and
  rtorrent behave.
- TCP is opt-in, for remote access, and requires a bearer token. It is never
  bound to a wildcard address without one.
- JSON-RPC over HTTP, with a WebSocket channel for the event stream so UIs get
  push updates without polling.

`sharza-ctl` and the web UI are both thin clients of this one interface.

## Storage

SQLite via a pure-Go driver, so the daemon stays cgo-free and
cross-compilable. Holds job metadata, per-engine state, scheduler leases and
the settings snapshot.

Written by the supervisor only. Workers are stateless from the store's
perspective and report progress over their supervisor channel.

## Front ends

One web frontend, two delivery mechanisms:

- **Web UI**, embedded in the daemon with `go:embed` and served from the
  supervisor. Reachable from any browser including a phone, which is the
  point of a headless daemon.
- **`sharza-ctl`**, a CLI over the same RPC for scripting and for machines
  where a browser is not the right tool.
- **Desktop GUI**, a later phase, built on the same web frontend so it is a
  thin native shell rather than a second UI codebase.

The daemon has no cgo dependency. Anything needing cgo lives in the desktop
GUI binary alone, which keeps the daemon cross-compilable and its packaging
simple.

## Repository layout

```
sharza/
  cmd/sharzad              supervisor and workers, one binary
  cmd/sharza-ctl           CLI client
  cmd/sharza-desktop       native shell (later phase)
  internal/rpc             UDS + HTTP/JSON-RPC + WebSocket events
  internal/store           SQLite schema and migrations
  internal/supervisor      process lifecycle, event bus
  internal/scheduler       canonical block map, leases
  internal/netns           netns/Vopono integration
  internal/engine/bt       anacrolix adapter
  internal/engine/ed2k     eDonkey2000 + Kad
  internal/engine/gnutella Gnutella 1 + 2
  web/                     frontend, embedded via go:embed
  harness/                 agentic build harness
  packaging/systemd/       units
  docs/                    this document and the roadmap
```

## Build and test gates

Every change must pass:

- `go build ./...`
- `go vet ./...`
- `go test ./...`
- SPDX header present on every `.go` file
- no cgo introduced into the daemon (`go list -deps` check)

Protocol work additionally requires a differential test against its oracle:
`amuled` for ed2k, gtk-gnutella for Gnutella, qBittorrent or Transmission for
BitTorrent. Network namespaces and VPN tests are skippable when the
environment cannot support them, and skip loudly rather than silently.

No test touches a public swarm.

## Attribution

Sharza stands on the shoulders of several projects, none of whose code it
includes:

- **Shareaza** (2002-2017), the original multi-protocol client, and the source
  of the Gnutella2 design this project follows.
- **gtk-gnutella**, the maintained Gnutella client used as an oracle and the
  best reference for current protocol behaviour.
- **aMule** and **mlDonkey**, whose eDonkey/Kad behaviour and swarming
  semantics are the reference for the ed2k engine.
- **anacrolix/torrent**, the BitTorrent engine (MPL-2.0).
- **Vopono**, for namespace-based VPN isolation.

Protocol specifications are facts. Behaviour was verified against running
clients rather than inferred from documentation.