# Handoff

Items noticed during a cycle and what became of them. Anything still open is
under **Open questions** at the bottom and is a maintainer decision, not a
blocker.

## Resolved in this cycle

### `go list -deps` reported `runtime/cgo` for a daemon with no cgo

The cgo check was `go list -deps ./cmd/sharzad | grep -E '^(C|runtime/cgo)$'`.
On any host with `CGO_ENABLED=1`, which is the default, that prints
`runtime/cgo`: the standard library's own `net` package has cgo files. It said
nothing about the daemon and would have failed on a pristine checkout.

The check is now `CGO_ENABLED=0 go list -deps`, which prints nothing on a clean
tree, plus a `CGO_ENABLED=0 go build ./...` to prove the cross-compile rather
than just asserting it. Fixed in `.opencode/command/verify.md` and in the
harness gate.

The general lesson is the one the handoff exists to record: a check that fails
for a reason unrelated to the tree is worse than no check, because it teaches
the reader to ignore it.

### `worker_restart_delay` was advertised in config and never read

The field existed, `Validate` did not look at it, and `StartWorkers` used the
`WorkerRestartDelay` constant unconditionally. An operator setting
`worker_restart_delay: 10s` got 2s and no warning.

`StartWorkers` now resolves the setting, `Validate` rejects an unparseable
value at startup rather than at the first worker death, and it rejects zero and
negative values too. That last one is not taste: the default's doc comment says
the delay is what stops a worker failing at startup from spinning the CPU, so
`"0s"` configures precisely the behaviour the default exists to prevent.

### `docs/ARCHITECTURE.md` claimed TOML; the code parses JSON

Corrected to `.json` in the naming table and in the native-Linux principle.
The doc was aspirational and the code never followed. Flagged here because the
same drift will reappear the moment packaging or a CLI starts writing config
files.

### The Go toolchain is not on `PATH` in a non-interactive shell

It is only exported by an interactive `zshrc`. The supervisor tests resolve it
explicitly (`$GO`, `$GOROOT/bin`, `~/sdk/go/bin`, the system paths) before
deciding to skip.

This matters more than it looks. A bare `exec.LookPath("go")` would have made
every process-level test skip, and **a skip reads as a pass in a CI log**. A
suite that silently stops testing because it cannot find the compiler is
indistinguishable from a suite that is green.

### The `sharza-ctl` half of the P0 exit gate is now demonstrated

`internal/supervisor/ctl_test.go` builds `cmd/sharza-ctl` once (mirroring
`buildDaemon`) and runs the real binary against a real supervisor over its UDS.
`TestSharzaCtlAnswersOverUDS` asserts status (pid, role, schema), `-json
status`, add, jobs, pause and resume from stdout and the exit code;
`TestSharzaCtlReportsUnavailableDaemon` asserts the non-zero exit and the
`is sharzad running?` hint when no daemon is there.

The assertions were checked against a deliberate mutation: making the client
dial a bogus socket turned `TestSharzaCtlAnswersOverUDS` red (a dial error,
not a compile error), then was reverted. A CLI test that passes with the socket
path ignored would have been worse than none.

### The Gnutella handshake brief contradicts the published wire format

The task brief for the P1 Gnutella handshake item specified `PUSH 0x03` and a
big-endian 4-byte payload length. Both conflict with the published protocol
(the annotated 0.4 spec at rfc-gnutella.sourceforge.net and the 0.6 RFC
draft): payload types are `0x00 Ping, 0x01 Pong, 0x02 Bye, 0x40 Push, 0x80
Query, 0x81 QueryHit`, and every multi-byte message field is little-endian
("All fields ... are in little-endian byte order unless otherwise specified"),
IPv4 addresses being the exception.

`internal/engine/gnutella` implements the published values: `MsgPush = 0x40`,
length decoded little-endian, PONG payload port little-endian with the IPv4
address big-endian. With the brief's values the engine could not have
connected to any real node, which is this item's whole acceptance gate, so
there was no honest way to follow the brief here: real peers (gtk-gnutella,
LimeWire, Shareaza) speak the spec, not the brief. The brief's
`x-gnutella-network` header extraction is still implemented (case-insensitive,
as `Handshake.Network()`), even though the header appears in neither RFC.

A second, subtler divergence: the 0.6 draft would have PONG replies handled by
the pong-caching scheme (TTL + Hops = 7, and no reply to a PING with TTL 0),
while the brief pins an observable "PONG for each PING with TTL decremented"
and a drop-at-zero rule. The brief's contract is implemented, because it is
what the tests can hold the daemon to on a direct link; it is dead-simple and
correct for the one-hop case the engine actually has, and the drop-at-zero
rule is what stops TTL-minus-one replies from being answered in a loop. The
trade is recorded in `peer.go` and covered by mutation-tested tests (TTL
decrement, GUID echo, and the TTL-0 drop each go red when removed).

### Gnutella bootstrap: GWebCache client, and the caches still alive in 2026

P1's loose end was that a daemon only ever dialed what the operator typed.
`internal/engine/gnutella/webcache.go` now fetches a GWebCache URL and feeds
the addresses into the same per-peer dial goroutine the configured
`gnutella_peers` use, so backoff and retry behaviour are identical whichever
source named the host, and an address named twice (by config and a cache, or
by two caches) gets exactly one loop. Config is `gnutella_caches`, validated
like `gnutella_peers`.

**The 2017-era webcache network is still partially alive.** Verified by
curl on 2026-10-09 (fetch only, no dial — the swarm is near-empty in 2026, so
the dial side is covered by the httptest-backed
`TestEngineDialsCacheFetchedPeer` instead). All four answered with host
lists when the parameterised form was used, and all four were re-checked
with the `Sharza/<version>` User-Agent the client sends:

| URL that works | bare GET | `?client=0.1.0.0+Sharza&get=1&net=gnutella2` |
| --- | --- | --- |
| `http://midian.jayl.de/g2/gwc.php` | XHTML "upgrade your browser" error page | 16 `H|` hosts, `U|` and `I|` lines |
| `http://cache.jayl.de/g2/gwc.php` | same error page | hosts |
| `http://gweb3.4octets.co.uk/gwc.php` | same error page | hosts |
| `http://dkac.trillinux.org/dkac/dkac.php/` | "This is DKAC/Enticing-Enumon" banner | hosts, as lowercase `h|` |

Three findings from that smoke test, all now handled or recorded:

- **The paths matter.** `dkac.trillinux.org` and `gweb3.4octets.co.uk` at
  their roots are a parked page and a 301 respectively; the working paths
  are the ones their `U|` lines advertise. Worse, Go's redirect handling
  follows the 301 to `/gwc.php` *without* re-attaching the query, so
  configuring the root URL of gweb3 silently yields zero hosts. Configure
  the direct path.
- **Line types are not consistently cased.** DKAC serves `h|` where the
  others serve `H|`, so `parseCacheBody` matches the type
  case-insensitively (Shareaza matches `i|` case-insensitively too).
- **`I|` lines are not always three fields.** Beacon Cache sends
  `I|access|period|33`, which Shareaza reads as the access period. The
  parser keeps everything between the first and last pipe as Key
  (`access|period`) and the last field as Value (`33`), so the three-field
  form from the brief parses as written and nothing is lost on the
  four-field one.

Two request shapes exist: the older caches serve the bare list on GET,
while the gweb3/4octets and Beacon families only answer
`?client=<4>+<ver>&get=1&net=<net>`. The client issues each shape exactly
once (no retry loop — retries live in the engine's dial loops) and uses
whichever yields more `H|` lines. The `+` in the client parameter is sent
literally rather than as `%2B`, because those caches split their query
strings naively.

The host filter drops malformed/out-of-range `host:port`, unspecified
addresses (`0.0.0.0`, `::`) and loopback addresses (`127.0.0.1`, `::1`,
`localhost`). `U|` URLs are parsed and kept but not yet polled, and `I|`
values (e.g. `AccessPeriod`) are logged and kept but nothing paces on them
yet.

### The live ultrapeers need `Accept-Encoding: deflate`, and the caches answer per network

Dialing the real 2026 swarm (through the GWebCache client above, and
directly) settled two things a scripted peer could not.

**The ultrapeers are gtk-gnutella 1.3.1 (built 2026-03-09), and they refuse
an uncompressed leaf link.** A CONNECT with no `Accept-Encoding` draws `403
Gnet connection not compressed`; adding `Accept-Encoding: deflate` draws
`200 OK` and a zlib-wrapped (RFC 1950) TX stream installed at handshake
completion. `peer.go` now offers `deflate`, and `inflate.go` decodes the
result, sniffing the first two bytes because HTTP's "deflate" is ambiguous
between the zlib wrapper and a bare RFC 1951 stream. Our own TX stays
uncompressed: the offer says what we read, not what we write. The mirror
image is handled too -- a peer that declares `Content-Encoding: deflate` on
the accept path (in its CONNECT or its confirmation; gtk-gnutella honours
both) has its stream inflated from the first message on.

**The live caches answer per network.** `net=gnutella` returns the
gtk-gnutella ultrapeers that complete a handshake; `net=gnutella2` returns
mostly Shielded Shareaza-family leaves that answer `503 Shielded leaf node`
and refuse everything unsolicited. The lists are disjoint, so neither can be
a "winner": both are fetched and merged (`cacheNets`, `mergeCacheResult`).

Verified against a live node on 2026-10-10: `sharzad` completed the 0.6
handshake with `gtk-gnutella/1.3.1-dirty (2026-03-09; ...)` and then decoded
and answered 1606 QUERY messages from its compressed stream over ~2 minutes
with no errors -- the inflate path exercised by real traffic, not a scripted
peer.

A side observation, already known: the per-peer dial loop retries every
`dialBackoff` (5s) forever, and against the tiny live swarm that earned `429
Banned for 5m` from several nodes inside a minute. Graduated backoff is still
open.

### A leaf must say it is a leaf: `X-Ultrapeer: False`

Once the gzip issue was gone, the rest of the swarm answered `403 Normal
nodes refused` / `503 No X-Ultrapeer`. gtk-gnutella classifies an incoming
peer that sends neither X-Ultrapeer nor X-Ultrapeer-Needed as a "normal
node" (`nodes.c`, `NODE_A_NO_ULTRA`) and refuses it once its normal-node
slots are full. The outbound CONNECT now sends `X-Ultrapeer: False` and
`X-Ultrapeer-Needed: True` (the BearShare-era equivalent, sent together as
LimeWire leaves do), which is the truthful claim: the engine is a leaf, it
has no routing responsibilities.

Re-run against the live swarm 2026-10-10: **7 of 7 configured
gtk-gnutella 1.3.1 ultrapeers completed the handshake, all `compressed=true`
(gtk-gnutella on Linux x86_64/i686, FreeBSD amd64, Windows x64), no decode
errors.** Remaining refusals are server-side leaf-slot policy, not missing
headers: `503 Not Good Leaf` (gtk-gnutella's leaf evaluation), `503 Shielded
leaf node` (the net=gnutella2 population), `503 Too many leaf connections`,
and one `429 Banned for 5m` from the 5s dial hammering. `Remote-IP` in the
outbound CONNECT was also sending `addr:port`; it now strips the port like
the accept path does.

## Open questions

### Should the daemon ship default `gnutella_caches`?

The field defaults to empty, so bootstrap only happens when the operator
lists a cache. The four caches above are known alive as of 2026-10-09 and
could be the default (zero-config bootstrap, which is the point of the item),
but defaults that start network traffic are a maintainer decision: they make
a fresh daemon phone home to third-party 2017-era servers on first start,
and someone has to own keeping that list honest as those caches die.

### Loopback filtering vs the engine test seam

`FetchHosts` drops loopback addresses as a policy for untrusted cache
content, but the mandated engine test points a cache at a loopback listener
(and a test may not reach the network). The compromise is the unexported
`Options.cacheAllowLoopback` field: production code never sets it, only the
in-package test does. If that seam is unwelcome, the alternatives are a
test-only accessor or letting the engine dial loopback from caches at all —
the second would weaken the filter for no production gain, since no live
cache has a reason to hand out `127.0.0.1`.

### Bootstrap scope deliberately not taken

Out of scope for this item, each its own piece of work: polling the `U|`
cache URLs the fetches return, pacing on the `I|` values, persisting fetched
hosts to the store (a restart re-fetches instead), submitting our own
address to a cache, the UDP host cache (`uhc:`), and G2 discovery via the
KHL / `ukhl:` packets. The `net=gnutella` fetch is now done as well and
merged with `net=gnutella2` (the two live populations are disjoint; see the
resolved entry above).

### The process-level orphan test was vacuous, and is now not

`TestStopLeavesNoOrphanWorkers` asserts that workers are gone after the
supervisor stops, which is the invariant P2's VPN work rests on. It was
untestable as written: the real worker is a leaf, so signalling its pid and
signalling its process group are indistinguishable. Confirmed by mutating
`Stop` to signal single pids and watching the test stay green.

`TestStopLeavesNoOrphanWorkerDescendants` now runs a worker that grows a
grandchild inheriting the worker's process group. Signalling the group clears
both; signalling the pid leaves the grandchild alive holding engine traffic
with no control plane. The mutation test now fails as it should.

The worker now also asserts that the pid the supervisor *reports* is the pid in
the fixture's pidfile. An earlier version of this test started its own copy of
the fake worker to read pids from, and consequently failed against correct code
for the reason that `Stop` had never heard of it.

### The tests build `sharzad` with `go build` per suite, not per test

Deliberate: one `sync.Once` build shared by the package. It is a
test-compilation cost paid once, but it does mean a rebuild is not triggered if
the daemon source changes mid-run.

### No oracle clients yet

No protocol engine exists, so nothing is compared against `amuled`,
`qBittorrent` or `gtk-gnutella`. That becomes a real gap the moment P1 lands,
at which point differential testing against a known-good client should be
part of the exit gate rather than an afterthought. With the 2026-10-07
reorder, P1 is Gnutella/Gnutella2, so gtk-gnutella is the first oracle
needed.

### The gtk-gnutella oracle check for the P1 handshake was **SKIPPED, not passed**

The engine's `gnutella_peers`/`gnutella_listen` config exists so a two-client
loop (sharzad vs gtk-gnutella) is a config change away, but the check itself
did not run: gtk-gnutella is not installed, and this environment has no root
and denies `sudo`, so `apt-get install` cannot happen here. Nothing above
claims oracle verification; the handshake and PING/PONG are verified against
scripted Go peers over real TCP (including the 0.4-refusal path), and the wire
format follows the published spec so the oracle loop should work when a
maintainer runs it on a host with root. Do not read this as a pass. The
engine's behaviour on an unsupported 0.4 CONNECT is a 503 refusal, which is
deliberate: 0.6 backward compatibility was decided out of scope.

**Update 2026-10-10: the oracle was reached over the network, though not as
the scripted two-client loop.** The engine completed a real 0.6 handshake
with a live `gtk-gnutella/1.3.1-dirty (2026-03-09)` ultrapeer and decoded the
QUERY traffic it then sent over the compressed stream (see the resolved entry
above). That is stronger evidence than a scripted peer for the wire format
and the compression negotiation, but it is not the controlled differential
loop this entry describes: it does not exercise a 0.4 refusal from the real
client, and it depends on a third party's uptime rather than a local binary.
The loop remains the wanted artifact.

### PONG replies use "request TTL minus one", not the 0.6 pong-caching policy

See the resolved entry above: the brief's observable contract
(TTL decremented, drop at zero) is what the engine implements, and the tests
pin it. The 0.6 draft's pong-caching scheme (a cached PONG answers any PING
with a matching hash, TTL + Hops = 7) is the maintainer's call to revisit
before anything resembling routing or horizon logic lands. The mutation tests
would then need updating in the same change.
