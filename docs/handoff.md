# Handoff

Items noticed during a cycle and what became of them. Anything still open is
under **Open questions** at the bottom and is a maintainer decision, not a
blocker.

## Resolved in this cycle

### Gnutella 1 download: search -> download is now one call (`Engine.Fetch`)

`internal/engine/gnutella/fetch.go` adds `Engine.Fetch(ctx, query, dir)`, the
single artifact for the P1 exit gate's "completes a search and a download"
criterion. It is composition only: it calls `Engine.Search(query)`, flattens
the returned `[]QueryHit` into `(QueryHit, FileHit)` candidates, and for each
in turn builds `Engine.Downloader(qh, hit)` and calls its `Fetch(ctx, dir)`
until one transfer succeeds. No wire format, no new message type, no new
integrity check.

The exported signatures of `Engine.Search`, `Engine.Downloader` and
`Downloader.Fetch` are unchanged; `Fetch` sits above them. Gnutella 1 stays
whole-file: nothing here touches the canonical 1 MiB block map, and size
remains the only integrity check (delegated to `Downloader`, not re-implemented).

Four decisions the next slice will want to know:

- **Candidate order is deterministic: descending declared `FileSize`, ties by
  first-seen.** `orderCandidates` uses `sort.SliceStable`, so equal sizes keep
  the order `Search` returned them rather than depending on the sort
  implementation. The test lists the larger hit *second*, so only a correct
  descending sort reaches it first.
- **The `FetchResult` reports the winning `QueryHit`, `FileHit`, `Source`
  (`QueryHit.Source()`), sanitised `Path` and `Bytes` actually written by this
  transfer.** `Source` reuses `QueryHit.Source()` (which already used
  `strconv`), not a hand-rolled integer formatter.
- **Errors are distinct per situation.** No QUERYHIT at all -> `ErrNoHits`.
  QUERYHITs came back but none named a file (an empty catalogue still produces
  a zero-hit QUERYHIT) -> `ErrAllCandidatesFailed`. Every candidate was tried
  and every one failed -> the *last transfer error* is returned directly, so
  the caller sees why (e.g. `ErrSizeMismatch`), not a generic sentinel.
  Context cancelled before a candidate is attempted -> `context.Canceled`.
- **`Options.SearchTimeout` semantics are inherited, not shortened.** `Search`
  has no context and still runs its full collection window; `Fetch` only
  consults `ctx` between transfer attempts, so cancelling abandons the
  transfers without truncating the search.

**Mutation checks (both performed and reverted).** Blanking the declared-size
body check in `download.go` (`n != want`) turned
`TestFetchAllCandidatesMismatchLeavesNoPartial` red (the mismatch transfer was
accepted, then the test failed on "Fetch succeeded"). Reversing the candidate
sort in `fetch.go` (`>` to `<`) turned
`TestFetchOrdersCandidatesByDescendingSize` red (the small hit won). Both were
restored; the working tree carries no mutation.

### A strict two-engine loop could not be the test: the engine has no upload side

The brief asked for a two-engine loop in which engine A holds a `Catalogue`
and engine B searches and fetches it. That cannot complete today, and the
tests are shaped around why: the engine answers a QUERY from its `Catalogue`
with a QUERYHIT, but the address that QUERYHIT advertises (`handleQuery` uses
the answering engine's own listen address and port) is the Gnutella listener,
which speaks the 0.6 handshake, not the servent HTTP download. So engine B's
`Fetch` would GET engine A's Gnutella port and fail. No branch in the tree
serves uploads either.

The end-to-end test therefore uses a scripted Gnutella 0.6 servent (a plain
TCP peer, as `peer_test.go` uses) to answer the QUERY, and a real
`httptest.NewServer` as the HTTP servent the QUERYHIT points at. Both halves
run over real TCP, so `Engine.Fetch` itself (Search, then Downloader) is the
thing under test; only the "one process both answers the query and serves the
file" convenience is scripted. When the engine grows an upload side, that file
is what a two-engine loop replaces.

A prior cycle's branch (`agent/20261013-afh8y`) carried a rough version of
this same slice. Its faults were the ones the brief named and this cycle
fixed: it wrote a hand-rolled `itoa`, reported a zeroed descriptor ID it could
not actually know (a QUERYHIT echoes the id but `Search` does not return it),
and left `docs/handoff.md` untouched. It was not merged; this is the clean
artifact.

**The oracle leg was not run.** gtk-gnutella is the differential oracle named
for this leg and is **not installed here** (no root, no sudo), so nothing above
claims oracle verification. The evidence is the scripted servent over real TCP
plus the `httptest` HTTP servent over real TCP. Report the oracle as
*skipped*, not passed.

## Open questions

### Download client: decisions left open (carried forward)

- **Resume is implicit and `Fetch` does not expose it.** `Downloader.Fetch`
  continues whatever partial file the sanitised name hits; `Engine.Fetch` adds
  no caller-supplied offset and no cross-candidate retry/backoff, exactly as
  the brief scopes. If a job store maps hits to explicit paths, an
  offset/destination parameter is the natural extension.
- **`Bytes` in `FetchResult` is bytes moved by the winning transfer, not the
  file's total length.** A resumed transfer counts only what it fetched. A
  caller that wants the on-disk size reads the file; if `FetchResult` should
  report total size instead, that is a small, deliberate change.
- **HTTP/1.1, not the convention's HTTP/1.0.** `net/http` sends HTTP/1.1; real
  Gnutella servents answer both, but that is untested here because no oracle
  client can be installed.
- **No retry and no re-verification of a resumed prefix.** A resume trusts the
  bytes already on disk; only size is checked, and Gnutella 1 offers nothing
  with which to check them.

### Wiring and scope deliberately not taken (each its own slice, some are gates)

- **The RPC surface is untouched.** `Engine.Fetch` has no `sharza-ctl`/RPC
  verb and no job-store entry; wiring a new RPC method is a human gate.
- **Persisting hits or progress to the store is out of scope** (schema
  migration is a human gate); `Fetch` writes only to the directory it is given.
- **`push` and `browse`** are separate sub-items of the same bullet. Sibling
  branches exist (`agent/20261014-bqt2d`, `agent/20261014-d0yu1` for the push
  downloader half; `agent/20261012-eebxw` for browse), none merged to `main`
  at this cycle's start.
- **The G2 half of P1 is untouched**: tree packet codec, UDP transceiver, hub
  topology, query hash tables, `PART` completeness.

### No oracle clients yet (unchanged)

No protocol engine is compared against `amuled`, `gtk-gnutella` or
`qBittorrent`; those are not installed and this host denies `sudo`. That
becomes a real gap the moment P1 is declared done: differential testing against
a known-good client belongs in the exit gate rather than after it. For P1 that
oracle is gtk-gnutella, and for this leg it did not run.

### Noticed, not touched: `query.go` and `query_test.go` are not gofmt-clean

`gofmt -l internal/engine/gnutella/` flags `query.go` and `query_test.go`;
both are unformatted already at `main` (confirmed against `HEAD`, not this
cycle's edits). The build and vet gates pass, so it is cosmetic, and it was
left alone rather than folded into this slice. A one-line `gofmt -w` should
ride with whichever change next touches those files.
