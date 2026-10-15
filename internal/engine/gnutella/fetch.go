// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Engine.Fetch joins the two requester-side primitives of a Gnutella 1
// transfer into one call: Engine.Search finds files, and Downloader
// moves the one that is tried. It is composition and nothing more: the
// QUERY it sends and the HTTP GET it performs are exactly the ones
// Search and Downloader already send, and no wire format is added here.
//
// The search half inherits Search's collection window: the QUERY runs
// to the full Options.SearchTimeout and returns whatever hits arrived,
// success or partial. Fetch must not shorten that, so it does not try:
// it takes Search's return value as given and only consults the context
// between transfer attempts. A caller that wants a shorter wait sets
// SearchTimeout; a caller that wants to abandon the whole thing
// cancels the context, which stops the transfers (Search itself has no
// context and still runs its window).
//
// Gnutella 1 has no content hash and no block protocol on this path, so
// the size a QUERYHIT declared is the only integrity check there is.
// Fetch does not add one: it delegates the check to Downloader and
// reports a transfer that failed as a failed candidate.

import (
	"context"
	"errors"
	"sort"
)

// ErrNoHits reports a search that found nothing to download: it
// returned no QUERYHIT at all. A QUERYHIT with an empty file list is a
// hit that names no file, which is ErrAllCandidatesFailed, not this.
var ErrNoHits = errors.New("gnutella: fetch: no hits")

// ErrAllCandidatesFailed reports a search that returned hits but left
// nothing to attempt: every QUERYHIT had an empty file list, so there
// was no (QUERYHIT, FileHit) candidate to hand to a Downloader. It is
// not the error for a set of attempts that all failed; that case returns
// the last transfer error instead, which says why they failed.
var ErrAllCandidatesFailed = errors.New("gnutella: fetch: no candidate to download")

// FetchResult describes a successful Engine.Fetch.
type FetchResult struct {
	// QueryHit is the QUERYHIT whose file won.
	QueryHit QueryHit

	// FileHit is the winning file within QueryHit.
	FileHit FileHit

	// Source is the host:port the QUERYHIT advertises as the file's
	// source (QueryHit.Source()), which is also where the GET was sent.
	Source string

	// Path is the file written, always inside the caller's directory.
	Path string

	// Bytes is how many bytes this transfer received and wrote. A
	// resumed transfer counts only the bytes it moved, not the prefix
	// that was already on disk.
	Bytes int64
}

// candidate is one (QUERYHIT, FileHit) pair to try, in the order Fetch
// considers it.
type candidate struct {
	qh  QueryHit
	hit FileHit
}

// Fetch searches for query, then downloads the first candidate that
// transfers, in order of descending declared FileSize (ties keep the
// order Search returned them). Each candidate is a new Downloader
// built from its own QUERYHIT, so a peer that answers a query need not
// be the peer that serves the file.
//
// It returns the first transfer that succeeds, or:
//
//   - ErrNoHits when the search returned no file to try;
//   - ErrAllCandidatesFailed when hits came back but none named a file;
//   - the last transfer error when every candidate was tried and every
//     one failed;
//   - the context error when the context ended before a candidate was
//     attempted, or the last transfer error if any candidate already
//     failed.
//
// Search can return hits alongside an error (a write to one peer failed
// but another answered); those hits are still usable, so Fetch tries them
// and only surfaces Search's error when it has nothing to try.
//
// The search runs its full collection window regardless of ctx; only the
// transfer attempts are cancellable. A failed transfer truncates its
// destination back to its starting offset (that is Downloader's
// contract), so a Fetch that ends in error does not leave a partial
// where a complete file should be.
func (e *Engine) Fetch(ctx context.Context, query, dir string) (FetchResult, error) {
	hits, searchErr := e.Search(query)
	cands := orderCandidates(hits)
	if len(cands) == 0 {
		if searchErr != nil {
			return FetchResult{}, searchErr
		}
		if len(hits) == 0 {
			return FetchResult{}, ErrNoHits
		}
		return FetchResult{}, ErrAllCandidatesFailed
	}

	var lastErr error
	for _, c := range cands {
		// Honour the context between candidates, before an attempt:
		// once cancelled there is no point starting another transfer.
		// If an earlier candidate already failed, report that failure
		// rather than the cancellation, because it is about the file.
		if err := ctx.Err(); err != nil {
			if lastErr != nil {
				return FetchResult{}, lastErr
			}
			return FetchResult{}, err
		}
		res, err := e.Downloader(c.qh, c.hit).Fetch(ctx, dir)
		if err == nil {
			return FetchResult{
				QueryHit: c.qh,
				FileHit:  c.hit,
				Source:   c.qh.Source(),
				Path:     res.Path,
				Bytes:    res.Bytes,
			}, nil
		}
		lastErr = err
	}
	// orderCandidates never returns an empty slice here, so the loop
	// above either returned a success or set lastErr exactly once per
	// candidate; the last of those is the one to report.
	return FetchResult{}, lastErr
}

// orderCandidates flattens the QUERYHITs into candidates and orders them
// the way Fetch considers them: largest declared FileSize first, so a
// transfer that is likely to take longest is not silently skipped in
// favour of a smaller one, and equal sizes keep the order Search
// returned them (a stable sort), so the result is deterministic rather
// than dependent on the sort implementation.
func orderCandidates(hits []QueryHit) []candidate {
	n := 0
	for _, qh := range hits {
		n += len(qh.Hits)
	}
	cands := make([]candidate, 0, n)
	for _, qh := range hits {
		for _, h := range qh.Hits {
			cands = append(cands, candidate{qh: qh, hit: h})
		}
	}
	sort.SliceStable(cands, func(i, j int) bool {
		return cands[i].hit.FileSize > cands[j].hit.FileSize
	})
	return cands
}
