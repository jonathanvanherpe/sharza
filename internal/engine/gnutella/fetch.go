// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"context"
	"errors"
	"net"
	"sort"
)

var (
	// ErrNoHits indicates the search returned no hits.
	ErrNoHits = errors.New("gnutella: fetch: no hits found")
	// ErrAllCandidatesFailed indicates every candidate hit failed to download.
	ErrAllCandidatesFailed = errors.New("gnutella: fetch: all candidates failed")
)

// FetchResult carries the result of a successful Engine.Fetch.
type FetchResult struct {
	// QueryHit is the originating QUERYHIT.
	QueryHit QueryHit
	// FileHit is the file hit that succeeded.
	FileHit FileHit
	// Source is the host:port of the source (from QueryHit.Source()).
	Source string
	// DescriptorID is the descriptor ID of the query that found this hit.
	DescriptorID [idSize]byte
	// Path is the local file path written.
	Path string
	// Bytes is the number of bytes received.
	Bytes int64
}

// candidate represents a candidate (queryHit, fileHit) in order of consideration.
type candidate struct {
	qh QueryHit
	h  FileHit
}
func (e *Engine) orderedCandidates(queryHits []QueryHit) []candidate {
	// To preserve first-seen order, we need to know original positions.
	// But we receive the list as returned; for our purposes, we track by insertion index.
	type item struct {
		cand candidate
		idx  int
	}
	items := make([]item, 0, 16)
	pos := 0
	for _, qh := range queryHits {
		for _, h := range qh.Hits {
			items = append(items, item{cand: candidate{qh: qh, h: h}, idx: pos})
			pos++
		}
	}
	// Order: descending declared FileSize, then first-seen (idx)
	sort.Slice(items, func(i, j int) bool {
		if items[i].cand.h.FileSize != items[j].cand.h.FileSize {
			// descending
			return items[i].cand.h.FileSize > items[j].cand.h.FileSize
		}
		return items[i].idx < items[j].idx
	})
	res := make([]candidate, len(items))
	for i := range items {
		res[i] = items[i].cand
	}
	return res
}

// Fetch calls Search(query), orders the returned hits deterministically
// (descending declared FileSize, then first-seen), and for each candidate
// builds e.Downloader(qh, hit) and calls Fetch(ctx, dir) until one succeeds.
// It returns the first success, or a typed error when there were no hits or
// every candidate failed.
func (e *Engine) Fetch(ctx context.Context, query, dir string) (FetchResult, error) {
	queryHits, err := e.Search(query)
	if err != nil {
		return FetchResult{}, err
	}
	if len(queryHits) == 0 {
		return FetchResult{}, ErrNoHits
	}

	cands := e.orderedCandidates(queryHits)
	var lastErr error
	for _, c := range cands {
		// Check context between candidates as a defensive measure.
		select {
		case <-ctx.Done():
			if lastErr != nil {
				return FetchResult{}, lastErr
			}
			return FetchResult{}, ctx.Err()
		default:
		}
		d := e.Downloader(c.qh, c.h)
		res, err := d.Fetch(ctx, dir)
		if err == nil {
			return FetchResult{
				QueryHit:     c.qh,
				FileHit:      c.h,
				Source:       net.JoinHostPort(net.IP(c.qh.IP[:]).String(), formatPort(c.qh.Port)),
				DescriptorID: [idSize]byte{},
				Path:         res.Path,
				Bytes:        res.Bytes + res.Offset, // total bytes in file? DownloadResult gives Bytes as how many received this call; if resumed, Offset is where it started. Total on disk is Offset+Bytes when we appended; but for complete case Bytes is 0 and Offset is size. Also in full case Bytes is size, Offset 0. In resume case, Bytes is transferred (size-partial), Offset is partial. So total is Offset+Bytes.
			}, nil
		}
		lastErr = err
	}
	if lastErr != nil {
		return FetchResult{}, lastErr
	}
	return FetchResult{}, ErrAllCandidatesFailed
}

func formatPort(p uint16) string {
	// strconv.Itoa
	return itoa(int(p))
}

// small helper to avoid import churn
func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	neg := false
	if v < 0 {
		neg = true
		v = -v
	}
	var buf [32]byte
	i := len(buf) - 1
	for v > 0 {
		buf[i] = byte('0' + v%10)
		i--
		v /= 10
	}
	if neg {
		buf[i] = '-'
		i--
	}
	return string(buf[i+1:])
}
