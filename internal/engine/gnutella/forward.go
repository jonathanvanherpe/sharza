// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"sync"
	"time"
)

// seenQueryEntry is one dedup record: the descriptor ID's expiry and, when
// the query was forwarded by us, the peer it arrived on so the matching
// QUERYHIT can travel back along the reverse path.
type seenQueryEntry struct {
	expires time.Time
	origin  *peerConn
}

// seenQueryCache is a small expiry cache keyed by descriptor ID. It
// prevents the same QUERY from being forwarded more than once and
// remembers where a forwarded query came from for reverse hit routing.
type seenQueryCache struct {
	mu      sync.Mutex
	entries map[[idSize]byte]seenQueryEntry
	expiry  time.Duration
}

func newSeenQueryCache(expiry time.Duration) *seenQueryCache {
	if expiry <= 0 {
		expiry = 2 * time.Minute
	}
	return &seenQueryCache{
		entries: make(map[[idSize]byte]seenQueryEntry),
		expiry:  expiry,
	}
}

// seen reports whether id is still in the cache (not expired).
func (c *seenQueryCache) seen(id [idSize]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok {
		return false
	}
	if time.Now().After(e.expires) {
		delete(c.entries, id)
		return false
	}
	return true
}

// markSeen records id in the cache with no origin (used by callers that
// only want dedup). It does not overwrite an existing, unexpired entry's
// origin if one was already recorded; the first writer wins.
func (c *seenQueryCache) markSeen(id [idSize]byte) {
	c.markSeenWithOrigin(id, nil)
}

// markSeenWithOrigin records id with the given origin, but only when no
// unexpired entry exists yet. This keeps the first arrival authoritative.
func (c *seenQueryCache) markSeenWithOrigin(id [idSize]byte, origin *peerConn) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[id]; ok && !time.Now().After(e.expires) {
		// keep existing entry (and its origin) authoritative
		return
	}
	c.entries[id] = seenQueryEntry{
		expires: time.Now().Add(c.expiry),
		origin:  origin,
	}
}

// origin returns the peer a forwarded query arrived on, or nil.
func (c *seenQueryCache) origin(id [idSize]byte) *peerConn {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok || time.Now().After(e.expires) {
		return nil
	}
	return e.origin
}

// Engine-level helpers, consistent with how searches is owned.

func (e *Engine) seen(id [idSize]byte) bool {
	if e.seenQueries == nil {
		return false
	}
	return e.seenQueries.seen(id)
}

func (e *Engine) markSeen(id [idSize]byte) {
	if e.seenQueries == nil {
		return
	}
	e.seenQueries.markSeen(id)
}

// forwardQuery forwards an inbound QUERY to every peer except origin,
// decrementing TTL and incrementing Hops, subject to dedup by descriptor
// ID. It never sends the QUERY back to the peer it arrived on. A QUERY
// with TTL <= 1 is not forwarded.
func (e *Engine) forwardQuery(origin *peerConn, hdr Header, payload []byte) {
	if hdr.TTL <= 1 {
		return
	}
	if e.seen(hdr.ID) {
		return
	}
	// Record dedup + reverse-path origin before writing, so a fast
	// answer cannot race the cache.
	e.seenQueries.markSeenWithOrigin(hdr.ID, origin)

	fwdHdr := hdr
	fwdHdr.TTL = hdr.TTL - 1
	fwdHdr.Hops = hdr.Hops + 1
	fwdHdr.Length = uint32(len(payload))

	buf := fwdHdr.AppendTo(nil)
	buf = append(buf, payload...)

	for _, pc := range e.peersExcept(origin) {
		pc.mu.Lock()
		err := pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
		if err == nil {
			_, err = pc.conn.Write(buf)
		}
		pc.mu.Unlock()
		if err != nil && e.opts.Logf != nil {
			e.opts.Logf("forward query to %s failed: %v", pc.addr, err)
		}
	}
}
