// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// QUERY forwarding with descriptor-ID dedup and reverse-path routing
// support. A query (and its answers) can travel beyond the direct link:
// an inbound QUERY is recorded as seen, forwarded to every neighbour but
// the one it came from, and answered from the local catalogue; a QUERYHIT
// arriving on a link whose descriptor ID was recorded is routed back to
// that origin peer instead of being treated as a local answer.

import (
	"sync"
	"time"
)

// seenQueryTTL is how long a forwarded QUERY's descriptor ID stays in the
// cache. Gnutella queries live for a few minutes in the wild; this is a
// generous upper bound and expiry is checked lazily on access.
const seenQueryTTL = 2 * time.Minute

// seenQueryCache remembers, for each descriptor ID, the peer the query
// first arrived from. The first writer wins: a later arrival with the
// same ID is treated as a duplicate and dropped. Entries expire after
// seenQueryTTL.
type seenQueryCache struct {
	mu      sync.Mutex
	entries map[[idSize]byte]seenEntry
	ttl     time.Duration
}

type seenEntry struct {
	origin *peerConn
	expiry time.Time
}

func newSeenQueryCache() *seenQueryCache {
	return &seenQueryCache{
		entries: make(map[[idSize]byte]seenEntry),
		ttl:     seenQueryTTL,
	}
}

// record stores origin for id if it is not already present (or has
// expired). It returns true when this call was the first writer.
func (c *seenQueryCache) record(id [idSize]byte, origin *peerConn) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if e, ok := c.entries[id]; ok && time.Now().Before(e.expiry) {
		return false
	}
	c.entries[id] = seenEntry{origin: origin, expiry: time.Now().Add(c.ttl)}
	return true
}

// has reports whether id is present and unexpired.
func (c *seenQueryCache) has(id [idSize]byte) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	return ok && time.Now().Before(e.expiry)
}

// lookup returns the recorded origin peer for id, if present and
// unexpired.
func (c *seenQueryCache) lookup(id [idSize]byte) (*peerConn, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	e, ok := c.entries[id]
	if !ok || !time.Now().Before(e.expiry) {
		return nil, false
	}
	return e.origin, true
}

// forwardQuery implements the forwarding half of query routing. It drops
// queries whose TTL is 1 or less (nothing left to forward) and queries
// whose descriptor ID has already been seen, records the origin peer for
// a newly seen ID, decrements TTL, increments Hops, and writes the
// resulting message to every live peer except origin. It returns true
// when the query was forwarded.
func (e *Engine) forwardQuery(origin *peerConn, hdr Header, payload []byte) bool {
	if hdr.TTL <= 1 {
		return false
	}
	if !e.seenQueries.record(hdr.ID, origin) {
		return false
	}
	newHdr := hdr
	newHdr.TTL = hdr.TTL - 1
	newHdr.Hops = hdr.Hops + 1
	newHdr.Length = uint32(len(payload))

	peers := e.peersExcept(origin)
	buf := newHdr.AppendTo(nil)
	buf = append(buf, payload...)

	var wg sync.WaitGroup
	for _, pc := range peers {
		wg.Add(1)
		go func(pc *peerConn) {
			defer wg.Done()
			pc.mu.Lock()
			defer pc.mu.Unlock()
			_ = pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			_, _ = pc.conn.Write(buf)
		}(pc)
	}
	wg.Wait()
	return true
}
