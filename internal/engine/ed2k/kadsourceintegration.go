// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
)

// KadSearchSources searches the engine's Kad routing table for sources for key.
// It reads the table's contacts under kadMu, builds a UDP address from each
// contact's IP/UDPPort, invokes the existing KadSearch helper against that
// contact, and aggregates the discovered sources, de-duplicating by hash.
//
// It returns nil, nil when the routing table is empty (or not initialised).
// Context cancellation is honoured: a cancelled ctx yields ctx.Err().
func (e *Engine) KadSearchSources(ctx context.Context, key [16]byte) ([]KadSearchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	// Snapshot the contacts under kadMu.
	e.kadMu.Lock()
	rt := e.kadRoutingTable
	if rt == nil {
		if e.kadTable != nil {
			rt = e.kadTable
		} else if e.routingTable != nil {
			rt = e.routingTable
		} else {
			rt = e.kadRT
		}
	}
	var contacts []KadContact
	if rt != nil {
		rt.mu.Lock()
		for _, b := range rt.Buckets {
			contacts = append(contacts, b.Contacts...)
		}
		rt.mu.Unlock()
	}
	e.kadMu.Unlock()

	if len(contacts) == 0 {
		return nil, nil
	}

	self := e.KadSelfID()

	seen := make(map[[16]byte]bool)
	var out []KadSearchResult
	for _, c := range contacts {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		ip := c.ipBytes()
		addr := &net.UDPAddr{IP: net.IP(ip[:]), Port: int(c.udpPort())}
		results, err := KadSearch(ctx, addr, key, self)
		if err != nil {
			if cerr := ctx.Err(); cerr != nil {
				return nil, cerr
			}
			continue
		}
		for _, r := range results {
			h := r.hashBytes()
			if seen[h] {
				continue
			}
			seen[h] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// Aliases.
func (e *Engine) KadSourceDiscovery(ctx context.Context, key [16]byte) ([]KadSearchResult, error) {
	return e.KadSearchSources(ctx, key)
}

func (e *Engine) SearchKadSources(ctx context.Context, key [16]byte) ([]KadSearchResult, error) {
	return e.KadSearchSources(ctx, key)
}

func (e *Engine) KadSearch(ctx context.Context, key [16]byte) ([]KadSearchResult, error) {
	return e.KadSearchSources(ctx, key)
}
