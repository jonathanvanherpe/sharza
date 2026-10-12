// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Requester-side browse-host. Browse sends one QUERY whose search criteria
// are empty and whose trailing GGEP section carries the "BH" marker. A peer
// that understands it answers with QUERYHITs listing its whole share, which
// this engine collects through the same descriptor-ID registry Search uses.
//
// The wire shape is the one LimeWire-family servents speak: an empty query
// string is never a useful keyword search, so the BH extension is what
// distinguishes "list everything you have" from "match the empty string".
// gtk-gnutella's own browse client uses the /gnutella/browse HTTP request
// instead, but it parses the BH marker in an inbound QUERY (search.c,
// EXT_T_GGEP_BH), so the query form is still interoperable.
//
// Browse deliberately does not refactor Search's collection machinery: it
// copies the register-before-write order, the all-writes-failed short cut,
// the full-window wait and the partial-hits-no-error timeout, so Search's
// tested semantics are untouched.

import (
	"sync"
	"sync/atomic"
	"time"
)

const (
	// browseTTL is the browse QUERY's time to live. Two hops is enough to
	// reach a direct peer and one of its neighbours without letting a
	// whole-catalogue request propagate across the swarm.
	browseTTL byte = 2

	// browseExtension is the GGEP ID that turns an empty QUERY into a
	// browse-host request.
	browseExtension = "BH"
)

// Browse sends a browse-host QUERY to every live peer and returns the
// QUERYHITs that echo its descriptor ID within SearchTimeout.
//
// Like Search, the query is registered before it is written, only hits
// under this query's own ID are returned, the window always runs to
// SearchTimeout, and no live peer is not an error. The error return is the
// first write error, if any.
func (e *Engine) Browse() ([]QueryHit, error) {
	q := Query{
		MinSpeed:   0,
		Search:     "",
		Extensions: EncodeGGEP([]GGEPExtension{{ID: browseExtension}}),
	}
	payload := EncodeQuery(q)
	hdr := Header{
		ID:     newDescriptorID(),
		Type:   MsgQuery,
		TTL:    browseTTL,
		Hops:   0,
		Length: uint32(len(payload)),
	}
	buf := hdr.AppendTo(nil)
	buf = append(buf, payload...)

	e.mu.Lock()
	peers := make([]*peerConn, 0, len(e.peers))
	for pc := range e.peers {
		peers = append(peers, pc)
	}
	reg := e.searches
	timeout := e.opts.SearchTimeout
	e.mu.Unlock()

	if len(peers) == 0 {
		return nil, nil
	}

	// Register before any write: the answer can arrive first.
	reg.register(hdr.ID)

	var (
		wg       sync.WaitGroup
		written  atomic.Int32
		errMu    sync.Mutex
		firstErr error
	)
	for _, pc := range peers {
		wg.Add(1)
		go func(pc *peerConn) {
			defer wg.Done()
			pc.mu.Lock()
			defer pc.mu.Unlock()
			err := pc.conn.SetWriteDeadline(time.Now().Add(writeTimeout))
			if err == nil {
				_, err = pc.conn.Write(buf)
			}
			if err != nil {
				errMu.Lock()
				if firstErr == nil {
					firstErr = err
				}
				errMu.Unlock()
				return
			}
			written.Add(1)
		}(pc)
	}
	wg.Wait()

	// Wait out the collection window so late hits are collected. If no
	// write succeeded there is no peer that can answer, so the wait would
	// only delay an empty result.
	if written.Load() > 0 {
		timer := time.NewTimer(timeout)
		<-timer.C
	}

	errMu.Lock()
	err := firstErr
	errMu.Unlock()
	return reg.close(hdr.ID), err
}
