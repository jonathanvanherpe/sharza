// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"time"
)

// KadSearch performs a single Kad source-discovery round against the node at
// addr. It creates and starts a KadUDP transceiver on an ephemeral port, sends
// a KadSearchReq carrying key (by file hash/key), waits for one KAD_SEARCH_RES
// (honouring ctx plus a short internal timeout), decodes it via
// DecodeKadSearchRes, and returns its discovered results. Search results are file
// sources, so no routing-table insertion is performed by this slice.
func KadSearch(ctx context.Context, addr net.Addr, key [16]byte, self [16]byte) ([]KadSearchResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	resCh := make(chan *KadPacket, 1)
	handler := func(remote net.Addr, pkt *KadPacket) {
		if pkt == nil {
			return
		}
		if pkt.opcode() != KAD_SEARCH_RES {
			return
		}
		select {
		case resCh <- pkt:
		default:
		}
	}

	u, err := NewKadUDP("", handler)
	if err != nil {
		return nil, err
	}

	waitCtx := ctx
	var cancel context.CancelFunc
	if _, ok := ctx.Deadline(); !ok {
		waitCtx, cancel = context.WithTimeout(ctx, 2*time.Second)
	} else {
		waitCtx, cancel = context.WithCancel(ctx)
	}
	defer cancel()

	if err := u.Start(waitCtx); err != nil {
		u.Close()
		return nil, err
	}
	defer u.Close()

	req := KadSearchReq{Key: key}
	pkt := &KadPacket{Protocol: ProtocolKad, Opcode: KAD_SEARCH_KEY_REQ, Payload: req.Marshal()}
	if err := u.Send(ctx, addr, pkt); err != nil {
		return nil, err
	}

	select {
	case rpkt := <-resCh:
		res, err := DecodeKadSearchRes(rpkt.payload())
		if err != nil {
			return nil, err
		}
		results := res.results()
		out := make([]KadSearchResult, len(results))
		copy(out, results)
		return out, nil
	case <-waitCtx.Done():
		return nil, waitCtx.Err()
	}
}