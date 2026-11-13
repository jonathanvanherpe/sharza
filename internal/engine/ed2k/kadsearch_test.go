// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestKadSearch(t *testing.T) {
	tag := Tag{Type: 0x03, Key: 0x01, Value: 42}
	res1 := KadSearchResult{Hash: bytes16(7), Tags: []Tag{tag}}
	res2 := KadSearchResult{Hash: bytes16(8), Tags: []Tag{}}
	fixed := []KadSearchResult{res1, res2}

	var responder *KadUDP
	var err error
	responder, err = NewKadUDP("127.0.0.1:0", func(remote net.Addr, pkt *KadPacket) {
		if pkt == nil || pkt.opcode() != KAD_SEARCH_KEY_REQ {
			return
		}
		// echo the requested key back as the response target
		req, _ := DecodeKadSearchReq(pkt.payload())
		r := KadSearchRes{Target: req.Key, Results: fixed}
		rpkt := &KadPacket{Protocol: ProtocolKad, Opcode: KAD_SEARCH_RES, Payload: r.Marshal()}
		_ = responder.Send(context.Background(), remote, rpkt)
	})
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	if err := responder.Start(rctx); err != nil {
		t.Fatal(err)
	}
	defer responder.Close()

	key := bytes16(5)
	got, err := KadSearch(context.Background(), responder.Addr(), key, bytes16(0))
	if err != nil {
		t.Fatalf("KadSearch: %v", err)
	}
	if len(got) != len(fixed) {
		t.Fatalf("returned %d results, want %d", len(got), len(fixed))
	}
	for i := range fixed {
		if got[i].Hash != fixed[i].Hash {
			t.Fatalf("result %d hash mismatch", i)
		}
		if len(got[i].Tags) != len(fixed[i].Tags) {
			t.Fatalf("result %d tags count mismatch", i)
		}
	}
}

func TestKadSearchCancellation(t *testing.T) {
	responder, err := NewKadUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	if err := responder.Start(rctx); err != nil {
		t.Fatal(err)
	}
	defer responder.Close()

	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	_, err = KadSearch(cctx, responder.Addr(), bytes16(0), bytes16(0))
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestKadSearchTimeout(t *testing.T) {
	responder, err := NewKadUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	rctx, rcancel := context.WithCancel(context.Background())
	defer rcancel()
	if err := responder.Start(rctx); err != nil {
		t.Fatal(err)
	}
	defer responder.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = KadSearch(ctx, responder.Addr(), bytes16(0), bytes16(0))
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took too long: %v", time.Since(start))
	}
}