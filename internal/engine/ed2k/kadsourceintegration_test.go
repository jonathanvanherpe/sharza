// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEngineKadSourceDiscovery(t *testing.T) {
	tag := Tag{Type: 0x03, Key: 0x01, Value: 42}
	res1 := KadSearchResult{Hash: bytes16(7), Tags: []Tag{tag}}
	res2 := KadSearchResult{Hash: bytes16(8), Tags: []Tag{}}
	fixed := []KadSearchResult{res1, res2}

	var responder *KadUDP
	var err error
	responder, err = NewKadUDP("127.0.0.1:0", func(remote net.Addr, pkt *KadPacket) {
		if pkt == nil {
			return
		}
		switch pkt.opcode() {
		case KAD_BOOTSTRAP_REQ:
			ra := responder.Addr().(*net.UDPAddr)
			c := KadContact{ID: bytes16(2), IP: [4]byte{127, 0, 0, 1}, UDPPort: uint16(ra.Port), TCPPort: uint16(ra.Port), Version: 9}
			res := KadBootstrapRes{ID: bytes16(1), TCPPort: 4661, Version: 9, Contacts: []KadContact{c}}
			rpkt := &KadPacket{Protocol: ProtocolKad, Opcode: KAD_BOOTSTRAP_RES, Payload: res.Marshal()}
			_ = responder.Send(context.Background(), remote, rpkt)
		case KAD_SEARCH_KEY_REQ:
			req, _ := DecodeKadSearchReq(pkt.payload())
			r := KadSearchRes{Target: req.Key, Results: fixed}
			rpkt := &KadPacket{Protocol: ProtocolKad, Opcode: KAD_SEARCH_RES, Payload: r.Marshal()}
			_ = responder.Send(context.Background(), remote, rpkt)
		}
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

	eng := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{KadBootstrapNodes: []string{responder.Addr().String()}}) }()

	waitCond(t, 3*time.Second, func() bool {
		rt := eng.KadRoutingTable()
		return rt != nil && rt.Size() == 1
	})

	key := bytes16(5)
	got, err := eng.KadSearchSources(ctx, key)
	if err != nil {
		t.Fatalf("KadSearchSources: %v", err)
	}
	if len(got) != len(fixed) {
		t.Fatalf("returned %d sources, want %d", len(got), len(fixed))
	}
	for i := range fixed {
		if got[i].Hash != fixed[i].Hash {
			t.Fatalf("source %d hash mismatch", i)
		}
	}

	// alias check
	got2, err := eng.KadSourceDiscovery(ctx, key)
	if err != nil || len(got2) != len(fixed) {
		t.Fatalf("alias KadSourceDiscovery failed: %v len=%d", err, len(got2))
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestEngineKadSourceDiscoveryEmptyTable(t *testing.T) {
	eng := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{}) }()

	select {
	case <-eng.Ready():
	case <-time.After(3 * time.Second):
		t.Fatal("not ready")
	}

	got, err := eng.KadSearchSources(ctx, bytes16(5))
	if err != nil {
		t.Fatalf("expected nil err, got %v", err)
	}
	if got != nil {
		t.Fatalf("expected nil sources, got %v", got)
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestEngineKadSourceDiscoveryCancellation(t *testing.T) {
	cctx, ccancel := context.WithCancel(context.Background())
	ccancel()
	eng := New()
	_, err := eng.KadSearchSources(cctx, bytes16(5))
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}
