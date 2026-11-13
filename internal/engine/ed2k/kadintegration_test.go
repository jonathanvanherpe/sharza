// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestEngineKadBootstrapIntegration(t *testing.T) {
	c1 := KadContact{ID: bytes16(2), IP: [4]byte{5, 6, 7, 8}, UDPPort: 1000, TCPPort: 1001, Version: 9}
	c2 := KadContact{ID: bytes16(3), IP: [4]byte{9, 10, 11, 12}, UDPPort: 2000, TCPPort: 2001, Version: 9}
	fixed := []KadContact{c1, c2}

	var responder *KadUDP
	var err error
	responder, err = NewKadUDP("127.0.0.1:0", func(remote net.Addr, pkt *KadPacket) {
		if pkt == nil || pkt.opcode() != KAD_BOOTSTRAP_REQ {
			return
		}
		res := KadBootstrapRes{ID: bytes16(1), TCPPort: 4661, Version: 9, Contacts: fixed}
		rpkt := &KadPacket{Protocol: ProtocolKad, Opcode: KAD_BOOTSTRAP_RES, Payload: res.Marshal()}
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

	eng := New()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{KadBootstrapNodes: []string{responder.Addr().String()}}) }()

	waitCond(t, 3*time.Second, func() bool {
		rt := eng.KadRoutingTable()
		return rt != nil && rt.Size() == len(fixed) && eng.KadContactCount() == len(fixed)
	})

	rt := eng.KadRoutingTable()
	if rt == nil {
		t.Fatal("nil routing table")
	}
	if rt.Size() != len(fixed) {
		t.Fatalf("rt.Size() = %d, want %d", rt.Size(), len(fixed))
	}
	for _, c := range fixed {
		if _, ok := rt.Get(c.ID); !ok {
			t.Fatalf("missing contact %v", c.ID)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return")
	}
}

func TestEngineKadBootstrapUnreachable(t *testing.T) {
	eng := New()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- eng.Run(ctx, Options{KadBootstrapNodes: []string{"127.0.0.1:1"}}) }()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("run did not return")
	}

	if rt := eng.KadRoutingTable(); rt != nil && rt.Size() != 0 {
		t.Fatalf("expected empty table, got %d", rt.Size())
	}
}
