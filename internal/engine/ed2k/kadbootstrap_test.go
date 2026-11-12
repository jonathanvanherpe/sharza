// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestKadBootstrap(t *testing.T) {
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

	self := bytes16(0)
	rt := NewKadRoutingTableWithSelf(self)
	got, err := KadBootstrap(context.Background(), responder.Addr(), self, rt)
	if err != nil {
		t.Fatalf("KadBootstrap: %v", err)
	}
	if len(got) != len(fixed) {
		t.Fatalf("returned %d contacts, want %d", len(got), len(fixed))
	}
	for i := range fixed {
		if got[i].ID != fixed[i].ID {
			t.Fatalf("contact %d id mismatch", i)
		}
	}
	if rt.Size() != len(fixed) {
		t.Fatalf("rt.Size() = %d, want %d", rt.Size(), len(fixed))
	}
	closest := rt.FindClosest(bytes16(2), 2)
	if len(closest) != 2 {
		t.Fatalf("FindClosest len = %d, want 2", len(closest))
	}
}

func TestKadBootstrapCancellation(t *testing.T) {
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
	_, err = KadBootstrap(cctx, responder.Addr(), bytes16(0), nil)
	if err == nil {
		t.Fatal("expected error on cancelled context")
	}
}

func TestKadBootstrapTimeout(t *testing.T) {
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
	_, err = KadBootstrap(ctx, responder.Addr(), bytes16(0), nil)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if time.Since(start) > 2*time.Second {
		t.Fatalf("took too long: %v", time.Since(start))
	}
}
