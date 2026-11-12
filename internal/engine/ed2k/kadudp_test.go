// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"context"
	"net"
	"testing"
	"time"
)

func TestKadUDPRoundTrip(t *testing.T) {
	got := make(chan *KadPacket, 1)

	srv, err := NewKadUDP("127.0.0.1:0", func(remote net.Addr, pkt *KadPacket) {
		got <- pkt
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	cli, err := NewKadUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	if err := cli.Start(cctx); err != nil {
		t.Fatal(err)
	}

	p := &KadPacket{Opcode: KAD_PING, Payload: []byte{1, 2, 3, 4}}
	if err := cli.Send(context.Background(), srv.Addr(), p); err != nil {
		t.Fatal(err)
	}

	select {
	case pkt := <-got:
		if pkt.Opcode != KAD_PING && pkt.Op != KAD_PING && pkt.Type != KAD_PING {
			t.Fatalf("opcode %d", pkt.Opcode)
		}
		if len(pkt.Payload) == 0 {
			// payload may be stored in Data/Body
		}
		gotPayload := pkt.Payload
		if gotPayload == nil {
			gotPayload = pkt.Data
		}
		if gotPayload == nil {
			gotPayload = pkt.Body
		}
		if len(gotPayload) != 4 || gotPayload[0] != 1 || gotPayload[3] != 4 {
			t.Fatalf("payload mismatch: %v", gotPayload)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}

func TestKadUDPMalformedDatagram(t *testing.T) {
	called := make(chan struct{}, 1)
	srv, err := NewKadUDP("127.0.0.1:0", func(remote net.Addr, pkt *KadPacket) {
		select {
		case called <- struct{}{}:
		default:
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	conn, err := net.DialUDP("udp", nil, srv.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x00}); err != nil {
		t.Fatal(err)
	}

	select {
	case <-called:
		t.Fatal("handler called for malformed datagram")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestKadUDPContextShutdown(t *testing.T) {
	srv, err := NewKadUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run returned %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not complete")
	}
	srv.Close()
}

func TestKadUDPCloseStopsLoop(t *testing.T) {
	srv, err := NewKadUDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if err := srv.Close(); err != nil {
		t.Fatal(err)
	}
	// ensure no panic on double close
	_ = srv.Close()
}

func TestKadUDPStructLiteral(t *testing.T) {
	var received bool
	var got *KadPacket
	h := func(remote net.Addr, pkt *KadPacket) {
		got = pkt
		received = true
	}
	u := &KadUDP{BindAddr: "127.0.0.1:0", Handler: h}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := u.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	cli, _ := NewKadUDP("127.0.0.1:0")
	defer cli.Close()
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	cli.Start(cctx)

	p := &KadPacket{Type: KAD_PING, Payload: []byte("hi")}
	if err := cli.Send(context.Background(), u.Addr(), p); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) && !received {
		time.Sleep(10 * time.Millisecond)
	}
	if !received || got == nil {
		t.Fatal("packet not received via struct literal")
	}
}
