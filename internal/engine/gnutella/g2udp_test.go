// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"context"
	"net"
	"sync"
	"testing"
	"time"
)

func TestG2UDPRoundTrip(t *testing.T) {
	got := make(chan *G2Packet, 1)
	remoteCh := make(chan net.Addr, 1)

	srv, err := NewG2UDP("127.0.0.1:0", func(remote net.Addr, pkt *G2Packet) {
		remoteCh <- remote
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

	// client sender
	cli, err := NewG2UDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer cli.Close()
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	if err := cli.Start(cctx); err != nil {
		t.Fatal(err)
	}

	p := &G2Packet{Type: "PI", Payload: []byte{1, 2, 3, 4}}
	if err := cli.Send(context.Background(), srv.Addr(), p); err != nil {
		t.Fatal(err)
	}

	select {
	case pkt := <-got:
		if pkt.Type != "PI" {
			t.Fatalf("type %q", pkt.Type)
		}
		if !bytesEqual(pkt.Payload, []byte{1, 2, 3, 4}) {
			t.Fatalf("payload mismatch")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for packet")
	}

	_ = remoteCh
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestG2UDPMalformedDatagram(t *testing.T) {
	called := make(chan struct{}, 1)
	srv, err := NewG2UDP("127.0.0.1:0", func(remote net.Addr, pkt *G2Packet) {
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

	// send garbage directly via a raw UDP socket
	conn, err := net.DialUDP("udp", nil, srv.Addr().(*net.UDPAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if _, err := conn.Write([]byte{0x00, 0xFF, 0x00}); err != nil {
		t.Fatal(err)
	}

	// wait a bit; handler should not be called
	select {
	case <-called:
		t.Fatal("handler called for malformed datagram")
	case <-time.After(300 * time.Millisecond):
	}
}

func TestG2UDPContextShutdown(t *testing.T) {
	srv, err := NewG2UDP("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	// ensure bound
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

func TestG2UDPStructLiteral(t *testing.T) {
	var received sync.Mutex
	var got *G2Packet
	h := func(remote net.Addr, pkt *G2Packet) {
		received.Lock()
		got = pkt
		received.Unlock()
	}
	u := &G2UDP{BindAddr: "127.0.0.1:0", Handler: h}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := u.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer u.Close()

	cli, _ := NewG2UDP("127.0.0.1:0")
	defer cli.Close()
	cctx, ccancel := context.WithCancel(context.Background())
	defer ccancel()
	cli.Start(cctx)

	p := &G2Packet{Type: "X", Payload: []byte("hi")}
	if err := cli.Send(context.Background(), u.Addr(), p); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		received.Lock()
		ok := got != nil
		received.Unlock()
		if ok {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	received.Lock()
	defer received.Unlock()
	if got == nil || got.Type != "X" {
		t.Fatal("packet not received via struct literal")
	}
}
