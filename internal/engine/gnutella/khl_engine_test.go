// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// khlTestAnswer builds a KHLA packet advertising addr (a host:port the
// engine should end up dialing). Mirrors the scripted peer in khl_test.go.
func khlTestAnswer(t *testing.T, addr string) *G2Packet {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("split host port %q: %v", addr, err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("port %q: %v", portStr, err)
	}
	topTS := uint32(1000)
	inlineTS := uint32(2000)
	ch := &G2Packet{Type: "CH", Payload: khlInlineAddr(host, port, inlineTS, true)}
	top := &G2Packet{Type: "TS", Payload: khlUint32Bytes(topTS)}
	return &G2Packet{Type: "KHLA", Compound: true, Children: []*G2Packet{ch, top}}
}

// TestEngineDialsKHLEndpointFetchedPeer mirrors TestEngineDialsCacheFetchedPeer
// for the KHL path: an engine with no Peers and one KHL endpoint must dial
// the host the endpoint returns.
func TestEngineDialsKHLEndpointFetchedPeer(t *testing.T) {
	target, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	var fetches atomic.Int64
	srv, err := NewG2UDP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.setHandler(func(remote net.Addr, pkt *G2Packet) {
		if pkt == nil || pkt.Type != "KHLR" {
			return
		}
		fetches.Add(1)
		_ = srv.Send(context.Background(), remote, khlTestAnswer(t, target.Addr().String()))
	})

	src, _ := startEngine(t, Options{
		KHLHosts: []string{srv.Addr().String()},
		// Loopback addresses are filtered in production; tests may only
		// reach loopback, so relax it.
		khlAllowLoopback:  true,
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	if len(src.opts.Peers) != 0 {
		t.Fatalf("Peers = %v, want empty: discovery must be the KHL endpoint's doing", src.opts.Peers)
	}

	deadline := time.Now().Add(testDeadline)
	for {
		sent, got := peerCount(src), peerCount(target)
		if sent > 0 && got > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("KHL-fetched peer never dialed: src peers=%d, target peers=%d, fetches=%d",
				sent, got, fetches.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fetches.Load() == 0 {
		t.Fatal("the engine never consulted the KHL endpoint")
	}

	time.Sleep(300 * time.Millisecond)
	if peerCount(src) == 0 || peerCount(target) == 0 {
		t.Errorf("connection did not survive: src peers=%d, target peers=%d",
			peerCount(src), peerCount(target))
	}
}

// TestEngineDedupsDuplicateKHLEndpoints: the same endpoint listed twice
// must not cause the discovered host to be dialed twice.
func TestEngineDedupsDuplicateKHLEndpoints(t *testing.T) {
	target, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	srv, err := NewG2UDP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.setHandler(func(remote net.Addr, pkt *G2Packet) {
		if pkt == nil || pkt.Type != "KHLR" {
			return
		}
		_ = srv.Send(context.Background(), remote, khlTestAnswer(t, target.Addr().String()))
	})

	src, _ := startEngine(t, Options{
		KHLHosts:          []string{srv.Addr().String(), srv.Addr().String()},
		khlAllowLoopback:  true,
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	deadline := time.Now().Add(testDeadline)
	for {
		if peerCount(target) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("KHL-fetched peer never dialed: target peers=%d", peerCount(target))
		}
		time.Sleep(20 * time.Millisecond)
	}
	// Give a moment for any duplicate dial to land.
	time.Sleep(300 * time.Millisecond)
	if peerCount(target) != 1 {
		t.Errorf("target peer count = %d, want 1 (duplicate endpoint must not double-dial)",
			peerCount(target))
	}
	if peerCount(src) != 1 {
		t.Errorf("src peer count = %d, want 1", peerCount(src))
	}
}

// TestEngineKHLEndpointFailureLoggedAndSkipped: an endpoint that fails to
// resolve must be logged and skipped without aborting the engine or other
// endpoints.
func TestEngineKHLEndpointFailureLoggedAndSkipped(t *testing.T) {
	target, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	var logsMu sync.Mutex
	var logs []string
	logf := func(format string, args ...any) {
		logsMu.Lock()
		defer logsMu.Unlock()
		logs = append(logs, fmt.Sprintf(format, args...))
	}

	srv, err := NewG2UDP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.setHandler(func(remote net.Addr, pkt *G2Packet) {
		if pkt == nil || pkt.Type != "KHLR" {
			return
		}
		_ = srv.Send(context.Background(), remote, khlTestAnswer(t, target.Addr().String()))
	})

	src, _ := startEngine(t, Options{
		KHLHosts: []string{
			"127.0.0.1:99999", // invalid port -> resolve error
			srv.Addr().String(),
		},
		khlAllowLoopback:  true,
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Logf:              logf,
	})

	// The good endpoint must still be consulted.
	deadline := time.Now().Add(testDeadline)
	for {
		if peerCount(target) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("good KHL endpoint never dialed: target peers=%d", peerCount(target))
		}
		time.Sleep(20 * time.Millisecond)
	}

	// Engine must still be running (Ready already closed at startEngine).
	if src.Ready() == nil {
		t.Fatal("engine not ready")
	}

	logsMu.Lock()
	defer logsMu.Unlock()
	sawFailure := false
	for _, l := range logs {
		if strings.Contains(l, "127.0.0.1:99999") {
			sawFailure = true
		}
	}
	if !sawFailure {
		t.Errorf("failing endpoint was not logged; logs=%v", logs)
	}
}

// TestEngineCacheAndKHLNoDoubleDial: a host returned by both a cache and a
// KHL endpoint must be dialed exactly once.
func TestEngineCacheAndKHLNoDoubleDial(t *testing.T) {
	target, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	// HTTP cache returning target.
	srvCache := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "H|%s|1700000000\n", target.Addr().String())
	}))
	t.Cleanup(srvCache.Close)

	// KHL endpoint returning the same target.
	srvKHL, err := NewG2UDP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srvKHL.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srvKHL.Close()
	srvKHL.setHandler(func(remote net.Addr, pkt *G2Packet) {
		if pkt == nil || pkt.Type != "KHLR" {
			return
		}
		_ = srvKHL.Send(context.Background(), remote, khlTestAnswer(t, target.Addr().String()))
	})

	src, _ := startEngine(t, Options{
		Caches:             []string{srvCache.URL},
		cacheAllowLoopback: true,
		KHLHosts:           []string{srvKHL.Addr().String()},
		khlAllowLoopback:   true,
		KeepAliveInterval:  time.Hour,
		IdleTimeout:        10 * time.Second,
	})

	deadline := time.Now().Add(testDeadline)
	for {
		if peerCount(target) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("shared host never dialed: target peers=%d, src peers=%d",
				peerCount(target), peerCount(src))
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond)
	if peerCount(target) != 1 {
		t.Errorf("target peer count = %d, want 1 (cache + KHL must not double-dial)",
			peerCount(target))
	}
	if peerCount(src) != 1 {
		t.Errorf("src peer count = %d, want 1", peerCount(src))
	}
}
