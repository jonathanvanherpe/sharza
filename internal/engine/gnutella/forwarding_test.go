// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestMarkSeenQueryDuplicateSuppression(t *testing.T) {
	eng := New()
	id := testID(0x11)
	if !eng.markSeenQuery(id) {
		t.Fatal("first mark should report new")
	}
	if !eng.isSeenQuery(id) {
		t.Fatal("marked id should be seen")
	}
	if eng.markSeenQuery(id) {
		t.Fatal("second mark should report duplicate")
	}
}

func TestSeenQueryHorizonExpiry(t *testing.T) {
	eng := New()
	id := testID(0x22)
	eng.markSeenQuery(id, 10*time.Millisecond)
	if !eng.isSeenQuery(id) {
		t.Fatal("should be seen before expiry")
	}
	time.Sleep(25 * time.Millisecond)
	if eng.isSeenQuery(id) {
		t.Fatal("should be expired")
	}
}

func TestForwardingSecondHopReachability(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 7, Size: 999, Name: "remote.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()

	var seen int
	var mu sync.Mutex
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
		OnQueryHit: func(_ net.Addr, _ [idSize]byte, _ QueryHit) {
			mu.Lock()
			seen++
			mu.Unlock()
		},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	waitForPeers(t, engB, 2) // A and C
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("remote")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileName == "remote.mp3" {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("second-hop hit not delivered; got %+v", results)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Error("OnQueryHit was not called for the reverse-routed hit")
	}
}

func TestForwardingReversePathHitDelivery(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 9, Size: 10, Name: "rp.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()

	var (
		mu   sync.Mutex
		hits int
	)
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
		OnQueryHit: func(_ net.Addr, _ [idSize]byte, qh QueryHit) {
			mu.Lock()
			defer mu.Unlock()
			for _, h := range qh.Hits {
				if h.FileName == "rp.mp3" {
					hits++
				}
			}
		},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	waitForPeers(t, engB, 2)
	time.Sleep(150 * time.Millisecond)

	_, err := engA.Search("rp")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits == 0 {
		t.Fatal("reverse-path hit did not invoke OnQueryHit")
	}
}

func TestForwardingHorizonExpiryIntegration(t *testing.T) {
	eng := New()
	id := testID(0x33)
	eng.markSeenQuery(id, 10*time.Millisecond)
	time.Sleep(25 * time.Millisecond)
	if eng.isSeenQuery(id) {
		t.Fatal("expired query still seen")
	}
	if !eng.markSeenQuery(id) {
		t.Fatal("re-mark after expiry should be new")
	}
	_ = net.Listener(nil)
}
