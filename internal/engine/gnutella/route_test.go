// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"sync"
	"testing"
	"time"
)

func TestQueryRoutingMesh(t *testing.T) {
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	defer cancelB()

	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 7, Size: 100, Name: "routed.mp3"},
		},
		Peers: []string{engB.Addr().String()},
	})
	defer cancelC()

	var (
		mu   sync.Mutex
		seen int
	)
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
	waitForPeers(t, engC, 1)
	waitForPeers(t, engB, 2)
	time.Sleep(200 * time.Millisecond)

	results, err := engA.Search("routed")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want routed hit from C")
	}
	if results[0].Hits[0].FileName != "routed.mp3" {
		t.Errorf("filename = %q", results[0].Hits[0].FileName)
	}

	mu.Lock()
	defer mu.Unlock()
	if seen == 0 {
		t.Error("OnQueryHit not called")
	}
	_ = net.IP{}
}
