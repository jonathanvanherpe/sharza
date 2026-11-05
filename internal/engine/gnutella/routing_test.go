// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
	"time"
)

// TestQueryForwardChain proves query forwarding and horizon handling over
// a three-engine chain: a query injected at one end reaches the far end,
// and the QUERYHIT it produces travels back along the reverse path to the
// searcher.
func TestQueryForwardChain(t *testing.T) {
	engC, cancelC := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 1, Size: 12345, Name: "test.mp3"},
		},
	})
	defer cancelC()

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Peers:             []string{engC.Addr().String()},
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engB, 1)
	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search failed: %v", err)
	}
	found := false
	for _, qh := range results {
		for _, h := range qh.Hits {
			if h.FileName == "test.mp3" {
				found = true
				if qh.Port != uint16(engC.Addr().(*net.TCPAddr).Port) {
					t.Errorf("port = %d, want %d", qh.Port, engC.Addr().(*net.TCPAddr).Port)
				}
				if qh.IP != [4]byte{127, 0, 0, 1} {
					t.Errorf("ip = %v, want 127.0.0.1", qh.IP)
				}
			}
		}
	}
	if !found {
		t.Fatalf("far-end hit not returned; results = %+v", results)
	}
}
