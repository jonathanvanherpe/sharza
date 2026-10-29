// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestSearchAndDownloadEndToEnd(t *testing.T) {
	const (
		index = 7
		size  = 1234
	)
	content := testContent(size)

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: size, Name: "test.bin"},
		},
	})
	defer cancelB()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engB.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	results, err := engA.Search("test")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 || len(results[0].Hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	qh := results[0]
	hit := qh.Hits[0]

	cancelB()
	time.Sleep(200 * time.Millisecond)

	addr := engB.Addr().String()
	var ln net.Listener
	deadline := time.Now().Add(testDeadline)
	for {
		l, err := net.Listen("tcp", addr)
		if err == nil {
			ln = l
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("could not bind HTTP listener on %s: %v", addr, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+strconv.Itoa(index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	srv.Listener = ln
	srv.Start()
	defer srv.Close()

	dir := t.TempDir()
	d := engA.Downloader(qh, hit)
	res, err := d.Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if _, err := os.Stat(res.Path); err != nil {
		t.Fatalf("destination missing: %v", err)
	}
	info, err := os.Stat(res.Path)
	if err != nil {
		t.Fatalf("stat destination: %v", err)
	}
	if info.Size() != int64(size) {
		t.Errorf("destination size = %d, want %d", info.Size(), size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read destination: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("destination bytes (%d) do not match served payload (%d)", len(onDisk), len(content))
	}
}
