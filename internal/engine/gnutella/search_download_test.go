// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestSearchAndDownloadComposes is the end-to-end evidence for the P1
// "completes a search and a download" exit-gate criterion, sliced to
// its smallest verifiable unit: one transfer over real TCP in which
// Engine.Search returns a hit and Engine.Downloader(...).Fetch writes
// the served bytes to disk. No production code is touched; it only
// composes primitives that already exist.
//
// Engine A dials a scripted 0.6 peer. That peer answers A's QUERY with
// a QUERYHIT naming an httptest servent's index, size and file name;
// A's Search returns that hit, and A's Downloader fetches the file from
// the servent over HTTP.

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"
)

func TestSearchAndDownloadComposes(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)

	// The servent: a real TCP listener speaking real HTTP, serving a
	// known file at /gnutella/<index>. It is the source the QUERYHIT
	// will name, and the bytes Fetch must end up with.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/7" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", "1200")
		w.Header().Set("X-Gnutella-Content-Length", "1200")
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	qhServent, hitServent := hitFor(t, srv, index, size, "song.mp3")

	// A scripted 0.6 peer that engine A will dial. It completes the
	// handshake, reads A's QUERY, and answers with a QUERYHIT naming
	// the servent above.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })

	accepted := make(chan net.Conn, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		accepted <- c
	}()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
		Peers:            []string{ln.Addr().String()},
	})
	defer cancelA()

	// Wait for the dial + handshake to finish before searching, so the
	// QUERY is not written into a half-open handshake.
	waitForPeers(t, engA, 1)

	var sconn net.Conn
	select {
	case sconn = <-accepted:
	case <-time.After(testDeadline):
		t.Fatal("engine never dialed the scripted peer")
	}
	defer sconn.Close()
	if err := sconn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}

	// Handle the handshake and the query/reply in a goroutine so the
	// main thread can call Search and wait out its collection window.
	finished := make(chan struct{})
	handshaken := make(chan struct{})
	go func() {
		r := bufio.NewReader(sconn)
		hs, err := ReadHandshake(r)
		if err != nil {
			t.Errorf("read connect request: %v", err)
			return
		}
		if !hs.Request {
			t.Errorf("first line is a response (%s), want CONNECT", hs.Status())
			return
		}
		if _, err := sconn.Write(OKReply(
			Field{"Listen-IP", "127.0.0.1:6346"},
			Field{"User-Agent", "scripted-peer/0.1"},
		)); err != nil {
			t.Errorf("write OK: %v", err)
			return
		}
		confirm, err := ReadHandshake(r)
		if err != nil {
			t.Errorf("read client confirmation: %v", err)
			return
		}
		if !confirm.IsOK() {
			t.Errorf("client confirmation = %s, want 200 OK", confirm.Status())
			return
		}
		close(handshaken)

		// Read A's QUERY.
		hdr, payload, err := readMsgErr(r)
		if err != nil {
			t.Errorf("read query: %v", err)
			return
		}
		if hdr.Type != MsgQuery {
			t.Errorf("first message type = %s, want query", typeName(hdr.Type))
			return
		}
		if _, err := DecodeQuery(payload); err != nil {
			t.Errorf("query payload: %v", err)
			return
		}

		// Answer with a QUERYHIT naming the servent.
		qh := qhServent
		hp := EncodeQueryHit(qh)
		sendMsg(t, sconn, Header{
			ID:     hdr.ID,
			Type:   MsgQueryHit,
			TTL:    6,
			Hops:   0,
			Length: uint32(len(hp)),
		}, hp)

		<-finished
	}()

	select {
	case <-handshaken:
	case <-time.After(testDeadline):
		t.Fatal("handshake did not complete")
	}

	results, err := engA.Search("song")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(results) == 0 {
		t.Fatal("Search returned no hits, want the QUERYHIT echoing its descriptor ID")
	}
	qh := results[0]
	if qh.HitCount < 1 || len(qh.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", qh)
	}
	if qh.Hits[0].FileName != "song.mp3" {
		t.Errorf("filename = %q, want %q", qh.Hits[0].FileName, "song.mp3")
	}

	hit := qh.Hits[0]

	close(finished)

	dir := t.TempDir()
	res, err := engA.Downloader(qh, hit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != int64(size) {
		t.Errorf("result.Bytes = %d, want %d", res.Bytes, size)
	}

	got, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if len(got) != size {
		t.Fatalf("downloaded size = %d, want %d", len(got), size)
	}
	if !bytes.Equal(got, content) {
		t.Fatal("downloaded bytes do not match served content")
	}

	// hitServent is the matching FileHit; res.Path already names the
	// sanitised file, so nothing else needs it here.
	_ = hitServent
}
