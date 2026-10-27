// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"
)

func TestSearchThenDownloadCompletes(t *testing.T) {
	const (
		index = 7
		size  = 1200
		name  = "song.mp3"
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != fmt.Sprintf("/gnutella/%d", index) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	qhTemplate, hitTemplate := hitFor(t, srv, index, size, name)

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
		Peers:             []string{ln.Addr().String()},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Logf:              t.Logf,
	})
	defer cancelA()

	var sconn net.Conn
	select {
	case sconn = <-accepted:
	case <-time.After(testDeadline):
		t.Fatal("engine never dialed the configured peer")
	}
	defer sconn.Close()
	if err := sconn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		t.Fatal(err)
	}
	r := bufio.NewReader(sconn)

	hs, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("read connect request: %v", err)
	}
	if !hs.Request {
		t.Fatalf("first line is a response (%s), want CONNECT", hs.Status())
	}
	if _, err := sconn.Write(OKReply(
		Field{"Listen-IP", "127.0.0.1:6346"},
		Field{"User-Agent", "scripted-server/0.1"},
	)); err != nil {
		t.Fatal(err)
	}
	confirm, err := ReadHandshake(r)
	if err != nil {
		t.Fatalf("read client confirmation: %v", err)
	}
	if !confirm.IsOK() {
		t.Fatalf("client confirmation = %s, want 200 OK", confirm.Status())
	}

	waitForPeers(t, engA, 1)
	time.Sleep(150 * time.Millisecond)

	type searchResult struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan searchResult, 1)
	go func() {
		hits, err := engA.Search("test")
		resCh <- searchResult{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first message type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	qh := QueryHit{
		HitCount: 1,
		Port:     qhTemplate.Port,
		IP:       qhTemplate.IP,
		Speed:    0,
		Hits:     []FileHit{hitTemplate},
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, sconn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search failed: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("Search returned no hits")
	}
	gotQH := res.hits[0]
	if len(gotQH.Hits) == 0 {
		t.Fatal("hit has no file hits")
	}
	gotHit := gotQH.Hits[0]

	dir := t.TempDir()
	dlRes, err := engA.Downloader(gotQH, gotHit).Fetch(context.Background(), dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	onDisk, err := os.ReadFile(dlRes.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match servent content (%d bytes)", len(onDisk), len(content))
	}
	if int64(len(onDisk)) != int64(size) {
		t.Errorf("file length = %d, want %d", len(onDisk), size)
	}
	if dlRes.Bytes != int64(size) {
		t.Errorf("result bytes = %d, want %d", dlRes.Bytes, size)
	}
	if gotHit.FileSize != uint32(size) {
		t.Errorf("hit declared size = %d, want %d", gotHit.FileSize, size)
	}
}
