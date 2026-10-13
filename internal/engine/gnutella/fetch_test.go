// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Fetch tests: end-to-end search -> download via Engine.Fetch.

import (
	"bufio"
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
	"io"
	"errors"
)

func TestFetchSearchThenDownloadEndToEnd(t *testing.T) {
	const (
		index = 5
		size  = 2048
	)
	content := testContent(size)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+itoa(int(index)) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", itoa(int(size)))
		w.Header().Set("X-Gnutella-Content-Length", itoa(int(size)))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	taSrv, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener is %T", srv.Listener.Addr())
	}
	ipSrv := taSrv.IP.To4()
	if ipSrv == nil {
		t.Fatal("not ipv4")
	}

	// Start a scripted responder peer
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveScriptedPeer(c, ipSrv, taSrv.Port, index, size, "archive.tar.gz")
		}
	}()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{l.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(100 * time.Millisecond)

	dir := t.TempDir()
	res, err := engA.Fetch(context.Background(), "archive", dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	wantPath := filepath.Join(dir, "archive.tar.gz")
	if res.Path != wantPath {
		t.Errorf("Path = %q, want %q", res.Path, wantPath)
	}
	if res.Bytes != size {
		t.Errorf("Bytes = %d, want %d", res.Bytes, size)
	}
	if res.FileHit.FileSize != uint32(size) {
		t.Errorf("FileHit.Size = %d, want %d", res.FileHit.FileSize, size)
	}
	if res.QueryHit.HitCount < 1 {
		t.Errorf("QueryHit.HitCount = %d, want >=1", res.QueryHit.HitCount)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file bytes mismatch")
	}
}



func serveScriptedPeer(c net.Conn, httpIP net.IP, httpPort int, index uint32, size uint32, name string) {
	defer c.Close()
	r := bufio.NewReader(c)
	// Read CONNECT request
	hs, err := ReadHandshake(r)
	if err != nil {
		return
	}
	if !hs.Request {
		return
	}
	// Send 200 OK
	_, _ = c.Write([]byte("GNUTELLA/0.6 200 OK\r\n\r\n"))
	// Read client confirmation
	if _, err := ReadHandshake(r); err != nil {
		return
	}
	buf := make([]byte, 1024*64)
	for {
		hdr, err := readMsgFromBufio(r, buf)
		if err != nil {
			return
		}
		if hdr.Type == MsgQuery {
			qh := QueryHit{
				HitCount: 1,
				Port:     uint16(httpPort),
				IP:       [4]byte{httpIP[0], httpIP[1], httpIP[2], httpIP[3]},
				Hits:     []FileHit{{FileIndex: index, FileSize: size, FileName: name}},
			}
			hp := EncodeQueryHit(qh)
			respHdr := Header{
				ID:     hdr.ID,
				Type:   MsgQueryHit,
				TTL:    6,
				Hops:   0,
				Length: uint32(len(hp)),
			}
			sendMsgToConn(c, respHdr, hp)
		}
	}
}

func readMsgFromBufio(r *bufio.Reader, buf []byte) (Header, error) {
	hdr, err := DecodeHeader(r)
	if err != nil {
		return Header{}, err
	}
	if hdr.Length > 0 {
		if uint64(hdr.Length) > uint64(len(buf)) {
			payload := make([]byte, hdr.Length)
			if _, err := io.ReadFull(r, payload); err != nil {
				return Header{}, err
			}
			return hdr, nil
		}
		_, err = io.ReadFull(r, buf[:hdr.Length])
		if err != nil {
			return Header{}, err
		}
	}
	return hdr, nil
}

func sendMsgToConn(conn net.Conn, h Header, payload []byte) {
	b := h.AppendTo(nil)
	b = append(b, payload...)
	_, _ = conn.Write(b)
}

func TestFetchFallbackFirstRefusesSecondCompletes(t *testing.T) {
	const (
		index = 7
		size  = 1024
	)
	content := testContent(size)

	// HTTP server that always serves
	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+itoa(int(index)) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", itoa(int(size)))
		w.Header().Set("X-Gnutella-Content-Length", itoa(int(size)))
		_, _ = w.Write(content)
	}))
	defer good.Close()
	goodAddr := good.Listener.Addr().(*net.TCPAddr)

	// First server that always fails
	bad := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer bad.Close()
	badAddr := bad.Listener.Addr().(*net.TCPAddr)

	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveScriptedPeerWithTwoHits(c, badAddr.IP.To4(), badAddr.Port, goodAddr.IP.To4(), goodAddr.Port, index, size)
		}
	}()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{l.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(100 * time.Millisecond)

	dir := t.TempDir()
	res, err := engA.Fetch(context.Background(), "file", dir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != size {
		t.Errorf("Bytes = %d, want %d", res.Bytes, size)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("content mismatch")
	}
}

func serveScriptedPeerWithTwoHits(c net.Conn, badIP net.IP, badPort int, goodIP net.IP, goodPort int, index uint32, size uint32) {
	defer c.Close()
	r := bufio.NewReader(c)
	hs, err := ReadHandshake(r)
	if err != nil {
		return
	}
	if !hs.Request {
		return
	}
	_, _ = c.Write([]byte("GNUTELLA/0.6 200 OK\r\n\r\n"))
	if _, err := ReadHandshake(r); err != nil {
		return
	}
	buf := make([]byte, 1024*64)
	for {
		hdr, err := readMsgFromBufio(r, buf)
		if err != nil {
			return
		}
		if hdr.Type == MsgQuery {
			// Send two separate QUERYHITs in one? No easier to send two hits from same QH but pointing to same addr - not quite.
			// Or better: send first QH with bad hit, second QH with good hit? But we only get one QUERY message and send responses.
			// Alternative: send two QUERYHIT messages? The peer can send multiple messages. Let us restructure.
			// Send first QUERYHIT (bad)
			qh1 := QueryHit{
				HitCount: 1,
				Port:     uint16(badPort),
				IP:       [4]byte{badIP[0], badIP[1], badIP[2], badIP[3]},
				Hits:     []FileHit{{FileIndex: index, FileSize: size, FileName: "bad.bin"}},
			}
			hp1 := EncodeQueryHit(qh1)
			respHdr1 := Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp1))}
			sendMsgToConn(c, respHdr1, hp1)
			// Send second QUERYHIT (good) - same ID is fine
			qh2 := QueryHit{
				HitCount: 1,
				Port:     uint16(goodPort),
				IP:       [4]byte{goodIP[0], goodIP[1], goodIP[2], goodIP[3]},
				Hits:     []FileHit{{FileIndex: index, FileSize: size, FileName: "good.bin"}},
			}
			hp2 := EncodeQueryHit(qh2)
			respHdr2 := Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp2))}
			sendMsgToConn(c, respHdr2, hp2)
			continue
		}
	}
}

func TestFetchNoHits(t *testing.T) {
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     200 * time.Millisecond,
	})
	defer cancelA()

	dir := t.TempDir()
	_, err := engA.Fetch(context.Background(), "nothing", dir)
	if !errors.Is(err, ErrNoHits) {
		t.Fatalf("Fetch err = %v, want ErrNoHits", err)
	}
}

func TestFetchContextCancel(t *testing.T) {
	const (
		index = 9
		size  = 8192
	)
	content := testContent(size)

	good := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+itoa(int(index)) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", itoa(int(size)))
		w.Header().Set("X-Gnutella-Content-Length", itoa(int(size)))
		_, _ = w.Write(content)
	}))
	defer good.Close()
	goodAddr := good.Listener.Addr().(*net.TCPAddr)

	// Peer will return hits
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()

	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			go serveScriptedPeerWithTwoHits(c, goodAddr.IP.To4(), goodAddr.Port, goodAddr.IP.To4(), goodAddr.Port, index, size)
		}
	}()

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{l.Addr().String()},
	})
	defer cancelA()

	waitForPeers(t, engA, 1)
	time.Sleep(100 * time.Millisecond)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // already cancelled
	dir := t.TempDir()
	_, err = engA.Fetch(ctx, "file", dir)
	if err == nil {
		t.Fatal("expected error from cancelled context")
	}
}
