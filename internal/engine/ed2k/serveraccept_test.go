// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"context"
	"net"
	"testing"
	"time"
)

func TestServerAcceptConnRoundTrip(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	availName := "accept.bin"
	wantData := bytes.Repeat([]byte("accept-payload-"), 16)

	serverClientID := uint32(777)
	serverPort := uint16(4662)

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		e.mu.Lock()
		e.clientID = serverClientID
		e.laddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: int(serverPort)}
		e.mu.Unlock()
		e.kadMu.Lock()
		e.kadSelf = wantHash
		e.kadSelfID = wantHash
		e.kadID = wantHash
		e.kadMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		pi, fr, rp, err := e.ServeAcceptConn(ctx, conn, wantHash, availName, wantData)
		if err != nil {
			t.Errorf("ServeAcceptConn: %v", err)
			return
		}
		if fr.Hash != wantHash {
			t.Errorf("server fr Hash = %v, want %v", fr.Hash, wantHash)
		}
		_ = pi
		_ = rp
	}()

	clientHash := wantHash
	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.mu.Lock()
	e.clientID = 12345
	e.mu.Unlock()
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	pi, ans, res, n, err := e.DialDownload(ctx, ln.Addr().String(), clientHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if pi.ClientID != serverClientID {
		t.Fatalf("peer ClientID = %d, want %d", pi.ClientID, serverClientID)
	}
	if ans.Name != availName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, availName)
	}
	if !res.Granted {
		t.Fatalf("expected granted queue result, got %+v", res)
	}
	if n != len(wantData) {
		t.Fatalf("n = %d, want %d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("downloaded bytes mismatch")
	}
}

func TestServerAcceptConnNotFound(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, _, err = e.ServeAcceptConn(ctx, conn)
		_ = err
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	_, _, _, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != ErrFileNotFound {
		t.Fatalf("expected ErrFileNotFound, got %v (n=%d)", err, n)
	}
	if n != 0 {
		t.Fatalf("expected 0 bytes, got %d", n)
	}
}

func TestServerAcceptConnPackageLevel(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{9, 9, 9}
	wantData := []byte("pkg-level")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, _, err = ServeAcceptConn(ctx, conn, wantHash, "f.bin", wantData, New())
		_ = err
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	_, _, _, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if n != len(wantData) {
		t.Fatalf("n=%d want=%d", n, len(wantData))
	}
	if !bytes.Equal(buf.Bytes(), wantData) {
		t.Fatalf("bytes mismatch")
	}
}

func TestServerAcceptConnIO(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	wantHash := [16]byte{7, 7, 7}
	wantData := []byte("io-variant")

	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		e := New()
		e.kadMu.Lock()
		e.kadSelf = wantHash
		e.kadSelfID = wantHash
		e.kadID = wantHash
		e.kadMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _, _, err = e.ServeAcceptConnIO(ctx, conn, wantHash, "io.bin", wantData)
		_ = err
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.kadMu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	_, _, _, n, err := e.DialDownload(ctx, ln.Addr().String(), wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownload: %v", err)
	}
	if n != len(wantData) {
		t.Fatalf("n=%d want=%d", n, len(wantData))
	}
}

func TestServerAcceptConnObfuscatedRoundTrip(t *testing.T) {
	c1, c2 := net.Pipe()

	wantHash := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	availName := "obf.bin"

	go func() {
		defer c1.Close()
		e := New()
		e.mu.Lock()
		e.clientID = 777
		e.laddr = &net.TCPAddr{IP: net.IPv4(10, 0, 0, 1), Port: 4662}
		e.mu.Unlock()
		e.kadMu.Lock()
		e.kadSelf = wantHash
		e.kadSelfID = wantHash
		e.kadID = wantHash
		e.kadMu.Unlock()
		e.opts.Obfuscation = true

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, _, _, err := e.ServeAcceptConn(ctx, c1, wantHash, availName); err != nil {
			t.Errorf("ServeAcceptConn: %v", err)
		}
	}()

	// Client side: obfuscate our end of the pipe manually (outbound wiring is
	// out of scope for this slice).
	var wc net.Conn
	var oerr error
	done := make(chan struct{})
	go func() {
		defer close(done)
		wc, oerr = ObfuscateConn(c2, nil)
	}()
	<-done
	if oerr != nil {
		t.Fatalf("client ObfuscateConn: %v", oerr)
	}
	defer wc.Close()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.mu.Lock()
	e.clientID = 12345
	e.mu.Unlock()
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	pi, ans, _, n, err := e.DialDownloadConn(ctx, wc, wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownloadConn: %v", err)
	}
	if pi.ClientID != 777 {
		t.Fatalf("peer ClientID = %d, want 777", pi.ClientID)
	}
	if ans.Name != availName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, availName)
	}
	_ = n
	_ = buf
}

func TestServerAcceptConnPlainPipe(t *testing.T) {
	c1, c2 := net.Pipe()

	wantHash := [16]byte{9, 9, 9, 9}
	availName := "plain.bin"

	go func() {
		defer c1.Close()
		e := New()
		e.mu.Lock()
		e.clientID = 777
		e.mu.Unlock()
		e.kadMu.Lock()
		e.kadSelf = wantHash
		e.kadSelfID = wantHash
		e.kadID = wantHash
		e.kadMu.Unlock()

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if _, _, _, err := e.ServeAcceptConn(ctx, c1, wantHash, availName); err != nil {
			t.Errorf("ServeAcceptConn: %v", err)
		}
	}()

	e := New()
	e.kadMu.Lock()
	e.kadSelf = wantHash
	e.kadSelfID = wantHash
	e.kadID = wantHash
	e.mu.Lock()
	e.clientID = 12345
	e.mu.Unlock()
	e.kadMu.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	buf := &bytes.Buffer{}
	_, ans, _, _, err := e.DialDownloadConn(ctx, c2, wantHash, buf)
	if err != nil {
		t.Fatalf("DialDownloadConn: %v", err)
	}
	if ans.Name != availName {
		t.Fatalf("answer Name = %q, want %q", ans.Name, availName)
	}
}

var _ = time.Second
var _ = net.Listen
var _ = context.Background