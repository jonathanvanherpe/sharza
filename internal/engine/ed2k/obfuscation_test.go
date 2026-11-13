// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"io"
	"net"
	"sync"
	"testing"
)

func TestObfuscationKeyGeneration(t *testing.T) {
	k1, err := NewObfuscationKeys()
	if err != nil {
		t.Fatal(err)
	}
	k2, err := NewObfuscationKeys()
	if err != nil {
		t.Fatal(err)
	}
	if len(k1.Public) != ObfuscationPrimeSize {
		t.Fatalf("public len = %d", len(k1.Public))
	}
	if bytes.Equal(k1.Public, k2.Public) {
		t.Fatal("two keypairs should differ")
	}
	if bytes.Equal(k1.Private, k2.Private) {
		t.Fatal("private keys should differ")
	}
}

func TestObfuscationSharedSecretSymmetry(t *testing.T) {
	k1, _ := NewObfuscationKeys()
	k2, _ := NewObfuscationKeys()
	s1, err := ObfuscationSharedSecret(k1, k2.Public)
	if err != nil {
		t.Fatal(err)
	}
	s2, err := ObfuscationSharedSecret(k2, k1.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s2) {
		t.Fatal("shared secrets differ")
	}
	if len(s1) != ObfuscationPrimeSize {
		t.Fatalf("secret len = %d", len(s1))
	}
	// raw private bytes also work
	s3, err := ObfuscationSharedSecret(k1.Private, k2.Public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(s1, s3) {
		t.Fatal("raw private derivation differs")
	}
}

func TestObfuscationKeystreamDrop(t *testing.T) {
	secret := make([]byte, ObfuscationPrimeSize)
	for i := range secret {
		secret[i] = byte(i + 1)
	}
	c1 := ObfuscationKeystream(secret, ObfuscationMagicClient)
	c2 := ObfuscationKeystream(secret, ObfuscationMagicClient)
	// After drop, both ciphers should produce identical keystream.
	b1 := make([]byte, 64)
	b2 := make([]byte, 64)
	zeros := make([]byte, 64)
	c1.XORKeyStream(b1, zeros)
	c2.XORKeyStream(b2, zeros)
	if !bytes.Equal(b1, b2) {
		t.Fatal("keystreams differ")
	}
	// RC4 key bytes are MD5(secret||magic)
	key := ObfuscationRC4Key(secret, ObfuscationMagicClient)
	if len(key) != 16 {
		t.Fatalf("rc4 key len = %d", len(key))
	}
	// KeystreamBytes helper
	ks := ObfuscationKeystreamBytes(secret, ObfuscationMagicClient, 32)
	if len(ks) != 32 {
		t.Fatal("bad keystream bytes len")
	}
	if !bytes.Equal(ks, b1[:32]) {
		t.Fatal("keystream bytes mismatch")
	}
}

func TestObfuscationKeystreamDifferentMagic(t *testing.T) {
	secret := make([]byte, ObfuscationPrimeSize)
	for i := range secret {
		secret[i] = byte(i * 3)
	}
	a := ObfuscationKeystreamBytes(secret, ObfuscationMagicClient, 16)
	b := ObfuscationKeystreamBytes(secret, ObfuscationMagicServer, 16)
	if bytes.Equal(a, b) {
		t.Fatal("different magic should yield different keystream")
	}
}

func TestObfuscationHandshakePipe(t *testing.T) {
	c1, c2 := net.Pipe()
	var w1, w2 net.Conn
	var e1, e2 error
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		w2, e2 = ObfuscateConn(c2, nil)
	}()
	w1, e1 = ObfuscateConn(c1, nil)
	wg.Wait()
	if e1 != nil {
		t.Fatalf("side1: %v", e1)
	}
	if e2 != nil {
		t.Fatalf("side2: %v", e2)
	}
	defer w1.Close()
	defer w2.Close()

	msg := []byte("hello obfuscated world")
	done := make(chan struct{})
	go func() {
		buf := make([]byte, len(msg))
		if _, err := io.ReadFull(w2, buf); err != nil {
			t.Errorf("read err: %v", err)
			close(done)
			return
		}
		if !bytes.Equal(buf, msg) {
			t.Errorf("got %q want %q", buf, msg)
		}
		close(done)
	}()
	if _, err := w1.Write(msg); err != nil {
		t.Fatal(err)
	}
	<-done
}

func TestObfuscationHandshakeTCP(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	var serverConn net.Conn
	var serverErr error
	done := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			serverErr = err
			close(done)
			return
		}
		serverConn, serverErr = ObfuscateConn(conn, nil)
		close(done)
	}()
	clientConn, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	clientWrapped, err := ObfuscateConn(clientConn, nil)
	if err != nil {
		t.Fatal(err)
	}
	<-done
	if serverErr != nil {
		t.Fatal(serverErr)
	}
	defer clientWrapped.Close()
	defer serverConn.Close()

	payload := []byte("tcp obfuscation round trip")
	if _, err := clientWrapped.Write(payload); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, len(payload))
	if _, err := io.ReadFull(serverConn, buf); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(buf, payload) {
		t.Fatalf("got %q want %q", buf, payload)
	}
}

func TestObfuscationEncryptionSymmetry(t *testing.T) {
	k1, _ := NewObfuscationKeys()
	k2, _ := NewObfuscationKeys()
	secret1, _ := ObfuscationSharedSecret(k1, k2.Public)
	secret2, _ := ObfuscationSharedSecret(k2, k1.Public)
	if !bytes.Equal(secret1, secret2) {
		t.Fatal("secrets differ")
	}
	// client sends with magic 34, server receives with magic 34 (recv magic 203? check pairing)
	send := ObfuscationKeystream(secret1, ObfuscationMagicClient)
	recv := ObfuscationKeystream(secret2, ObfuscationMagicClient)
	plain := []byte("symmetric encryption test data 12345")
	ct := make([]byte, len(plain))
	send.XORKeyStream(ct, plain)
	// receiver decrypts with same keystream position: must use matching cipher
	dec := make([]byte, len(ct))
	recv.XORKeyStream(dec, ct)
	// recv cipher started fresh; to decrypt, keystream must align. Since both
	// created fresh and dropped, XORing ciphertext yields plaintext.
	if !bytes.Equal(dec, plain) {
		t.Fatalf("decryption mismatch: got %q", dec)
	}
}

func TestObfuscatedConnReadWrite(t *testing.T) {
	c1, c2 := net.Pipe()
	// handshake in goroutines to avoid pipe deadlock
	var w1, w2 net.Conn
	var e1, e2 error
	var hg sync.WaitGroup
	hg.Add(1)
	go func() {
		defer hg.Done()
		w2, e2 = ObfuscateConn(c2, nil)
	}()
	w1, e1 = ObfuscateConn(c1, nil)
	hg.Wait()
	if e1 != nil || e2 != nil {
		t.Fatalf("%v %v", e1, e2)
	}
	defer w1.Close()
	defer w2.Close()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		buf := make([]byte, 100)
		n, err := io.ReadFull(w2, buf)
		if err != nil {
			t.Errorf("read err: %v", err)
			return
		}
		if !bytes.Equal(buf[:n], bytes.Repeat([]byte("a"), 100)) {
			t.Errorf("bad read")
		}
	}()
	data := bytes.Repeat([]byte("a"), 100)
	if _, err := w1.Write(data); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
}

func TestObfuscationInvalidInputs(t *testing.T) {
	if _, err := ObfuscationSharedSecret(nil, make([]byte, ObfuscationPrimeSize)); err == nil {
		t.Fatal("expected error for nil keys")
	}
	badPub := make([]byte, 10)
	if _, err := ObfuscationSharedSecret(mustKeys(t), badPub); err == nil {
		t.Fatal("expected error for bad pub len")
	}
	if _, err := ObfuscateConn(nil, nil); err == nil {
		t.Fatal("expected error for nil conn")
	}
}

func mustKeys(t *testing.T) *ObfuscationKeys {
	t.Helper()
	k, err := NewObfuscationKeys()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func FuzzObfuscationHandshake(f *testing.F) {
	f.Add(make([]byte, ObfuscationPrimeSize))
	secret := make([]byte, ObfuscationPrimeSize)
	f.Add(secret)
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) < ObfuscationPrimeSize {
			return
		}
		pub := data[:ObfuscationPrimeSize]
		k, err := NewObfuscationKeys()
		if err != nil {
			return
		}
		_, _ = ObfuscationSharedSecret(k, pub)
		_ = ObfuscationKeystream(pub, ObfuscationMagicClient)
		_ = ObfuscationKeystreamBytes(pub, ObfuscationMagicServer, 8)
	})
}
