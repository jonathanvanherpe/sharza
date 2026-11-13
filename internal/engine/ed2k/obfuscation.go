// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds protocol obfuscation helpers for eDonkey client/server
// connections. It provides a Diffie-Hellman keypair generator, shared-secret
// derivation, and an RC4 stream cipher with the standard 1024-byte initial
// keystream drop, plus a net.Conn wrapper that performs the obfuscation
// handshake and transparently encrypts/decrypts subsequent bytes.
//
// Stdlib only: crypto/*, math/big, net, io. No cgo, no external deps.
package ed2k

import (
	"bytes"
	"crypto/md5"
	"crypto/rand"
	"crypto/rc4"
	"errors"
	"io"
	"math/big"
	"net"
	"sync"
)

// Obfuscation constants. Sizes follow eMule's client/server DH agreement:
// 128-bit exponents, 768-bit (96-byte) prime and shared secret.
const (
	ObfuscationPrimeSize    = 96
	ObfuscationPrivateSize   = 16
	ObfuscationDropBytes     = 1024
	ObfuscationGenerator     = 2
	ObfuscationMagicSync     = 0x835E6FC4
	ObfuscationMagicClient   = 34
	ObfuscationMagicServer   = 203
)

// ObfuscationPrime is eMule's dh768_p (big-endian, 96 bytes).
var ObfuscationPrime = []byte{
	0xF2, 0xBF, 0x52, 0xC5, 0x5F, 0x58, 0x7A, 0xDD, 0x53, 0x71, 0xA9, 0x36,
	0xE8, 0x86, 0xEB, 0x3C, 0x62, 0x17, 0xA3, 0x3E, 0xC3, 0x4C, 0xB4, 0x0D,
	0xC7, 0x3A, 0x41, 0xA6, 0x43, 0xAF, 0xFC, 0xE7, 0x21, 0xFC, 0x28, 0x63,
	0x66, 0x53, 0x5B, 0xDB, 0xCE, 0x25, 0x9F, 0x22, 0x86, 0xDA, 0x4A, 0x91,
	0xB2, 0x07, 0xCB, 0xAA, 0x52, 0x55, 0xD4, 0xF6, 0x1C, 0xCE, 0xAE, 0xD4,
	0x5A, 0xD5, 0xE0, 0x74, 0x7D, 0xF7, 0x78, 0x18, 0x28, 0x10, 0x5F, 0x34,
	0x0F, 0x76, 0x23, 0x87, 0xF8, 0x8B, 0x28, 0x91, 0x42, 0xFB, 0x42, 0x68,
	0x8F, 0x05, 0x15, 0x0F, 0x54, 0x8B, 0x5F, 0x43, 0x6A, 0xF7, 0x0D, 0xF3,
}

// Aliases for the prime size.
const ObfuscationDHSize = ObfuscationPrimeSize

var (
	ErrObfuscationKeys      = errors.New("ed2k: invalid obfuscation keys")
	ErrObfuscationPubKey    = errors.New("ed2k: invalid obfuscation public key")
	ErrObfuscationHandshake = errors.New("ed2k: obfuscation handshake failed")
)

// ObfuscationKeys holds a Diffie-Hellman keypair for eDonkey obfuscation.
type ObfuscationKeys struct {
	Private    []byte
	Public     []byte
	PrivateKey []byte
	PublicKey  []byte
	Priv       []byte
	Pub        []byte
	A          []byte
	B          []byte
	DHPrivate  []byte
	DHPublic   []byte
}

// NewObfuscationKeys generates a fresh DH keypair.
func NewObfuscationKeys() (*ObfuscationKeys, error) {
	priv := make([]byte, ObfuscationPrivateSize)
	if _, err := rand.Read(priv); err != nil {
		return nil, err
	}
	pub, err := obfuscationPublicKey(priv)
	if err != nil {
		return nil, err
	}
	k := &ObfuscationKeys{
		Private:    priv,
		Public:     pub,
		PrivateKey: priv,
		PublicKey:  pub,
		Priv:       priv,
		Pub:        pub,
		A:          pub,
		DHPrivate:  priv,
		DHPublic:   pub,
	}
	return k, nil
}

// Aliases.
func NewObfuscationKeyPair() (*ObfuscationKeys, error) { return NewObfuscationKeys() }
func NewObfuscationDHKeys() (*ObfuscationKeys, error)  { return NewObfuscationKeys() }
func NewObfuscationDH() (*ObfuscationKeys, error)      { return NewObfuscationKeys() }
func NewDHKeys() (*ObfuscationKeys, error)            { return NewObfuscationKeys() }

func obfuscationPublicKey(priv []byte) ([]byte, error) {
	if len(priv) == 0 {
		return nil, ErrObfuscationKeys
	}
	a := new(big.Int).SetBytes(priv)
	p := new(big.Int).SetBytes(ObfuscationPrime)
	g := big.NewInt(ObfuscationGenerator)
	out := make([]byte, ObfuscationPrimeSize)
	pub := new(big.Int).Exp(g, a, p)
	b := pub.Bytes()
	if len(b) > ObfuscationPrimeSize {
		// Should not happen for this prime; keep low bytes.
		b = b[len(b)-ObfuscationPrimeSize:]
	}
	copy(out[ObfuscationPrimeSize-len(b):], b)
	return out, nil
}

// ObfuscationSharedSecret derives the shared secret from a local keypair (or
// raw private key) and the remote public key.
func ObfuscationSharedSecret(local any, remotePub []byte) ([]byte, error) {
	var priv []byte
	switch v := local.(type) {
	case *ObfuscationKeys:
		if v == nil {
			return nil, ErrObfuscationKeys
		}
		priv = v.Private
		if len(priv) == 0 {
			priv = v.PrivateKey
		}
		if len(priv) == 0 {
			priv = v.Priv
		}
		if len(priv) == 0 {
			priv = v.DHPrivate
		}
	case []byte:
		priv = v
	case string:
		priv = []byte(v)
	default:
		return nil, ErrObfuscationKeys
	}
	if len(priv) == 0 {
		return nil, ErrObfuscationKeys
	}
	if len(remotePub) != ObfuscationPrimeSize {
		return nil, ErrObfuscationPubKey
	}
	a := new(big.Int).SetBytes(priv)
	p := new(big.Int).SetBytes(ObfuscationPrime)
	remote := new(big.Int).SetBytes(remotePub)
	shared := new(big.Int).Exp(remote, a, p)
	out := make([]byte, ObfuscationPrimeSize)
	b := shared.Bytes()
	if len(b) > ObfuscationPrimeSize {
		b = b[len(b)-ObfuscationPrimeSize:]
	}
	copy(out[ObfuscationPrimeSize-len(b):], b)
	return out, nil
}

// Aliases.
func ObfuscationComputeSharedSecret(local any, remotePub []byte) ([]byte, error) {
	return ObfuscationSharedSecret(local, remotePub)
}
func SharedSecret(local any, remotePub []byte) ([]byte, error) {
	return ObfuscationSharedSecret(local, remotePub)
}
func ObfuscationDHSharedSecret(local any, remotePub []byte) ([]byte, error) {
	return ObfuscationSharedSecret(local, remotePub)
}

// ObfuscationRC4Key derives the RC4 key bytes (MD5(secret || magic)).
func ObfuscationRC4Key(secret []byte, magic byte) []byte {
	h := md5.New()
	h.Write(secret)
	h.Write([]byte{magic})
	return h.Sum(nil)
}

// ObfuscationKeystream creates an RC4 cipher for the given secret and magic
// value, with the standard 1024-byte initial keystream drop applied.
func ObfuscationKeystream(secret []byte, magic byte) *rc4.Cipher {
	key := ObfuscationRC4Key(secret, magic)
	c, err := rc4.NewCipher(key)
	if err != nil {
		// Key length is always valid here; fall back to a zero key.
		c, _ = rc4.NewCipher(make([]byte, 16))
	}
	drop := make([]byte, ObfuscationDropBytes)
	c.XORKeyStream(drop, drop)
	return c
}

// Aliases.
func ObfuscationNewCipher(secret []byte, magic byte) *rc4.Cipher {
	return ObfuscationKeystream(secret, magic)
}
func ObfuscationStreamCipher(secret []byte, magic byte) *rc4.Cipher {
	return ObfuscationKeystream(secret, magic)
}
func ObfuscationCipher(secret []byte, magic byte) *rc4.Cipher {
	return ObfuscationKeystream(secret, magic)
}
func NewObfuscationCipher(secret []byte, magic byte) *rc4.Cipher {
	return ObfuscationKeystream(secret, magic)
}
func ObfuscationRC4(secret []byte, magic byte) *rc4.Cipher {
	return ObfuscationKeystream(secret, magic)
}

// ObfuscationKeystreamBytes returns n bytes of keystream (after the drop).
func ObfuscationKeystreamBytes(secret []byte, magic byte, n int) []byte {
	if n < 0 {
		n = 0
	}
	c := ObfuscationKeystream(secret, magic)
	out := make([]byte, n)
	zeros := make([]byte, n)
	c.XORKeyStream(out, zeros)
	return out
}

// ObfuscatedConn wraps a net.Conn with send/recv RC4 stream ciphers.
type ObfuscatedConn struct {
	net.Conn
	SendCipher *rc4.Cipher
	RecvCipher *rc4.Cipher
	send       *rc4.Cipher
	recv       *rc4.Cipher
}

// NewObfuscatedConn wraps conn with the provided ciphers.
func NewObfuscatedConn(conn net.Conn, send, recv *rc4.Cipher) *ObfuscatedConn {
	return &ObfuscatedConn{Conn: conn, SendCipher: send, RecvCipher: recv, send: send, recv: recv}
}

// Aliases.
func NewObfuscationConn(conn net.Conn, send, recv *rc4.Cipher) *ObfuscatedConn {
	return NewObfuscatedConn(conn, send, recv)
}
func ObfuscatedConnection(conn net.Conn, send, recv *rc4.Cipher) *ObfuscatedConn {
	return NewObfuscatedConn(conn, send, recv)
}

func (c *ObfuscatedConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	if n > 0 {
		cipher := c.recv
		if cipher == nil {
			cipher = c.RecvCipher
		}
		if cipher != nil {
			cipher.XORKeyStream(p[:n], p[:n])
		}
	}
	return n, err
}

func (c *ObfuscatedConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	buf := make([]byte, len(p))
	cipher := c.send
	if cipher == nil {
		cipher = c.SendCipher
	}
	if cipher != nil {
		cipher.XORKeyStream(buf, p)
	} else {
		copy(buf, p)
	}
	return c.Conn.Write(buf)
}

// ObfuscateConn performs the obfuscation handshake over conn and returns a
// wrapped connection. remotePub is accepted for API compatibility and may be
// nil; the handshake exchanges public keys over the connection itself.
func ObfuscateConn(conn net.Conn, remotePub []byte) (net.Conn, error) {
	_ = remotePub
	if conn == nil {
		return nil, errors.New("ed2k: nil connection")
	}
	localKeys, err := NewObfuscationKeys()
	if err != nil {
		return nil, err
	}
	localPub := localKeys.Public
	if len(localPub) != ObfuscationPrimeSize {
		localPub = localKeys.PublicKey
	}

	// Exchange public keys concurrently to avoid deadlocks on buffered-less
	// transports such as net.Pipe.
	peerPub := make([]byte, ObfuscationPrimeSize)
	var writeErr, readErr error
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		if err := writeAll(conn, localPub); err != nil {
			writeErr = err
		}
	}()
	go func() {
		defer wg.Done()
		if _, err := io.ReadFull(conn, peerPub); err != nil {
			readErr = err
		}
	}()
	wg.Wait()
	if writeErr != nil {
		return nil, writeErr
	}
	if readErr != nil {
		return nil, readErr
	}

	// Determine role by comparing public keys: the side with the smaller
	// public key takes the client magic (34 for send).
	clientRole := bytes.Compare(localPub, peerPub) < 0
	secret, err := ObfuscationSharedSecret(localKeys, peerPub)
	if err != nil {
		return nil, err
	}
	var sendMagic, recvMagic byte
	if clientRole {
		sendMagic = ObfuscationMagicClient
		recvMagic = ObfuscationMagicServer
	} else {
		sendMagic = ObfuscationMagicServer
		recvMagic = ObfuscationMagicClient
	}
	sendCipher := ObfuscationKeystream(secret, sendMagic)
	recvCipher := ObfuscationKeystream(secret, recvMagic)
	return NewObfuscatedConn(conn, sendCipher, recvCipher), nil
}

// Aliases.
func ObfuscateConnection(conn net.Conn, remotePub []byte) (net.Conn, error) {
	return ObfuscateConn(conn, remotePub)
}
func ObfuscationHandshake(conn net.Conn, remotePub []byte) (net.Conn, error) {
	return ObfuscateConn(conn, remotePub)
}

func writeAll(w io.Writer, b []byte) error {
	for len(b) > 0 {
		n, err := w.Write(b)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		b = b[n:]
	}
	return nil
}


