// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
	"time"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		Target:    testID(0xAB),
		FileIndex: 42,
		IP:        [4]byte{127, 0, 0, 1},
		Port:      6346,
	}
	enc := EncodePush(p)
	if len(enc) != pushPayloadSize {
		t.Fatalf("encoded len = %d, want %d", len(enc), pushPayloadSize)
	}
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.Target != p.Target {
		t.Errorf("target mismatch")
	}
	if dec.ServentID != p.Target {
		t.Errorf("servent id alias mismatch")
	}
	if dec.FileIndex != p.FileIndex {
		t.Errorf("file index: got %d want %d", dec.FileIndex, p.FileIndex)
	}
	if dec.IP != p.IP {
		t.Errorf("ip mismatch")
	}
	if dec.Port != p.Port {
		t.Errorf("port: got %d want %d", dec.Port, p.Port)
	}
}

func TestDecodePushShortPayloadRejected(t *testing.T) {
	if _, err := DecodePush(make([]byte, pushPayloadSize-1)); err == nil {
		t.Fatal("expected error for short payload")
	}
}

func TestDecodePushIgnoresTrailingGGEP(t *testing.T) {
	p := Push{Target: testID(0xCD), FileIndex: 7, IP: [4]byte{10, 0, 0, 1}, Port: 1234}
	enc := EncodePush(p)
	enc = append(enc, []byte{0x01, 0x02, 0x03}...) // trailing GGEP
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.FileIndex != p.FileIndex {
		t.Errorf("file index mismatch")
	}
	if dec.Target != p.Target {
		t.Errorf("target mismatch")
	}
}

func TestPushRegistryAddRemoveIdentity(t *testing.T) {
	r := newPushRegistry()
	c1, d1 := net.Pipe()
	c2, d2 := net.Pipe()
	t.Cleanup(func() {
		_ = c1.Close()
		_ = d1.Close()
		_ = c2.Close()
		_ = d2.Close()
	})
	old := &peer{conn: c1}
	fresh := &peer{conn: c2}
	r.add(old)
	r.add(fresh) // same key "pipe": reconnected peer now owns it
	r.remove(old) // stale connection's deferred remove

	r.mu.Lock()
	got := r.byAddr[c1.RemoteAddr().String()]
	r.mu.Unlock()
	if got != fresh {
		t.Fatalf("registry holds %v after old removed, want fresh", got)
	}
	r.remove(fresh)
	r.mu.Lock()
	n := len(r.byAddr)
	r.mu.Unlock()
	if n != 0 {
		t.Errorf("registry has %d entries after removing both, want 0", n)
	}
}

func TestPushRegistryReportsMissingPath(t *testing.T) {
	r := newPushRegistry()
	someAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6346}
	id := testID(0x11)
	var nilReg *pushRegistry
	if err := nilReg.send(someAddr, id, 1); err != ErrNoPushPath {
		t.Fatalf("nil registry: err = %v, want ErrNoPushPath", err)
	}
	if err := r.send(nil, id, 1); err != ErrNoPushPath {
		t.Fatalf("nil via: err = %v, want ErrNoPushPath", err)
	}
	if err := r.send(someAddr, id, 1); err != ErrNoPushPath {
		t.Fatalf("unregistered via: err = %v, want ErrNoPushPath", err)
	}
}

func TestPushRegistryNilSafe(t *testing.T) {
	var r *pushRegistry
	r.add(&peer{})
	r.remove(&peer{})
}

func TestPushEndToEndScriptedPeer(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)
	time.Sleep(150 * time.Millisecond)

	serventID := testID(0x55)
	qh := QueryHit{
		HitCount: 1,
		Port:     1234,
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 9, FileSize: 10, FileName: "f.mp3"}},
		ClientID: serventID,
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: testID(0x01), Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	time.Sleep(100 * time.Millisecond)

	eng.mu.Lock()
	var via net.Addr
	for pc := range eng.peers {
		via = pc.conn.RemoteAddr()
	}
	eng.mu.Unlock()
	if via == nil {
		t.Fatal("no peer")
	}
	qh.Via = via
	qh.ClientID = serventID

	d := eng.Downloader(qh, qh.Hits[0])
	if d.RequestPush == nil {
		t.Fatal("RequestPush not wired")
	}
	if err := d.RequestPush(); err != nil {
		t.Fatalf("RequestPush failed: %v", err)
	}

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgPush {
		t.Fatalf("type = %s, want push", typeName(hdr.Type))
	}
	pp, err := DecodePush(payload)
	if err != nil {
		t.Fatalf("decode push: %v", err)
	}
	if pp.Target != serventID {
		t.Errorf("target mismatch in push")
	}
	if pp.FileIndex != 9 {
		t.Errorf("file index = %d, want 9", pp.FileIndex)
	}
}

func TestPushGoneConnectionReturnsErrNoPushPath(t *testing.T) {
	eng, cancel := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	_, conn := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)
	time.Sleep(150 * time.Millisecond)

	eng.mu.Lock()
	var via net.Addr
	for pc := range eng.peers {
		via = pc.conn.RemoteAddr()
	}
	eng.mu.Unlock()

	conn.Close()
	cancel()
	time.Sleep(200 * time.Millisecond)

	eng.mu.Lock()
	pushes := eng.pushes
	eng.mu.Unlock()
	if err := pushes.send(via, Push{}); err != ErrNoPushPath {
		t.Fatalf("err = %v, want ErrNoPushPath", err)
	}
}
