// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
	"time"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		ServentID: testID(0xAB),
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
	if dec.ServentID != p.ServentID {
		t.Errorf("servent id mismatch")
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
	p := Push{ServentID: testID(0xCD), FileIndex: 7, IP: [4]byte{10, 0, 0, 1}, Port: 1234}
	enc := EncodePush(p)
	enc = append(enc, []byte{0x01, 0x02, 0x03}...) // trailing GGEP
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.FileIndex != p.FileIndex {
		t.Errorf("file index mismatch")
	}
}

func TestPushRegistryAddRemoveIdentity(t *testing.T) {
	r := newPushRegistry()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 1234}
	p1 := &peer{}
	p2 := &peer{}
	r.add(addr, p1)
	r.remove(addr, p2)
	r.mu.Lock()
	got := r.conns[addr.String()]
	r.mu.Unlock()
	if got != p1 {
		t.Fatalf("p1 removed by identity mismatch")
	}
	r.remove(addr, p1)
	r.mu.Lock()
	got = r.conns[addr.String()]
	r.mu.Unlock()
	if got != nil {
		t.Fatalf("p1 not removed")
	}
}

func TestPushRegistrySendNoPath(t *testing.T) {
	r := newPushRegistry()
	addr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9999}
	if err := r.send(addr, Push{}); err != ErrNoPushPath {
		t.Fatalf("err = %v, want ErrNoPushPath", err)
	}
	var nilr *pushRegistry
	if err := nilr.send(addr, Push{}); err != ErrNoPushPath {
		t.Fatalf("nil registry err = %v", err)
	}
}

func TestPushRegistryNilSafe(t *testing.T) {
	var r *pushRegistry
	r.add(nil, nil)
	r.remove(nil, nil)
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
	if pp.ServentID != serventID {
		t.Errorf("servent id mismatch in push")
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

	// Close connection and wait for unregister.
	conn.Close()
	cancel()
	time.Sleep(200 * time.Millisecond)

	// Registry should be empty.
	eng.mu.Lock()
	pushes := eng.pushes
	eng.mu.Unlock()
	if err := pushes.send(via, Push{}); err != ErrNoPushPath {
		t.Fatalf("err = %v, want ErrNoPushPath", err)
	}
}
