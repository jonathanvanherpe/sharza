// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"testing"
	"time"
)

func TestPushCodecRoundTrip(t *testing.T) {
	p := Push{
		ClientID:  testID(0xAB),
		FileIndex: 7,
		IP:        [4]byte{1, 2, 3, 4},
		Port:      6346,
	}
	enc := EncodePush(p)
	if len(enc) != 26 {
		t.Fatalf("encoded length = %d, want 26", len(enc))
	}
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec != p {
		t.Errorf("decoded %+v, want %+v", dec, p)
	}
}

func TestPushRegistrySendNoPath(t *testing.T) {
	reg := newPushRegistry()
	var id [idSize]byte
	for i := range id {
		id[i] = 0xAB
	}
	err := reg.send(id, Push{ClientID: id})
	if err != ErrNoPushPath {
		t.Fatalf("send err = %v, want ErrNoPushPath", err)
	}
}

func TestPushOverTCP(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	_, conn := dialEngine(t, eng.Addr().String())

	sid := eng.ServentID
	push := Push{ClientID: sid, FileIndex: 5, IP: [4]byte{127, 0, 0, 1}, Port: 1234}
	payload := EncodePush(push)
	sendMsg(t, conn, Header{ID: testID(0x01), Type: MsgPush, TTL: 5, Hops: 0, Length: uint32(len(payload))}, payload)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		eng.mu.Lock()
		n := len(eng.pushRequests)
		eng.mu.Unlock()
		if n > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	eng.mu.Lock()
	n := len(eng.pushRequests)
	eng.mu.Unlock()
	if n == 0 {
		t.Fatal("engine recorded no dial-back push request")
	}
	if len(eng.pushes.Requests()) == 0 {
		t.Fatal("push registry recorded no dial-back push request")
	}
}