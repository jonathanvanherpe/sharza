// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"net"
	"testing"
	"time"
)

func TestPushCodecRoundTrip(t *testing.T) {
	p := Push{
		ClientID:  testID(0xAB),
		FileIndex: 42,
		IP:        [4]byte{127, 0, 0, 1},
		Port:      6346,
	}
	enc := EncodePush(p)
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.ClientID != p.ClientID {
		t.Errorf("clientid mismatch")
	}
	if dec.FileIndex != p.FileIndex {
		t.Errorf("fileindex mismatch")
	}
	if dec.IP != p.IP {
		t.Errorf("ip mismatch")
	}
	if dec.Port != p.Port {
		t.Errorf("port mismatch")
	}
}

func TestPushRegistrySendNoPath(t *testing.T) {
	reg := newPushRegistry()
	push := Push{ClientID: testID(0xAB), FileIndex: 7, IP: [4]byte{127, 0, 0, 1}, Port: 6346}
	err := reg.send(push)
	if err != ErrNoPushPath {
		t.Fatalf("err = %v, want ErrNoPushPath", err)
	}
}

func TestEngineSendsPushOverRealPeer(t *testing.T) {
	engA, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:      10 * time.Second,
		SearchTimeout:    1 * time.Second,
	})

	r, conn := dialEngine(t, engA.Addr().String())
	waitForPeers(t, engA, 1)

	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := engA.Search("push")
		resCh <- result{hits, err}
	}()

	hdr, payload := readMsg(t, r)
	if hdr.Type != MsgQuery {
		t.Fatalf("first msg type = %s, want query", typeName(hdr.Type))
	}
	if _, err := DecodeQuery(payload); err != nil {
		t.Fatalf("query payload: %v", err)
	}

	clientID := testID(0xCD)
	qh := QueryHit{
		HitCount: 1,
		Port:     1234,
		IP:       [4]byte{127, 0, 0, 1},
		Hits:     []FileHit{{FileIndex: 9, FileSize: 9, FileName: "f.mp3"}},
		ClientID: clientID,
	}
	hp := EncodeQueryHit(qh)
	sendMsg(t, conn, Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}, hp)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search: %v", res.err)
	}
	if len(res.hits) == 0 {
		t.Fatal("no hits")
	}
	got := res.hits[0]
	if got.ClientID != clientID {
		t.Fatalf("clientid not preserved")
	}
	if got.Via == nil {
		t.Fatal("Via not stamped")
	}
	hit := got.Hits[0]
	d := engA.Downloader(got, hit)
	if d.RequestPush == nil {
		t.Fatal("RequestPush not wired")
	}
	if err := d.RequestPush(); err != nil {
		t.Fatalf("RequestPush: %v", err)
	}

	phdr, ppayload := readMsg(t, r)
	if phdr.Type != MsgPush {
		t.Fatalf("msg type = %s, want push", typeName(phdr.Type))
	}
	dec, err := DecodePush(ppayload)
	if err != nil {
		t.Fatalf("decode push: %v", err)
	}
	if dec.ClientID != clientID {
		t.Errorf("push clientid mismatch")
	}
	if dec.FileIndex != hit.FileIndex {
		t.Errorf("push fileindex mismatch")
	}
	_ = net.IP{}
}
