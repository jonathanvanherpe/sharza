// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"context"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func khlUint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func khlInlineAddr(ip string, port int, ts uint32, withTS bool) []byte {
	parsed := net.ParseIP(ip).To4()
	v := uint32(parsed[0])<<24 | uint32(parsed[1])<<16 | uint32(parsed[2])<<8 | uint32(parsed[3])
	out := make([]byte, 0, 10)
	// little-endian IP
	out = append(out, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
	out = append(out, byte(port>>8), byte(port))
	if withTS {
		tsb := make([]byte, 4)
		binary.BigEndian.PutUint32(tsb, ts)
		out = append(out, tsb...)
	}
	return out
}

func TestParseKHLAnswerTimestampAdjustment(t *testing.T) {
	now := time.Now().Unix()
	topTS := int64(1000)
	hostTS := uint32(2000)

	na := make([]byte, 6)
	// 127.0.0.1 little-endian
	na[0], na[1], na[2], na[3] = 1, 0, 0, 127
	na[4], na[5] = 0x18, 0xCA // 6346

	nh := &G2Packet{Type: "NH", Compound: true, Children: []*G2Packet{
		{Type: "NA", Payload: na},
		{Type: "V", Payload: []byte("SHAR")},
		{Type: "TS", Payload: khlUint32Bytes(hostTS)},
	}}
	top := &G2Packet{Type: "TS", Payload: khlUint32Bytes(uint32(topTS))}
	pkt := &G2Packet{Type: "KHLA", Compound: true, Children: []*G2Packet{nh, top}}

	got := ParseKHLAnswer(pkt)
	if len(got) != 1 {
		t.Fatalf("hosts = %d, want 1", len(got))
	}
	if got[0].Addr != "127.0.0.1:6346" {
		t.Errorf("addr = %q, want 127.0.0.1:6346", got[0].Addr)
	}
	if got[0].Vendor != "SHAR" {
		t.Errorf("vendor = %q, want SHAR", got[0].Vendor)
	}
	wantSeen := int64(hostTS) + (now - topTS)
	if got[0].Seen != wantSeen {
		t.Errorf("seen = %d, want %d", got[0].Seen, wantSeen)
	}
}

func TestParseKHLAnswerInlineForm(t *testing.T) {
	now := time.Now().Unix()
	topTS := int64(500)
	inlineTS := uint32(900)

	ch := &G2Packet{Type: "CH", Payload: khlInlineAddr("127.0.0.2", 6347, inlineTS, true)}
	top := &G2Packet{Type: "TS", Payload: khlUint32Bytes(uint32(topTS))}
	pkt := &G2Packet{Type: "KHLA", Compound: true, Children: []*G2Packet{ch, top}}

	got := ParseKHLAnswer(pkt)
	if len(got) != 1 {
		t.Fatalf("hosts = %d, want 1", len(got))
	}
	if got[0].Addr != "127.0.0.2:6347" {
		t.Errorf("addr = %q, want 127.0.0.2:6347", got[0].Addr)
	}
	wantSeen := int64(inlineTS) + (now - topTS)
	if got[0].Seen != wantSeen {
		t.Errorf("seen = %d, want %d", got[0].Seen, wantSeen)
	}
}

func TestKHLFetchHostsScriptedPeer(t *testing.T) {
	srv, err := NewG2UDP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.setHandler(func(remote net.Addr, pkt *G2Packet) {
		if pkt == nil || pkt.Type != "KHLR" {
			return
		}
		topTS := uint32(1000)
		hostTS := uint32(2000)
		na := make([]byte, 6)
		na[0], na[1], na[2], na[3] = 1, 0, 0, 127
		na[4], na[5] = 0x18, 0xCA
		nh := &G2Packet{Type: "NH", Compound: true, Children: []*G2Packet{
			{Type: "NA", Payload: na},
			{Type: "V", Payload: []byte("SHAR")},
			{Type: "TS", Payload: khlUint32Bytes(hostTS)},
		}}
		// duplicate of host1 to test dedup
		nhDup := &G2Packet{Type: "NH", Compound: true, Children: []*G2Packet{
			{Type: "NA", Payload: append([]byte{}, na...)},
		}}
		ch := &G2Packet{Type: "CH", Payload: khlInlineAddr("127.0.0.2", 6347, 3000, true)}
		top := &G2Packet{Type: "TS", Payload: khlUint32Bytes(topTS)}
		ans := &G2Packet{Type: "KHLA", Compound: true, Children: []*G2Packet{nh, nhDup, ch, top}}
		_ = srv.Send(context.Background(), remote, ans)
	})

	addr := srv.Addr().String()
	hosts, err := fetchKHLHosts(context.Background(), addr, true)
	if err != nil {
		t.Fatalf("fetchKHLHosts: %v", err)
	}
	if len(hosts) != 2 {
		t.Fatalf("hosts = %d, want 2: %+v", len(hosts), hosts)
	}
	if hosts[0].Addr != "127.0.0.1:6346" {
		t.Errorf("host0 addr = %q", hosts[0].Addr)
	}
	if hosts[1].Addr != "127.0.0.2:6347" {
		t.Errorf("host1 addr = %q", hosts[1].Addr)
	}
}

func TestKHLFetchHostsMalformedDrop(t *testing.T) {
	srv, err := NewG2UDP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.setHandler(func(remote net.Addr, pkt *G2Packet) {
		// send garbage + a valid host
		conn, _ := net.DialUDP("udp", nil, remote.(*net.UDPAddr))
		if conn != nil {
			conn.Write([]byte{0x00, 0xFF, 0x00})
			conn.Close()
		}
		topTS := uint32(1000)
		ch := &G2Packet{Type: "CH", Payload: khlInlineAddr("127.0.0.3", 6348, 1111, true)}
		top := &G2Packet{Type: "TS", Payload: khlUint32Bytes(topTS)}
		ans := &G2Packet{Type: "KHLA", Compound: true, Children: []*G2Packet{ch, top}}
		_ = srv.Send(context.Background(), remote, ans)
	})

	hosts, err := fetchKHLHosts(context.Background(), srv.Addr().String(), true)
	if err != nil {
		t.Fatalf("fetch: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1: %+v", len(hosts), hosts)
	}
	if hosts[0].Addr != "127.0.0.3:6348" {
		t.Errorf("addr = %q", hosts[0].Addr)
	}
}

func TestKHLFetchHostsTimeoutPartial(t *testing.T) {
	srv, err := NewG2UDP("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := srv.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer srv.Close()

	srv.setHandler(func(remote net.Addr, pkt *G2Packet) {
		if pkt == nil || pkt.Type != "KHLR" {
			return
		}
		// first host immediately
		ch1 := &G2Packet{Type: "CH", Payload: khlInlineAddr("127.0.0.4", 6349, 1, true)}
		top := &G2Packet{Type: "TS", Payload: khlUint32Bytes(1000)}
		ans1 := &G2Packet{Type: "KHLA", Compound: true, Children: []*G2Packet{ch1, top}}
		_ = srv.Send(context.Background(), remote, ans1)

		// second host after delay
		go func() {
			time.Sleep(500 * time.Millisecond)
			ch2 := &G2Packet{Type: "CH", Payload: khlInlineAddr("127.0.0.5", 6350, 2, true)}
			ans2 := &G2Packet{Type: "KHLA", Compound: true, Children: []*G2Packet{ch2, top}}
			_ = srv.Send(context.Background(), remote, ans2)
		}()
	})

	cctx, ccancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer ccancel()
	hosts, err := fetchKHLHosts(cctx, srv.Addr().String(), true)
	if err != nil {
		t.Fatalf("expected no error on timeout, got %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("hosts = %d, want 1 (partial): %+v", len(hosts), hosts)
	}
	if hosts[0].Addr != "127.0.0.4:6349" {
		t.Errorf("addr = %q", hosts[0].Addr)
	}
}

func TestNewKHLRequestType(t *testing.T) {
	p := NewKHLRequest()
	if p.Type != "KHLR" {
		t.Fatalf("type = %q, want KHLR", p.Type)
	}
	if p.Compound {
		t.Fatal("request should be leaf")
	}
}
