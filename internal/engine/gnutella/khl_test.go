// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Tests for the G2 KHL host-cache exchange: SGP datagram framing, the
// KHL/KHLA address forms, and the bootstrap loop closed end to end.

import (
	"bytes"
	"net"
	"strconv"
	"testing"
	"time"
)

// addrField returns the six-byte G2 form of an IPv4 address and port:
// the four octets, then a big-endian port.
func addrField(ip [4]byte, port uint16) []byte {
	return []byte{ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
}

// TestSGPRoundTrip encodes a one-part SGP datagram and parses it back.
func TestSGPRoundTrip(t *testing.T) {
	payload := []byte("KHLR")
	dg := encodeSGP(0x1234, payload)
	if len(dg) != sgpHeaderSize+len(payload) {
		t.Fatalf("datagram length = %d, want %d", len(dg), sgpHeaderSize+len(payload))
	}
	if string(dg[0:3]) != sgpTag {
		t.Fatalf("tag = %q, want %q", dg[0:3], sgpTag)
	}
	got, ok := parseSGP(dg)
	if !ok {
		t.Fatal("parseSGP rejected our own datagram")
	}
	if got.seq != 0x1234 || got.part != 1 || got.count != 1 {
		t.Fatalf("header = seq %#x part %d count %d, want seq 0x1234 part 1 count 1",
			got.seq, got.part, got.count)
	}
	if !bytes.Equal(got.data, payload) {
		t.Fatalf("payload = %q, want %q", got.data, payload)
	}
}

// TestParseSGPRejectsGarbage checks a short or untagged datagram is
// refused before any header field is trusted.
func TestParseSGPRejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{
		nil,
		[]byte("SGP"),
		make([]byte, sgpHeaderSize), // zeroed tag
	} {
		if _, ok := parseSGP(in); ok {
			t.Fatalf("parseSGP(% x) accepted a datagram with no tag", in)
		}
	}
}

// TestParseKHLHostsForms covers the address shapes a KHL/KHLA packet is
// seen in: NA sub-packets (with and without fields), flat entries, the
// Shareaza compound form with a trailing address, and filtering.
func TestParseKHLHostsForms(t *testing.T) {
	na := func(ip [4]byte, port uint16) *g2Packet {
		return &g2Packet{Type: g2TypeCH, Compound: true, Children: []*g2Packet{
			{Type: g2TypeNA, Data: addrField(ip, port)},
		}}
	}
	khla := func(entries ...*g2Packet) *g2Packet {
		return &g2Packet{Type: g2TypeKHLA, Compound: true, Children: entries}
	}

	// The Shareaza KHLA builder writes V, then a zero separator, then a
	// bare address, port and timestamp. Assemble those bytes exactly.
	withVendor := []byte{
		0x5C, 0x16, 'K', 'H', 'L', 'A',
		0x4C, 0x12, 'C', 'H',
		0x40, 0x04, 'V', 'S', 'H', 'A', 'R',
		0x00,
		0x01, 0x02, 0x03, 0x04, 0x18, 0xCA,
		0x00, 0x00, 0x00, 0x01,
	}
	vendorPkt, _, err := decodeG2Packet(withVendor)
	if err != nil {
		t.Fatalf("decode vendor form: %v", err)
	}

	flatTS := append(addrField([4]byte{1, 2, 3, 4}, 6346), 0x00, 0x00, 0x00, 0x01)

	tests := []struct {
		name  string
		pkt   *g2Packet
		allow bool
		want  []string
	}{
		{"compound NA", khla(na([4]byte{1, 2, 3, 4}, 6346)), false, []string{"1.2.3.4:6346"}},
		{"compound NA with fields", khla(&g2Packet{Type: g2TypeCH, Compound: true, Children: []*g2Packet{
			{Type: g2TypeNA, Data: addrField([4]byte{1, 2, 3, 4}, 6346)},
			{Type: g2TypeTS, Data: []byte{0, 0, 0, 1}},
			{Type: g2TypeV, Data: []byte("SHAR")},
		}}), false, []string{"1.2.3.4:6346"}},
		{"flat 6", khla(&g2Packet{Type: g2TypeCH, Data: addrField([4]byte{1, 2, 3, 4}, 6346)}), false, []string{"1.2.3.4:6346"}},
		{"flat 10", khla(&g2Packet{Type: g2TypeCH, Data: flatTS}), false, []string{"1.2.3.4:6346"}},
		{"Shareaza vendor compound", vendorPkt, false, []string{"1.2.3.4:6346"}},
		{"unspecified dropped", khla(na([4]byte{0, 0, 0, 0}, 6346)), false, nil},
		{"loopback dropped", khla(na([4]byte{127, 0, 0, 1}, 6346)), false, nil},
		{"loopback kept when allowed", khla(na([4]byte{127, 0, 0, 1}, 6346)), true, []string{"127.0.0.1:6346"}},
		{"deduplicated", khla(na([4]byte{1, 2, 3, 4}, 6346), na([4]byte{1, 2, 3, 4}, 6346)), false, []string{"1.2.3.4:6346"}},
		{"non-entry children ignored", khla(na([4]byte{1, 2, 3, 4}, 6346), &g2Packet{Type: g2TypeTS, Data: []byte{0, 0, 0, 1}}), false, []string{"1.2.3.4:6346"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := parseKHLHosts(tc.pkt, tc.allow)
			if err != nil {
				t.Fatalf("parseKHLHosts: %v", err)
			}
			if !equalStrings(got, tc.want) {
				t.Fatalf("hosts = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestParseKHLHostsRejectsNonHostLists checks a packet that is not a
// compound KHL/KHLA is reported as an error, so a caller can tell "not a
// host list" from "no hosts".
func TestParseKHLHostsRejectsNonHostLists(t *testing.T) {
	if _, err := parseKHLHosts(&g2Packet{Type: g2TypeKHLR}, false); err == nil {
		t.Error("a non-compound KHLR was accepted as a host list")
	}
	if _, err := parseKHLHosts(&g2Packet{Type: g2TypeNA, Compound: true}, false); err == nil {
		t.Error("a non-KHL packet was accepted as a host list")
	}
}

// TestEngineDialsKHLFetchedPeer is the ukhl: bootstrap loop closed: an
// engine with no configured peers is given one ukhl: hub, the hub
// answers its KHLR with a KHLA naming a second engine's loopback
// address, and the first engine's dial machinery must connect to it.
func TestEngineDialsKHLFetchedPeer(t *testing.T) {
	target, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	hub, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp hub: %v", err)
	}
	t.Cleanup(func() { _ = hub.Close() })

	answer := khlAnswer(t, target.Addr().String())
	served := make(chan struct{})
	go func() {
		buf := make([]byte, maxKHLDatagram)
		for {
			n, from, err := hub.ReadFromUDP(buf)
			if err != nil {
				return
			}
			pkt, ok := parseSGP(buf[:n])
			if !ok || pkt.part != 1 || pkt.count != 1 {
				continue
			}
			g, _, err := decodeG2Packet(pkt.data)
			if err != nil || g.Type != g2TypeKHLR {
				continue
			}
			close(served)
			_, _ = hub.WriteToUDP(encodeSGP(7, answer), from)
			return
		}
	}()

	src, _ := startEngine(t, Options{
		UKHL: []string{hub.LocalAddr().String()},
		// The answer names 127.0.0.1, which production drops; a test
		// may only reach loopback, so relax it.
		khlAllowLoopback:  true,
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	if len(src.opts.Peers) != 0 {
		t.Fatalf("Peers = %v, want empty: discovery must be the ukhl hub's doing", src.opts.Peers)
	}

	deadline := time.Now().Add(testDeadline)
	for {
		if peerCount(src) > 0 && peerCount(target) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("KHL-fetched peer never dialed: src peers=%d, target peers=%d",
				peerCount(src), peerCount(target))
		}
		time.Sleep(20 * time.Millisecond)
	}
	select {
	case <-served:
	case <-time.After(time.Second):
		t.Fatal("the engine never sent a KHLR to the ukhl hub")
	}

	// The connection must have completed its handshake, not raced and died.
	time.Sleep(300 * time.Millisecond)
	if peerCount(src) == 0 || peerCount(target) == 0 {
		t.Errorf("connection did not survive the handshake: src peers=%d, target peers=%d",
			peerCount(src), peerCount(target))
	}
}

// khlAnswer builds a KHLA datagram body naming host:port in the
// canonical NA-sub-packet form.
func khlAnswer(t *testing.T, hostport string) []byte {
	t.Helper()
	host, portStr, err := net.SplitHostPort(hostport)
	if err != nil {
		t.Fatalf("split %q: %v", hostport, err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		t.Fatalf("khlAnswer needs an IPv4 address, got %q", host)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		t.Fatalf("port %q is not usable", portStr)
	}
	var a [4]byte
	copy(a[:], ip)
	return (&g2Packet{
		Type:     g2TypeKHLA,
		Compound: true,
		Children: []*g2Packet{{
			Type:     g2TypeCH,
			Compound: true,
			Children: []*g2Packet{{Type: g2TypeNA, Data: addrField(a, uint16(port))}},
		}},
	}).marshal()
}

// equalStrings compares two slices of addresses as sets-insensitive
// lists, so a nil and an empty result are treated the same.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
