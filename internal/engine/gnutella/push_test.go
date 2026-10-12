// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// PUSH tests. The codec is pinned against the published 26-byte layout,
// and the engine's send side is driven over real TCP with scripted 0.6
// peers, the same way the handshake and search slices are: the wire bytes
// a peer receives are the contract, not the encoder's own idea of them.

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		GUID:      testID(0x5A),
		FileIndex: 0x01020304,
		IP:        [4]byte{192, 168, 1, 2},
		Port:      0x1A2B,
	}
	b := EncodePush(p)
	if len(b) != pushPayloadSize {
		t.Fatalf("EncodePush length = %d, want %d", len(b), pushPayloadSize)
	}
	dec, err := DecodePush(b)
	if err != nil {
		t.Fatalf("DecodePush: %v", err)
	}
	if dec != p {
		t.Errorf("round trip = %+v, want %+v", dec, p)
	}
}

// TestDecodePushMalformed pins the minimum length. A PUSH is fixed-size:
// the 16-byte GUID, 4-byte index, 4-byte address and 2-byte port are all
// mandatory, so anything below 26 bytes cannot be decoded and must be
// refused rather than read past the end. The brief's "under 22" would
// accept a payload with no address; see docs/handoff.md.
func TestDecodePushMalformed(t *testing.T) {
	valid := EncodePush(Push{
		GUID:      testID(0x01),
		FileIndex: 1,
		IP:        [4]byte{1, 2, 3, 4},
		Port:      1,
	})
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", nil},
		{"guid only", valid[:16]},
		{"brief's 22 bytes (no address)", valid[:22]},
		{"address truncated", valid[:23]},
		{"one short", valid[:25]},
	}
	for _, c := range cases {
		if _, err := DecodePush(c.b); err == nil {
			t.Errorf("%s: DecodePush accepted a short payload", c.name)
		}
	}

	// Bytes after the address are a GGEP trailer and are ignored, not an
	// error: a real peer may append one.
	withTrailer := append(append([]byte(nil), valid...), 0xC3, 0x01)
	if _, err := DecodePush(withTrailer); err != nil {
		t.Errorf("DecodePush with a trailing GGEP block: %v", err)
	}
}

// TestEnginePushFanoutToPeers is the send-side evidence: Engine.Push
// writes one PUSH frame to every connected peer, carrying the hit's
// servent GUID and file index and the engine's own listen address as the
// dial-back target.
func TestEnginePushFanoutToPeers(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour, // silence must not be mistaken for a PUSH
		IdleTimeout:       10 * time.Second,
	})
	r1, _ := dialEngine(t, eng.Addr().String())
	r2, _ := dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 2)

	qh := QueryHit{
		GUID: testID(0xA5),
		IP:   [4]byte{203, 0, 113, 7}, // the firewalled source
		Port: 6346,
	}
	hit := FileHit{FileIndex: 0x2A, FileSize: 4000, FileName: "firewalled.mp3"}
	if err := eng.Push(qh, hit); err != nil {
		t.Fatalf("Push: %v", err)
	}

	engAddr := eng.Addr().(*net.TCPAddr)
	wantIP := engAddr.IP.To4()
	if wantIP == nil {
		t.Fatalf("engine listener %s is not IPv4", engAddr)
	}
	for i, r := range []*bufio.Reader{r1, r2} {
		hdr, payload := readMsg(t, r)
		if hdr.Type != MsgPush {
			t.Fatalf("peer %d: message type = %s, want push", i, typeName(hdr.Type))
		}
		push, err := DecodePush(payload)
		if err != nil {
			t.Fatalf("peer %d: DecodePush: %v", i, err)
		}
		if push.GUID != qh.GUID {
			t.Errorf("peer %d: GUID = %x, want the hit's servent GUID %x", i, push.GUID, qh.GUID)
		}
		if push.FileIndex != hit.FileIndex {
			t.Errorf("peer %d: file index = %d, want %d", i, push.FileIndex, hit.FileIndex)
		}
		if push.Port != uint16(engAddr.Port) {
			t.Errorf("peer %d: dial-back port = %d, want the engine listener %d",
				i, push.Port, engAddr.Port)
		}
		if push.IP != [4]byte{wantIP[0], wantIP[1], wantIP[2], wantIP[3]} {
			t.Errorf("peer %d: dial-back IP = %v, want the engine listener %v", i, push.IP, wantIP)
		}
	}
}

// TestEnginePushRecognisesDialBack pins the pending-push registry: after
// a PUSH to a source address, an inbound connection from that address is
// logged as the expected dial-back instead of an unexplained peer.
func TestEnginePushRecognisesDialBack(t *testing.T) {
	var (
		mu    sync.Mutex
		lines []string
	)
	logf := func(format string, args ...any) {
		mu.Lock()
		lines = append(lines, fmt.Sprintf(format, args...))
		mu.Unlock()
	}
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Logf:              logf,
	})
	// A peer carries the PUSH out; without a successful write there is
	// nothing to dial back to and the address must not be registered.
	_, _ = dialEngine(t, eng.Addr().String())
	waitForPeers(t, eng, 1)

	qh := QueryHit{GUID: testID(0x11), IP: [4]byte{127, 0, 0, 1}, Port: 6346}
	if err := eng.Push(qh, FileHit{FileIndex: 1, FileSize: 1, FileName: "x"}); err != nil {
		t.Fatalf("Push: %v", err)
	}

	// The source dials back from the pending address.
	_, _ = dialEngine(t, eng.Addr().String())

	deadline := time.Now().Add(testDeadline)
	for {
		mu.Lock()
		found := false
		for _, l := range lines {
			if strings.Contains(l, "expected push connection from 127.0.0.1") {
				found = true
				break
			}
		}
		snapshot := append([]string(nil), lines...)
		mu.Unlock()
		if found {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("no expected-push-connection log line; got %q", snapshot)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestEnginePushNoPeersIsNotAnError mirrors Search: a push with nobody to
// carry it is not a failure, and it must not register an address that no
// frame ever reached.
func TestEnginePushNoPeersIsNotAnError(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	qh := QueryHit{GUID: testID(0x22), IP: [4]byte{127, 0, 0, 1}, Port: 1}
	if err := eng.Push(qh, FileHit{FileIndex: 1}); err != nil {
		t.Fatalf("Push with no peers = %v, want nil", err)
	}
	if eng.pushes.take("127.0.0.1") {
		t.Error("Push with no peers registered its source as awaiting a dial-back")
	}
}
