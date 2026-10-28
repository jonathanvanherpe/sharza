// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

func TestEncodeDecodePushRoundTrip(t *testing.T) {
	var sid [16]byte
	for i := range sid {
		sid[i] = byte(i + 1)
	}
	p := Push{
		ServentID: sid,
		FileIndex: 0x12345678,
		IPAddress: [4]byte{192, 168, 1, 2},
		Port:      6346,
	}
	enc := EncodePush(p)
	dec, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if dec.ServentID != p.ServentID {
		t.Errorf("servent id mismatch: got %x want %x", dec.ServentID, p.ServentID)
	}
	if dec.FileIndex != p.FileIndex {
		t.Errorf("file index: got %d want %d", dec.FileIndex, p.FileIndex)
	}
	if dec.IPAddress != p.IPAddress {
		t.Errorf("ip: got %v want %v", dec.IPAddress, p.IPAddress)
	}
	if dec.Port != p.Port {
		t.Errorf("port: got %d want %d", dec.Port, p.Port)
	}
}

func TestPushFieldByteOrder(t *testing.T) {
	// Build a payload by hand to assert wire byte order:
	// servent id 16 bytes, file index LE, IP BE, port LE.
	var buf [pushPayloadSize]byte
	for i := 0; i < 16; i++ {
		buf[i] = byte(0xA0 + i)
	}
	binary.LittleEndian.PutUint32(buf[16:20], 0x01020304)
	buf[20] = 10
	buf[21] = 0
	buf[22] = 0
	buf[23] = 5
	binary.LittleEndian.PutUint16(buf[24:26], 0x0506)

	dec, err := DecodePush(buf[:])
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if dec.FileIndex != 0x01020304 {
		t.Errorf("file index LE decode: got 0x%08x", dec.FileIndex)
	}
	if dec.IPAddress != [4]byte{10, 0, 0, 5} {
		t.Errorf("ip BE decode: got %v", dec.IPAddress)
	}
	if dec.Port != 0x0506 {
		t.Errorf("port LE decode: got 0x%04x", dec.Port)
	}

	// Encode must produce the same bytes.
	enc := EncodePush(dec)
	if len(enc) != pushPayloadSize {
		t.Fatalf("encoded len %d", len(enc))
	}
	for i := range buf {
		if enc[i] != buf[i] {
			t.Errorf("byte %d: got 0x%02x want 0x%02x", i, enc[i], buf[i])
		}
	}
}

func TestDecodePushMalformed(t *testing.T) {
	cases := []struct {
		name string
		b    []byte
	}{
		{"empty", []byte{}},
		{"truncated 1", make([]byte, 1)},
		{"truncated 25", make([]byte, 25)},
		{"too long", make([]byte, 27)},
	}
	for _, c := range cases {
		if _, err := DecodePush(c.b); err == nil {
			t.Errorf("%s: expected error", c.name)
		} else if !errors.Is(err, ErrPushBadFormat) {
			t.Errorf("%s: unexpected err %v", c.name, err)
		}
	}
}

func TestHandlePushKeepsConnectionOpen(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       5 * time.Second,
	})
	r, conn := dialEngine(t, eng.Addr().String())

	// Valid push.
	var sid [16]byte
	sid[0] = 0xAB
	push := Push{ServentID: sid, FileIndex: 7, IPAddress: [4]byte{127, 0, 0, 1}, Port: 6346}
	sendMsg(t, conn, Header{ID: testID(0x40), Type: MsgPush, TTL: 3, Hops: 0, Length: uint32(len(EncodePush(push)))}, EncodePush(push))

	// Malformed push (truncated).
	sendMsg(t, conn, Header{ID: testID(0x41), Type: MsgPush, TTL: 3, Hops: 0, Length: 5}, []byte{1, 2, 3, 4, 5})

	// Connection must still be alive: a ping gets a pong.
	sendMsg(t, conn, Header{ID: testID(0x42), Type: MsgPing, TTL: 3, Hops: 0}, nil)
	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgPong || hdr.ID != testID(0x42) {
		t.Fatalf("after push, got type %s id %x, want pong for 42", typeName(hdr.Type), hdr.ID)
	}
}