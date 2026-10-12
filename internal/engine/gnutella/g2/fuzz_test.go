// SPDX-License-Identifier: GPL-3.0-or-later

package g2

import (
	"bytes"
	"testing"
)

// FuzzG2ParsePacket drives the parser with arbitrary bytes. Two invariants
// must hold for anything Parse accepts:
//
//  1. Parse must not panic. It is the first code to touch hostile input from
//     the network, so a panic here is a remotely triggerable crash.
//  2. Marshal(Parse(b)) must re-parse to a tree equal to Parse(b). The emitter
//     is allowed to canonicalise the length field width, but it must never
//     lose or reshape a packet.
func FuzzG2ParsePacket(f *testing.F) {
	f.Add(leafPacket())
	f.Add(parentPacket())
	f.Add(beLeafPacket())
	f.Add(zeroCompoundPacket())
	f.Add([]byte{})
	f.Add([]byte{0x00})
	f.Add([]byte{0xC8, 0xFF})
	f.Add([]byte{0x4C, 0x05, 0x41, 0x41, 0x48, 0x00, 0x54, 0x4F, 0xFF})

	f.Fuzz(func(t *testing.T, b []byte) {
		p, err := Parse(b)
		if err != nil {
			return
		}
		enc, err := p.Marshal()
		if err != nil {
			t.Fatalf("Marshal(Parse(%x)) failed: %v", b, err)
		}
		again, err := Parse(enc)
		if err != nil {
			t.Fatalf("Parse(Marshal(%x)) failed: %v (encoded %x)", b, err, enc)
		}
		if !packetsEqual(p, again) {
			t.Fatalf("tree changed on round trip:\n first = %s\nsecond = %s", p, again)
		}
	})
}

// packetsEqual reports whether two parsed trees are structurally identical.
func packetsEqual(a, b *Packet) bool {
	if a == nil || b == nil {
		return a == b
	}
	if a.Type != b.Type || a.Compound != b.Compound || a.BigEndian != b.BigEndian {
		return false
	}
	if !bytes.Equal(a.Payload, b.Payload) {
		return false
	}
	if len(a.Children) != len(b.Children) {
		return false
	}
	for i := range a.Children {
		if !packetsEqual(a.Children[i], b.Children[i]) {
			return false
		}
	}
	return true
}
