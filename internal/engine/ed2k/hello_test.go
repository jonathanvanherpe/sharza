// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func FuzzHello(f *testing.F) {
	f.Add([]byte{})
	f.Add(Hello{Hash: [16]byte{1}, ClientID: 2, Port: 3, Tags: []Tag{{Type: 0x02, Key: 0x01, Str: "x"}}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		h, err := DecodeHello(data)
		if err != nil {
			return
		}
		b := h.Marshal()
		g, err := DecodeHello(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzHelloAnswer(f *testing.F) {
	f.Add([]byte{})
	f.Add(HelloAnswer{Hash: [16]byte{1}, ClientID: 2, Port: 3, Tags: []Tag{{Type: 0x02, Key: 0x01, Str: "x"}}, ServerIP: [4]byte{1, 2, 3, 4}, ServerPort: 5}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := DecodeHelloAnswer(data)
		if err != nil {
			return
		}
		b := a.Marshal()
		g, err := DecodeHelloAnswer(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}
