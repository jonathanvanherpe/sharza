// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"testing"
)

func FuzzFileRequest(f *testing.F) {
	f.Add([]byte{})
	f.Add(FileRequest{Hash: [16]byte{1}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		fr, err := DecodeFileRequest(data)
		if err != nil {
			return
		}
		b := fr.Marshal()
		g, err := DecodeFileRequest(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzFileReqAnswer(f *testing.F) {
	f.Add([]byte{})
	f.Add(FileReqAnswer{Hash: [16]byte{1}, Name: "file.txt"}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		a, err := DecodeFileReqAnswer(data)
		if err != nil {
			return
		}
		b := a.Marshal()
		g, err := DecodeFileReqAnswer(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}

func FuzzFileNotFound(f *testing.F) {
	f.Add([]byte{})
	f.Add(FileNotFound{Hash: [16]byte{1}}.Marshal())
	f.Fuzz(func(t *testing.T, data []byte) {
		fn, err := DecodeFileNotFound(data)
		if err != nil {
			return
		}
		b := fn.Marshal()
		g, err := DecodeFileNotFound(b)
		if err != nil {
			t.Fatalf("re-decode failed: %v", err)
		}
		if !bytes.Equal(g.Marshal(), b) {
			t.Fatalf("round-trip mismatch")
		}
	})
}
