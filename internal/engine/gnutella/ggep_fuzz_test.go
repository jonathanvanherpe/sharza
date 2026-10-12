// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import "testing"

func FuzzDecodeGGEP(f *testing.F) {
	// Seeds: the browse marker, a marker with data, and a multi-extension
	// block, all produced by the encoder so the fuzzer starts from valid
	// shapes as well as the malformed ones it will discover.
	f.Add(EncodeGGEP([]GGEPExtension{{ID: "BH"}}))
	f.Add(EncodeGGEP([]GGEPExtension{{ID: "LF", Data: []byte{1, 2, 3}}}))
	f.Add(EncodeGGEP([]GGEPExtension{{ID: "BH"}, {ID: "CH"}, {ID: "XYZ", Data: []byte{9}}}))
	f.Add([]byte{0xC3})
	f.Add([]byte{0xC3, 0x82, 'B', 'H', 0x40})

	f.Fuzz(func(t *testing.T, b []byte) {
		exts, err := DecodeGGEP(b)
		if err != nil {
			return
		}
		// Anything that decodes must re-encode and decode identically.
		reencoded := EncodeGGEP(exts)
		redecoded, err := DecodeGGEP(reencoded)
		if err != nil {
			t.Fatalf("re-decode of % X failed: %v", reencoded, err)
		}
		if len(redecoded) != len(exts) {
			t.Fatalf("re-decode count %d != %d", len(redecoded), len(exts))
		}
	})
}
