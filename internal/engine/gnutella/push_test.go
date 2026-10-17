// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

import (
	"bytes"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
)

// testGUID is a fixed servent GUID for byte-level assertions.
func testGUID(t *testing.T, s string) [idSize]byte {
	t.Helper()
	raw, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad test guid %q: %v", s, err)
	}
	if len(raw) != idSize {
		t.Fatalf("test guid %q is %d bytes, want %d", s, len(raw), idSize)
	}
	var g [idSize]byte
	copy(g[:], raw)
	return g
}

const (
	guidA = "d51dff817f895598ff0065537c09d503"
	guidB = "00112233445566778899aabbccddeeff"
)

func TestEncodePushWireLayout(t *testing.T) {
	p := Push{
		Target:    testGUID(t, guidA),
		FileIndex: 0x01020304,
		IP:        [4]byte{192, 168, 1, 9},
		Port:      6346,
	}
	got := EncodePush(p)
	if len(got) != pushPayloadSize {
		t.Fatalf("payload is %d bytes, want %d", len(got), pushPayloadSize)
	}
	// The 16-byte target GUID is first, in order.
	wantTarget := testGUID(t, guidA)
	if !bytes.Equal(got[0:16], wantTarget[:]) {
		t.Errorf("target GUID wrong: % x", got[0:16])
	}
	// File index is little-endian.
	if want := []byte{0x04, 0x03, 0x02, 0x01}; !bytes.Equal(got[16:20], want) {
		t.Errorf("file index = % x, want % x (little-endian)", got[16:20], want)
	}
	// The IPv4 address is the four address bytes in order, not reversed.
	if want := []byte{192, 168, 1, 9}; !bytes.Equal(got[20:24], want) {
		t.Errorf("ip = % x, want % x (address order)", got[20:24], want)
	}
	// Port 6346 = 0x18CA, little-endian on the wire.
	if want := []byte{0xCA, 0x18}; !bytes.Equal(got[24:26], want) {
		t.Errorf("port = % x, want % x (little-endian)", got[24:26], want)
	}
}

func TestEncodePushRoundTrip(t *testing.T) {
	p := Push{
		Target:    testGUID(t, guidB),
		FileIndex: 4294967295,
		IP:        [4]byte{10, 0, 0, 7},
		Port:      1,
	}
	got, err := DecodePush(EncodePush(p))
	if err != nil {
		t.Fatalf("DecodePush: %v", err)
	}
	if got != p {
		t.Errorf("round trip = %+v, want %+v", got, p)
	}
}

func TestDecodePushAcceptsTrailingGGEP(t *testing.T) {
	p := Push{Target: testGUID(t, guidA), FileIndex: 7, IP: [4]byte{1, 2, 3, 4}, Port: 5}
	payload := append(EncodePush(p), 0xC3, 0x47, 0x47, 0x45, 0x50) // a GGEP tail
	got, err := DecodePush(payload)
	if err != nil {
		t.Fatalf("DecodePush with trailing block: %v", err)
	}
	if got != p {
		t.Errorf("decoded %+v, want %+v", got, p)
	}
}

func TestDecodePushTooShort(t *testing.T) {
	_, err := DecodePush(make([]byte, pushPayloadSize-1))
	if !errors.Is(err, ErrPushBadFormat) {
		t.Fatalf("short payload error = %v, want ErrPushBadFormat", err)
	}
}

func TestPushValid(t *testing.T) {
	cases := []struct {
		name string
		p    Push
		want bool
	}{
		{"normal", Push{IP: [4]byte{1, 2, 3, 4}, Port: 6346}, true},
		{"zero port", Push{IP: [4]byte{1, 2, 3, 4}}, false},
		{"zero address", Push{Port: 6346}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.p.Valid(); got != tc.want {
				t.Errorf("Valid() = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestEncodeGIVFormat(t *testing.T) {
	g := GIV{FileIndex: 124, GUID: testGUID(t, guidA)}
	got := string(EncodeGIV(g))
	want := "GIV 124:" + strings.ToUpper(guidA) + "/\n\n"
	if got != want {
		t.Errorf("EncodeGIV = %q, want %q", got, want)
	}
}

func TestEncodeGIVWithName(t *testing.T) {
	g := GIV{FileIndex: 1, GUID: testGUID(t, guidB), Name: "my%20song.mp3"}
	got := string(EncodeGIV(g))
	if !strings.HasSuffix(got, "/my%20song.mp3\n\n") {
		t.Errorf("EncodeGIV = %q, want the name kept verbatim after the slash", got)
	}
}

func TestGIVRoundTrip(t *testing.T) {
	g := GIV{FileIndex: 4096, GUID: testGUID(t, guidA), Name: "file.bin"}
	got, err := DecodeGIV(EncodeGIV(g))
	if err != nil {
		t.Fatalf("DecodeGIV: %v", err)
	}
	if got != g {
		t.Errorf("round trip = %+v, want %+v", got, g)
	}
}

func TestDecodeGIVVariants(t *testing.T) {
	hexA := strings.ToUpper(guidA)
	cases := []struct {
		name string
		line string
		want GIV
	}{
		{
			"with name",
			"GIV 124:" + hexA + "/my%20song.mp3",
			GIV{FileIndex: 124, GUID: testGUID(t, guidA), Name: "my%20song.mp3"},
		},
		{
			"trailing slash only",
			"GIV 1:" + hexA + "/",
			GIV{FileIndex: 1, GUID: testGUID(t, guidA)},
		},
		{
			"no slash",
			"GIV 1:" + hexA,
			GIV{FileIndex: 1, GUID: testGUID(t, guidA)},
		},
		{
			"lowercase hex",
			"GIV 7:" + guidA + "/",
			GIV{FileIndex: 7, GUID: testGUID(t, guidA)},
		},
		{
			"trailing CRLF",
			"GIV 7:" + hexA + "/\r\n",
			GIV{FileIndex: 7, GUID: testGUID(t, guidA)},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := DecodeGIV([]byte(tc.line))
			if err != nil {
				t.Fatalf("DecodeGIV(%q): %v", tc.line, err)
			}
			if got != tc.want {
				t.Errorf("DecodeGIV(%q) = %+v, want %+v", tc.line, got, tc.want)
			}
		})
	}
}

func TestDecodeGIVBad(t *testing.T) {
	hexA := strings.ToUpper(guidA)
	cases := []struct {
		name string
		line string
	}{
		{"missing prefix", "GNUTELLA 124:" + hexA + "/"},
		{"missing colon", "GIV 124" + hexA + "/"},
		{"short guid", "GIV 124:" + hexA[:30] + "/"},
		{"non-hex guid", "GIV 124:" + strings.Repeat("zz", 16) + "/"},
		{"non-numeric index", "GIV 12x:" + hexA + "/"},
		{"empty index", "GIV :" + hexA + "/"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := DecodeGIV([]byte(tc.line)); !errors.Is(err, ErrGIVBadFormat) {
				t.Errorf("DecodeGIV(%q) error = %v, want ErrGIVBadFormat", tc.line, err)
			}
		})
	}
}
