// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Push tests. The firewalled case is two engines over real loopback TCP:
// the source holds the file and refuses a direct GET, and the requester
// reaches it only by PUSH and the dial-back that follows. Codec tests pin
// the 26-byte PUSH layout and the QUERYHIT client ID trailer.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// findHit returns the QUERYHIT and file hit naming name in hits.
func findHit(t *testing.T, hits []QueryHit, name string) (QueryHit, FileHit) {
	t.Helper()
	for _, qh := range hits {
		for _, h := range qh.Hits {
			if h.FileName == name {
				return qh, h
			}
		}
	}
	t.Fatalf("no hit named %q among %d QUERYHIT(s)", name, len(hits))
	return QueryHit{}, FileHit{}
}

func TestPushEncodeDecodeRoundTrip(t *testing.T) {
	want := Push{
		ServentID: testID(0xA5),
		IP:        [4]byte{192, 0, 2, 7},
		Port:      6346,
		FileIndex: 0x01020304,
	}
	enc := EncodePush(want)
	if len(enc) != 26 {
		t.Fatalf("encoded PUSH is %d bytes, want 26", len(enc))
	}
	got, err := DecodePush(enc)
	if err != nil {
		t.Fatalf("DecodePush: %v", err)
	}
	if got != want {
		t.Errorf("round trip = %+v, want %+v", got, want)
	}
}

// TestPushPayloadLayout pins the byte order against the spec: IP
// big-endian, port and index little-endian. A round trip alone would not
// catch both ends being wrong the same way.
func TestPushPayloadLayout(t *testing.T) {
	p := Push{
		ServentID: testID(0x11),
		IP:        [4]byte{10, 20, 30, 40},
		Port:      0x1234,
		FileIndex: 0x0A0B0C0D,
	}
	b := EncodePush(p)
	if !bytes.Equal(b[0:16], p.ServentID[:]) {
		t.Errorf("servent ID bytes = %x", b[0:16])
	}
	if !bytes.Equal(b[16:20], []byte{10, 20, 30, 40}) {
		t.Errorf("IP bytes = %x, want big-endian 0a141e28", b[16:20])
	}
	if binary.LittleEndian.Uint16(b[20:22]) != 0x1234 || b[20] != 0x34 || b[21] != 0x12 {
		t.Errorf("port bytes = %x, want little-endian 3412", b[20:22])
	}
	if binary.LittleEndian.Uint32(b[22:26]) != 0x0A0B0C0D || b[22] != 0x0D {
		t.Errorf("index bytes = %x, want little-endian 0d0c0b0a", b[22:26])
	}
}

func TestPushDecodeRejectsWrongLength(t *testing.T) {
	good := EncodePush(Push{ServentID: testID(1)})
	for _, n := range []int{0, 25, 27} {
		b := make([]byte, n)
		copy(b, good)
		if _, err := DecodePush(b); !errors.Is(err, ErrPushBadFormat) {
			t.Errorf("DecodePush(%d bytes) error = %v, want ErrPushBadFormat", n, err)
		}
	}
}

// TestPushQueryHitCarriesServentID checks the 0.6 trailer: a 16-byte
// client ID after the last hit is decoded, and any other trailing length
// is left undecoded rather than read as an ID.
func TestPushQueryHitCarriesServentID(t *testing.T) {
	qh := QueryHit{
		Port:        6346,
		IP:          [4]byte{127, 0, 0, 1},
		Hits:        []FileHit{{FileIndex: 3, FileSize: 9, FileName: "a.mp3"}},
		ClientID:    testID(0xC3),
		HasClientID: true,
	}
	enc := EncodeQueryHit(qh)
	dec, err := DecodeQueryHit(enc)
	if err != nil {
		t.Fatalf("DecodeQueryHit: %v", err)
	}
	if !dec.HasClientID || dec.ClientID != qh.ClientID {
		t.Errorf("client ID = %x (has=%v), want %x", dec.ClientID, dec.HasClientID, qh.ClientID)
	}

	qh.HasClientID = false
	bare := EncodeQueryHit(qh)
	if len(bare) != len(enc)-16 {
		t.Fatalf("encoding without a client ID is %d bytes, want %d", len(bare), len(enc)-16)
	}
	if dec, _ := DecodeQueryHit(bare); dec.HasClientID {
		t.Error("a QUERYHIT with no trailer decoded a client ID")
	}

	// Fifteen trailing bytes are not a client ID.
	short := append(append([]byte(nil), bare...), make([]byte, 15)...)
	if dec, err := DecodeQueryHit(short); err != nil || dec.HasClientID {
		t.Errorf("15-byte trailer: has=%v err=%v, want no client ID and no error", dec.HasClientID, err)
	}
}

// TestPushFetchFromFirewalledSource is the two-engine pair. The source
// holds the file and cannot be reached directly, so the transfer succeeds
// only over the dial-back that the PUSH triggers.
func TestPushFetchFromFirewalledSource(t *testing.T) {
	payload := testContent(3000)
	const index = 5

	src, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(len(payload)), Name: "push.bin", Data: payload},
		},
	})
	req, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     time.Second,
		Peers:             []string{src.Addr().String()},
	})
	waitForPeers(t, req, 1)
	time.Sleep(150 * time.Millisecond)

	hits, err := req.Search("push")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	qh, hit := findHit(t, hits, "push.bin")
	if !qh.HasClientID || qh.ClientID != src.servent {
		t.Fatalf("hit carries servent %x (has=%v), want the source's %x",
			qh.ClientID, qh.HasClientID, src.servent)
	}

	// The firewalled case: a direct GET to the source is refused. The
	// source's listener speaks only the Gnutella handshake, so the GET
	// is not a CONNECT and nothing is served.
	directDir := t.TempDir()
	if _, err := NewDownloader(qh, hit).Fetch(context.Background(), directDir); err == nil {
		t.Fatal("direct GET to the firewalled source succeeded; the test has no firewall")
	}
	if _, err := os.Stat(filepath.Join(directDir, "push.bin")); !os.IsNotExist(err) {
		t.Errorf("a refused direct GET left a file behind: stat err = %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	dir := t.TempDir()
	res, err := req.PushFetch(ctx, qh, hit, dir)
	if err != nil {
		t.Fatalf("PushFetch: %v", err)
	}
	if res.Bytes != int64(len(payload)) || res.Offset != 0 || res.Complete {
		t.Errorf("result = %+v, want %d bytes from offset 0", res, len(payload))
	}
	if want := filepath.Join(dir, "push.bin"); res.Path != want {
		t.Errorf("result path = %q, want %q", res.Path, want)
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read result: %v", err)
	}
	if !bytes.Equal(onDisk, payload) {
		t.Errorf("file on disk (%d bytes) does not match the catalogue payload (%d bytes)",
			len(onDisk), len(payload))
	}
}

// TestPushRefusesSizeMismatch shows the pushed transfer applies the direct
// download's size rule. The source advertises a size larger than the bytes
// it serves, so the requester must refuse and write nothing.
func TestPushRefusesSizeMismatch(t *testing.T) {
	payload := testContent(1000)
	const index = 9

	src, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: index, Size: uint32(len(payload) + 7), Name: "lying.bin", Data: payload},
		},
	})
	req, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     time.Second,
		Peers:             []string{src.Addr().String()},
	})
	waitForPeers(t, req, 1)
	time.Sleep(150 * time.Millisecond)

	hits, err := req.Search("lying")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	qh, hit := findHit(t, hits, "lying.bin")

	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	dir := t.TempDir()
	_, err = req.PushFetch(ctx, qh, hit, dir)
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("PushFetch error = %v, want ErrSizeMismatch", err)
	}
	// A refused transfer is truncated back to the offset it started at,
	// which for a fresh download is zero: no bytes may survive it.
	fi, statErr := os.Stat(filepath.Join(dir, "lying.bin"))
	if statErr != nil && !os.IsNotExist(statErr) {
		t.Fatalf("stat: %v", statErr)
	}
	if statErr == nil && fi.Size() != 0 {
		t.Errorf("a refused push left %d bytes on disk, want 0", fi.Size())
	}
}

// TestPushWithMismatchedServentIDIsIgnored sends a PUSH to a source under
// the wrong servent ID and asserts no dial-back happens. A positive control
// follows on the same connection: the same PUSH with the right ID does
// dial back. Without that control the negative could pass just because
// the dial-back path is broken.
func TestPushWithMismatchedServentIDIsIgnored(t *testing.T) {
	src, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue: []FileEntry{
			{Index: 5, Size: 4, Name: "x.bin", Data: []byte("data")},
		},
	})
	_, conn := dialEngine(t, src.Addr().String())

	// A listener standing in for the requester: any dial-back lands here.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	port := uint16(ln.Addr().(*net.TCPAddr).Port)
	pushTo := func(id [idSize]byte) {
		t.Helper()
		payload := EncodePush(Push{
			ServentID: id,
			IP:        [4]byte{127, 0, 0, 1},
			Port:      port,
			FileIndex: 5,
		})
		hdr := Header{ID: newDescriptorID(), Type: MsgPush, TTL: 7, Length: uint32(len(payload))}
		sendMsg(t, conn, hdr, payload)
	}

	// Negative: a servent ID that is not the source's.
	pushTo(testID(0x77))
	tl := ln.(*net.TCPListener)
	_ = tl.SetDeadline(time.Now().Add(500 * time.Millisecond))
	if c, err := ln.Accept(); err == nil {
		_ = c.Close()
		t.Fatal("a PUSH for another servent made the source dial back")
	} else {
		assertTimeout(t, err)
	}

	// Positive control: the same PUSH with the source's own ID dials back
	// and announces the file with a GIV line.
	pushTo(src.servent)
	_ = tl.SetDeadline(time.Now().Add(testDeadline))
	c, err := ln.Accept()
	if err != nil {
		t.Fatalf("positive control: no dial-back for the source's own servent ID: %v", err)
	}
	defer c.Close()
	_ = c.SetReadDeadline(time.Now().Add(testDeadline))
	line, err := readGIVLine(bufio.NewReader(c))
	if err != nil {
		t.Fatalf("positive control: reading GIV: %v", err)
	}
	if !strings.HasPrefix(line, "GIV 5:") {
		t.Errorf("GIV line = %q, want a GIV for index 5", line)
	}
}
