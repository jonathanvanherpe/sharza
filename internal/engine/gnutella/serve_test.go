// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Tests for the upload (serving) half of Gnutella 1. The engine's own
// Gnutella listener answers the download GET, so the client below is a
// plain net/http client speaking real HTTP over real TCP to that port;
// nothing here reaches the network.

import (
	"bytes"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// serveTestEngine boots an engine that shares the given files and
// returns it with the base URL of its Gnutella port. files maps a file
// index to (name, on-disk path); Size is the file's real length.
func serveTestEngine(t *testing.T, entries []FileEntry) (*Engine, string) {
	t.Helper()
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue:         entries,
	})
	return eng, "http://" + eng.Addr().String()
}

// serveTestClient is an HTTP client with no proxy, so a developer
// environment's HTTP_PROXY cannot intercept the loopback request.
func serveTestClient() *http.Client {
	return &http.Client{Transport: &http.Transport{}}
}

// writeTestFile writes b to dir/name and returns the path.
func writeTestFile(t *testing.T, dir, name string, b []byte) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, b, 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestServeDownloadFullFile is the core upload contract: GET
// /gnutella/<index> returns the file's exact bytes with the servent
// length headers set.
func TestServeDownloadFullFile(t *testing.T) {
	const (
		index = 7
		size  = 1200
	)
	content := testContent(size)
	path := writeTestFile(t, t.TempDir(), "song.mp3", content)
	_, base := serveTestEngine(t, []FileEntry{
		{Index: index, Size: size, Name: "song.mp3", Path: path},
	})

	resp, err := serveTestClient().Get(base + "/gnutella/" + strconv.Itoa(index))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	if got := resp.Header.Get("Content-Type"); got != "application/binary" {
		t.Errorf("Content-Type = %q, want application/binary", got)
	}
	if got := resp.Header.Get("X-Gnutella-Content-Length"); got != strconv.Itoa(size) {
		t.Errorf("X-Gnutella-Content-Length = %q, want %d", got, size)
	}
	if resp.ContentLength != size {
		t.Errorf("Content-Length = %d, want %d", resp.ContentLength, size)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Errorf("body (%d bytes) does not match the file (%d bytes)", len(body), len(content))
	}
}

// TestServeDownloadRange pins the resume half: a Range: bytes=<n>-
// request gets a 206 with the Content-Range the download client parses,
// and exactly the suffix bytes.
func TestServeDownloadRange(t *testing.T) {
	const (
		index  = 3
		size   = 1000
		offset = 400
	)
	content := testContent(size)
	path := writeTestFile(t, t.TempDir(), "part.bin", content)
	_, base := serveTestEngine(t, []FileEntry{
		{Index: index, Size: size, Name: "part.bin", Path: path},
	})

	req, err := http.NewRequest(http.MethodGet, base+"/gnutella/"+strconv.Itoa(index), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes="+strconv.Itoa(offset)+"-")
	resp, err := serveTestClient().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusPartialContent {
		t.Fatalf("status = %d, want 206", resp.StatusCode)
	}
	wantRange := "bytes " + strconv.Itoa(offset) + "-" + strconv.Itoa(size-1) + "/" + strconv.Itoa(size)
	if got := resp.Header.Get("Content-Range"); got != wantRange {
		t.Errorf("Content-Range = %q, want %q", got, wantRange)
	}
	// The servent length header is the whole file's length even for a
	// range, which is what the transfer checks the complete file against.
	if got := resp.Header.Get("X-Gnutella-Content-Length"); got != strconv.Itoa(size) {
		t.Errorf("X-Gnutella-Content-Length = %q, want the whole file %d", got, size)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, content[offset:]) {
		t.Errorf("range body (%d bytes) is not the requested suffix", len(body))
	}
}

// TestServeDownloadUnknownIndex pins 404 for an index the catalogue does
// not know, and for an entry that names no Path (advertised but not
// servable).
func TestServeDownloadUnknownIndex(t *testing.T) {
	dir := t.TempDir()
	content := testContent(64)
	path := writeTestFile(t, dir, "known.bin", content)
	_, base := serveTestEngine(t, []FileEntry{
		{Index: 1, Size: 64, Name: "known.bin", Path: path},
		{Index: 2, Size: 64, Name: "no-path.bin"}, // Path empty: not servable
	})

	for _, tc := range []struct {
		name  string
		index int
	}{
		{"unknown index", 999},
		{"entry without a path", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resp, err := serveTestClient().Get(base + "/gnutella/" + strconv.Itoa(tc.index))
			if err != nil {
				t.Fatalf("GET: %v", err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("status = %d, want 404", resp.StatusCode)
			}
		})
	}
}

// TestServeDownloadRangeOutOfBounds pins 416 for a range that starts
// past the end of the file.
func TestServeDownloadRangeOutOfBounds(t *testing.T) {
	const (
		index = 4
		size  = 100
	)
	content := testContent(size)
	path := writeTestFile(t, t.TempDir(), "small.bin", content)
	_, base := serveTestEngine(t, []FileEntry{
		{Index: index, Size: size, Name: "small.bin", Path: path},
	})

	req, err := http.NewRequest(http.MethodGet, base+"/gnutella/"+strconv.Itoa(index), nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Range", "bytes=1000-")
	resp, err := serveTestClient().Do(req)
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestedRangeNotSatisfiable {
		t.Errorf("status = %d, want 416", resp.StatusCode)
	}
}

// TestServeDownloadTrailingName pins the lenient route: a servent may
// append the file name after the index, and the index is still the one
// served.
func TestServeDownloadTrailingName(t *testing.T) {
	const (
		index = 6
		size  = 200
	)
	content := testContent(size)
	path := writeTestFile(t, t.TempDir(), "named.bin", content)
	_, base := serveTestEngine(t, []FileEntry{
		{Index: index, Size: size, Name: "named.bin", Path: path},
	})

	resp, err := serveTestClient().Get(base + "/gnutella/" + strconv.Itoa(index) + "/named.bin")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if !bytes.Equal(body, content) {
		t.Errorf("body does not match the file named by the trailing segment")
	}
}

// TestServeDownloadEmptyCatalogue pins the feature-flag invariant: with
// nothing in the catalogue, nothing is served.
func TestServeDownloadEmptyCatalogue(t *testing.T) {
	_, base := serveTestEngine(t, nil)
	resp, err := serveTestClient().Get(base + "/gnutella/1")
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Errorf("status = %d, want 404 with an empty catalogue", resp.StatusCode)
	}
}

// TestHandshakeAndDownloadShareThePort is the invariant the sniffing
// accept loop must not break: the Gnutella port answers a 0.6 handshake
// and an HTTP download GET, in either order, without the sniff consuming
// a handshake byte.
func TestHandshakeAndDownloadShareThePort(t *testing.T) {
	const (
		index = 8
		size  = 256
	)
	content := testContent(size)
	path := writeTestFile(t, t.TempDir(), "shared.bin", content)
	eng, base := serveTestEngine(t, []FileEntry{
		{Index: index, Size: size, Name: "shared.bin", Path: path},
	})

	// HTTP first, then a handshake on a fresh connection.
	resp, err := serveTestClient().Get(base + "/gnutella/" + strconv.Itoa(index))
	if err != nil {
		t.Fatalf("GET: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || !bytes.Equal(body, content) {
		t.Fatalf("download before handshake failed: status %d, %d bytes", resp.StatusCode, len(body))
	}

	r, conn := dialEngine(t, eng.Addr().String())
	ping := Header{ID: testID(0x9A), Type: MsgPing, TTL: 5, Hops: 0}
	sendMsg(t, conn, ping, nil)
	hdr, _ := readMsg(t, r)
	if hdr.Type != MsgPong || hdr.ID != ping.ID || hdr.TTL != 4 {
		t.Fatalf("handshake/ Ping after HTTP = type %s id %x ttl %d, want pong ttl 4",
			typeName(hdr.Type), hdr.ID, hdr.TTL)
	}

	// And the reverse order: handshake is open, a second HTTP GET still
	// works on its own connection.
	resp2, err := serveTestClient().Get(base + "/gnutella/" + strconv.Itoa(index))
	if err != nil {
		t.Fatalf("GET after handshake: %v", err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || !bytes.Equal(body2, content) {
		t.Errorf("download after handshake failed: status %d, %d bytes", resp2.StatusCode, len(body2))
	}
}
