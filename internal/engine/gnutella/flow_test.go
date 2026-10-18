// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Exit-gate flow tests: the composed Search -> Downloader -> Fetch leg
// driven over one real TCP connection to a scripted ultrapeer, plus the
// failure paths that must refuse a bad hit or a short body.
//
// The scripted peer plays the server half of the 0.6 handshake (the
// engine is the dialer, exactly as a leaf joins the network): it reads
// the engine's CONNECT, asserts the Accept-Encoding: deflate offer the
// live gtk-gnutella ultrapeers require, accepts the offer by declaring
// Content-Encoding: deflate, and answers with a QUERYHIT on a
// zlib-compressed stream, so the compression negotiation and the
// inflate path are exercised end to end. The engine's own TX stays
// plain, so the scripted peer reads the QUERY uncompressed.
//
// Every observable is checked through flowCheck, which counts
// assertions in flowChecks; each test logs its own delta on the way
// out, so a passing run shows a non-zero assertion count per test even
// when it prints nothing else.

import (
	"bufio"
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// flowChecks counts every flow assertion made through flowCheck and
// flowAssert. Tests snapshot it on entry and log their delta on exit.
var flowChecks atomic.Int64

// flowCheck records one assertion for the test goroutine: ok must hold,
// otherwise the failure is reported with the given format.
func flowCheck(t *testing.T, ok bool, format string, args ...any) {
	t.Helper()
	flowChecks.Add(1)
	if !ok {
		t.Errorf(format, args...)
	}
}

// flowAssert is flowCheck for the scripted peer's goroutine, which must
// not touch t: a failed assertion becomes an error the peer hands back
// through its error channel, reported by the test's cleanup.
func flowAssert(ok bool, format string, args ...any) error {
	flowChecks.Add(1)
	if ok {
		return nil
	}
	return fmt.Errorf(format, args...)
}

// flowPeer is the scripted ultrapeer's listening address and its
// handshake-complete signal. ready is closed once the engine's 200
// confirmation has been read: the engine registers a dialed peer before
// its handshake runs, so a Search started after ready is guaranteed a
// finished peer and its QUERY cannot interleave with handshake bytes.
type flowPeer struct {
	addr  string
	ready chan struct{}
}

// flowAnswer builds the scripted peer's reply to one QUERY. It receives
// the QUERY's descriptor header and decoded body; the returned header
// supplies the response descriptor ID (echo it for a matching hit, or
// hand back a foreign one to exercise the drop path). The helper fills
// in Type, Length and a default TTL.
type flowAnswer func(query Header, q Query) (Header, QueryHit)

// startFlowUltrapeer binds a loopback listener and starts the scripted
// peer on it. Call it before startEngine: cleanups run LIFO, so the
// engine shuts down first, which hangs up the connection the peer is
// draining, and only then does the peer's own cleanup collect its
// result. The cleanup reports any protocol failure the peer recorded.
func startFlowUltrapeer(t *testing.T, answer flowAnswer) *flowPeer {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("scripted ultrapeer listen: %v", err)
	}
	fp := &flowPeer{addr: ln.Addr().String(), ready: make(chan struct{})}
	errCh := make(chan error, 1)
	go serveFlowUltrapeer(ln, fp, answer, errCh)
	t.Cleanup(func() {
		_ = ln.Close()
		select {
		case err := <-errCh:
			flowCheck(t, err == nil, "scripted ultrapeer: %v", err)
		case <-time.After(testDeadline):
			t.Error("scripted ultrapeer did not finish")
		}
	})
	return fp
}

// serveFlowUltrapeer runs one scripted peer connection: handshake as
// the server, read one QUERY, answer it through answer, send the
// QUERYHIT compressed with a single zlib context (Flush, not Close, so
// the engine sees a complete message on a stream that stays open), then
// drain the connection. The drain only ends when the engine hangs up,
// which its teardown does first; anything that goes wrong before that
// point is returned as an error for the cleanup to report.
func serveFlowUltrapeer(ln net.Listener, fp *flowPeer, answer flowAnswer, errCh chan<- error) {
	fail := func(err error) {
		select {
		case errCh <- err:
		default:
		}
	}
	conn, err := ln.Accept()
	if err != nil {
		// The listener closing without ever being dialled is the
		// teardown of a test that failed before the engine started,
		// not a protocol failure.
		if errors.Is(err, net.ErrClosed) {
			errCh <- nil
			return
		}
		fail(fmt.Errorf("accept: %w", err))
		return
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(testDeadline)); err != nil {
		fail(err)
		return
	}
	r := bufio.NewReader(conn)

	hs, err := ReadHandshake(r)
	if err != nil {
		fail(fmt.Errorf("read CONNECT: %w", err))
		return
	}
	if err := flowAssert(hs.Request && hs.Version == "0.6",
		"first block = %s, want CONNECT/0.6", hs.Status()); err != nil {
		fail(err)
		return
	}
	ae, hasAE := hs.Get("Accept-Encoding")
	if err := flowAssert(hasAE && strings.Contains(strings.ToLower(ae), "deflate"),
		"CONNECT Accept-Encoding = %q, want an offer including deflate", ae); err != nil {
		fail(err)
		return
	}
	if _, err := conn.Write(OKReply(
		Field{"Listen-IP", "127.0.0.1:6346"},
		Field{"User-Agent", "scripted-ultrapeer/0.1"},
		Field{"Content-Encoding", "deflate"},
	)); err != nil {
		fail(fmt.Errorf("write 200 OK: %w", err))
		return
	}
	conf, err := ReadHandshake(r)
	if err != nil {
		fail(fmt.Errorf("read confirmation: %w", err))
		return
	}
	if err := flowAssert(conf.IsOK(),
		"engine confirmation = %s, want 200 OK", conf.Status()); err != nil {
		fail(err)
		return
	}
	// Handshake complete: from here the engine's TX is binary only.
	close(fp.ready)

	hdr, payload, err := readMsgErr(r)
	if err != nil {
		fail(fmt.Errorf("read QUERY: %w", err))
		return
	}
	if err := flowAssert(hdr.Type == MsgQuery,
		"message = %s, want query", typeName(hdr.Type)); err != nil {
		fail(err)
		return
	}
	if err := flowAssert(hdr.ID[8] == guidNetworkID && hdr.ID[15] == guidReserved,
		"QUERY descriptor ID = %x, want the network/reserved byte layout", hdr.ID); err != nil {
		fail(err)
		return
	}
	q, err := DecodeQuery(payload)
	if err != nil {
		fail(fmt.Errorf("decode QUERY: %w", err))
		return
	}

	resHdr, qh := answer(hdr, q)
	hitPayload := EncodeQueryHit(qh)
	resHdr.Type = MsgQueryHit
	if resHdr.TTL == 0 {
		resHdr.TTL = 7
	}
	resHdr.Hops = 0
	resHdr.Length = uint32(len(hitPayload))
	msg := resHdr.AppendTo(nil)
	msg = append(msg, hitPayload...)

	var compressed bytes.Buffer
	zw := zlib.NewWriter(&compressed)
	if _, err := zw.Write(msg); err != nil {
		fail(fmt.Errorf("compress QUERYHIT: %w", err))
		return
	}
	if err := zw.Flush(); err != nil {
		fail(fmt.Errorf("flush QUERYHIT: %w", err))
		return
	}
	if _, err := conn.Write(compressed.Bytes()); err != nil {
		fail(fmt.Errorf("write QUERYHIT: %w", err))
		return
	}

	// The protocol work is done. Drain until the engine hangs up (its
	// teardown runs before this goroutine's cleanup collects the
	// result); read errors here are the shutdown, not a failure.
	_, _ = io.Copy(io.Discard, conn)
	errCh <- nil
}

// waitFlowPeer waits for the scripted peer to finish the handshake with
// the engine, so a Search below is sent to a peer that is registered,
// past its handshake, and ready to read a QUERY.
func waitFlowPeer(t *testing.T, fp *flowPeer) {
	t.Helper()
	select {
	case <-fp.ready:
	case <-time.After(testDeadline):
		t.Fatal("engine did not complete the 0.6 handshake with the scripted ultrapeer")
	}
}

// TestFlowSearchThenDownload composes the whole exit-gate leg: Search
// over the scripted ultrapeer returns the hit it answered with, and
// Downloader.Fetch pulls that hit's file from the servent the QUERYHIT
// advertises, byte for byte.
func TestFlowSearchThenDownload(t *testing.T) {
	before := flowChecks.Load()
	t.Cleanup(func() { t.Logf("flow assertions checked: %d", flowChecks.Load()-before) })

	const (
		searchTerm = "flow song"
		index      = 17
		size       = 4096
		fileName   = "flow-song.mp3"
	)
	content := testContent(size)

	// The servent the QUERYHIT will advertise. The request path and the
	// X-Gnutella-Content-Length header are captured here and asserted
	// after the transfer.
	var gotPath, gotXGCL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotXGCL = r.Header.Get("X-Gnutella-Content-Length")
		w.Header().Set("Content-Length", strconv.Itoa(size))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	qh, hit := hitFor(t, srv, index, size, fileName)

	// Capture the QUERY as the scripted peer saw it: the query channel
	// is the happens-before edge between the peer's goroutine and the
	// assertions below.
	queryCh := make(chan Query, 4)
	fp := startFlowUltrapeer(t, func(hdr Header, q Query) (Header, QueryHit) {
		select {
		case queryCh <- q:
		default:
		}
		return Header{ID: hdr.ID}, qh
	})

	eng, _ := startEngine(t, Options{
		Peers:             []string{fp.addr},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     400 * time.Millisecond,
	})
	waitFlowPeer(t, fp)

	hits, err := eng.Search(searchTerm)
	flowCheck(t, err == nil, "Search error = %v", err)
	flowCheck(t, len(hits) == 1, "Search returned %d hits, want 1", len(hits))
	if len(hits) != 1 {
		t.Fatalf("Search returned %d hits, want 1", len(hits))
	}
	got := hits[0]
	flowCheck(t, got.Port == qh.Port,
		"hit port = %d, want the servent's %d", got.Port, qh.Port)
	flowCheck(t, got.IP == qh.IP,
		"hit IP = %v, want the servent's %v", got.IP, qh.IP)
	flowCheck(t, len(got.Hits) == 1,
		"hit carries %d file entries, want 1", len(got.Hits))
	if len(got.Hits) == 1 {
		flowCheck(t, got.Hits[0] == hit,
			"file entry = %+v, want %+v", got.Hits[0], hit)
	}

	select {
	case q := <-queryCh:
		flowCheck(t, q.Search == searchTerm,
			"QUERY searched %q, want %q", q.Search, searchTerm)
	case <-time.After(testDeadline):
		t.Error("no QUERY reached the scripted ultrapeer")
	}

	d := eng.Downloader(got, hit)
	flowCheck(t, d != nil, "Downloader returned nil")
	if d == nil {
		return
	}
	flowCheck(t, d.QH.Port == qh.Port,
		"Downloader QH port = %d, want %d", d.QH.Port, qh.Port)
	flowCheck(t, d.Hit.FileIndex == hit.FileIndex,
		"Downloader hit index = %d, want %d", d.Hit.FileIndex, hit.FileIndex)

	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	res, err := d.Fetch(ctx, dir)
	flowCheck(t, err == nil, "Fetch error = %v", err)
	if err != nil {
		return
	}
	flowCheck(t, res.Bytes == size,
		"Fetch moved %d bytes, want %d", res.Bytes, size)
	flowCheck(t, res.Offset == 0 && !res.Resumed(),
		"Fetch offset = %d, want a whole-file transfer", res.Offset)
	wantPath := filepath.Join(dir, fileName)
	flowCheck(t, res.Path == wantPath,
		"Fetch path = %q, want %q", res.Path, wantPath)
	onDisk, err := os.ReadFile(res.Path)
	flowCheck(t, err == nil, "read back %s: %v", res.Path, err)
	if err == nil {
		flowCheck(t, int64(len(onDisk)) == size,
			"file on disk is %d bytes, want %d", len(onDisk), size)
		flowCheck(t, bytes.Equal(onDisk, content),
			"file on disk differs from the servent's content")
	}
	flowCheck(t, gotPath == fmt.Sprintf("/gnutella/%d", index),
		"servent saw path %q, want /gnutella/%d", gotPath, index)
	flowCheck(t, gotXGCL == strconv.Itoa(size),
		"servent saw X-Gnutella-Content-Length %q, want %d", gotXGCL, size)
}

// TestFlowForeignDescriptorIDYieldsNoHits answers the QUERY under a
// descriptor ID the engine never registered. The hit must still arrive
// (the OnQueryHit callback proves it did, and proves the compressed
// stream decoded), but Search must not attribute it: the registry
// matching on descriptor ID is what keeps another query's results out
// of this search.
func TestFlowForeignDescriptorIDYieldsNoHits(t *testing.T) {
	before := flowChecks.Load()
	t.Cleanup(func() { t.Logf("flow assertions checked: %d", flowChecks.Load()-before) })

	const (
		searchTerm = "flow foreign"
		wantName   = "foreign-hit.mp3"
	)
	foreignID := testID(0xEE)

	queryCh := make(chan Query, 4)
	fp := startFlowUltrapeer(t, func(_ Header, q Query) (Header, QueryHit) {
		select {
		case queryCh <- q:
		default:
		}
		return Header{ID: foreignID}, QueryHit{
			Port: 6346,
			IP:   [4]byte{127, 0, 0, 1},
			Hits: []FileHit{{FileIndex: 9, FileSize: 1234, FileName: wantName}},
		}
	})

	type arrival struct {
		id [idSize]byte
		qh QueryHit
	}
	arrived := make(chan arrival, 1)

	eng, _ := startEngine(t, Options{
		Peers:             []string{fp.addr},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     400 * time.Millisecond,
		OnQueryHit: func(_ net.Addr, id [idSize]byte, qh QueryHit) {
			select {
			case arrived <- arrival{id, qh}:
			default:
			}
		},
	})
	waitFlowPeer(t, fp)

	hits, err := eng.Search(searchTerm)
	flowCheck(t, err == nil, "Search error = %v", err)
	flowCheck(t, len(hits) == 0,
		"Search returned %d hits under a foreign descriptor ID, want 0", len(hits))

	select {
	case q := <-queryCh:
		flowCheck(t, q.Search == searchTerm,
			"QUERY searched %q, want %q", q.Search, searchTerm)
	case <-time.After(testDeadline):
		t.Error("no QUERY reached the scripted ultrapeer")
	}

	select {
	case a := <-arrived:
		flowCheck(t, a.id == foreignID,
			"OnQueryHit id = %x, want the foreign %x", a.id, foreignID)
		flowCheck(t, len(a.qh.Hits) == 1,
			"OnQueryHit carried %d file entries, want 1", len(a.qh.Hits))
		if len(a.qh.Hits) == 1 {
			flowCheck(t, a.qh.Hits[0].FileName == wantName,
				"OnQueryHit file name = %q, want %q", a.qh.Hits[0].FileName, wantName)
		}
	case <-time.After(testDeadline):
		t.Error("OnQueryHit never fired; the QUERYHIT did not arrive")
	}
}

// TestFlowShortBodyRefusedAndTruncated answers a full-size hit but the
// servent sends fewer bytes with no length header to catch it early.
// Fetch must refuse with ErrSizeMismatch and leave no partial bytes
// behind: a size mismatch is the only integrity check Gnutella 1
// offers, so accepting a short body would silently corrupt the file.
func TestFlowShortBodyRefusedAndTruncated(t *testing.T) {
	before := flowChecks.Load()
	t.Cleanup(func() { t.Logf("flow assertions checked: %d", flowChecks.Load()-before) })

	const (
		searchTerm = "flow short"
		index      = 23
		size       = 4096
		short      = 3000
		fileName   = "flow-short.mp3"
	)
	content := testContent(size)

	// No Content-Length and no X-Gnutella-Content-Length: the headers
	// that could catch the short body up front are absent, so the body
	// count after the copy is the only check left.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeChunked(w, content[:short])
	}))
	defer srv.Close()

	qh, hit := hitFor(t, srv, index, size, fileName)

	queryCh := make(chan Query, 4)
	fp := startFlowUltrapeer(t, func(hdr Header, q Query) (Header, QueryHit) {
		select {
		case queryCh <- q:
		default:
		}
		return Header{ID: hdr.ID}, qh
	})

	eng, _ := startEngine(t, Options{
		Peers:             []string{fp.addr},
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     400 * time.Millisecond,
	})
	waitFlowPeer(t, fp)

	hits, err := eng.Search(searchTerm)
	flowCheck(t, err == nil, "Search error = %v", err)
	flowCheck(t, len(hits) == 1, "Search returned %d hits, want 1", len(hits))
	if len(hits) != 1 {
		t.Fatalf("Search returned %d hits, want 1", len(hits))
	}

	select {
	case q := <-queryCh:
		flowCheck(t, q.Search == searchTerm,
			"QUERY searched %q, want %q", q.Search, searchTerm)
	case <-time.After(testDeadline):
		t.Error("no QUERY reached the scripted ultrapeer")
	}

	d := eng.Downloader(hits[0], hit)
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), testDeadline)
	defer cancel()
	res, err := d.Fetch(ctx, dir)
	flowCheck(t, errors.Is(err, ErrSizeMismatch),
		"Fetch error = %v, want ErrSizeMismatch", err)

	dest := filepath.Join(dir, fileName)
	fi, statErr := os.Stat(dest)
	flowCheck(t, statErr == nil,
		"destination %s missing after a refused transfer: %v", dest, statErr)
	if statErr == nil {
		flowCheck(t, fi.Size() == 0,
			"destination holds %d bytes after refusal, want 0", fi.Size())
	}
	if err == nil {
		flowCheck(t, res.Path == "",
			"Fetch accepted a %d-byte body for a %d-byte hit", short, size)
	}
}
