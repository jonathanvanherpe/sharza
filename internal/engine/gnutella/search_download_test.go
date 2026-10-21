// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// End-to-end search-and-download: engine B fuses Engine.Search and
// Downloader.Fetch through Engine.SearchAndDownload over real loopback
// TCP. The answering servent is a scripted 0.6 client whose QUERYHIT
// names a loopback HTTP listener serving the payload, so both legs
// (QUERY/QUERYHIT and the download GET) are real sockets on 127.0.0.1
// and nothing here reaches the network.
//
// Engine A is the second engine: it runs with Catalogue set and answers
// every QUERY, but its catalogue is deliberately empty, so its QUERYHIT
// carries no file hits and the hit selection must skip it. A non-empty
// catalogue would advertise A's own Gnutella listener as the download
// source (handleQuery pins the QUERYHIT's port to it, and no engine
// serves HTTP there), which would make the winner of the selection
// depend on which answer arrived first. The empty catalogue keeps the
// skip deterministic whichever answer lands first, and still exercises
// a real engine answering a real QUERY on the wire.

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"testing"
	"time"
)

// serventQueryHit builds the QUERYHIT a scripted servent answers with:
// a single file hit, advertised at srv's real TCP address, which is
// where the download GET will go.
func serventQueryHit(t *testing.T, srv *httptest.Server, index, size uint32, name string) QueryHit {
	t.Helper()
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	ip := ta.IP.To4()
	if ip == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}
	var qh QueryHit
	copy(qh.IP[:], ip)
	qh.Port = uint16(ta.Port)
	qh.Hits = []FileHit{{FileIndex: index, FileSize: size, FileName: name}}
	return qh
}

// answerQueriesAs connects to addr like a Gnutella 0.6 client and
// answers every QUERY that arrives with qh, under the QUERY's own
// descriptor ID. The reply's IP and Port are left exactly as the caller
// set them: a downloadable servent names its HTTP listener, an unusable
// one names nothing worth dialing.
func answerQueriesAs(t *testing.T, addr string, qh QueryHit) {
	t.Helper()
	r, conn := dialEngine(t, addr)
	go func() {
		for {
			hdr, _, err := readMsgErr(r)
			if err != nil {
				return // connection closed at test teardown
			}
			if hdr.Type != MsgQuery {
				continue
			}
			hp := EncodeQueryHit(qh)
			b := Header{ID: hdr.ID, Type: MsgQueryHit, TTL: 6, Hops: 0, Length: uint32(len(hp))}.AppendTo(nil)
			b = append(b, hp...)
			if _, err := conn.Write(b); err != nil {
				return
			}
		}
	}()
}

// startPayloadServent serves exactly one file over real HTTP on
// loopback, asserting the download request path on the way.
func startPayloadServent(t *testing.T, index uint32, content []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/gnutella/"+strconv.FormatUint(uint64(index), 10) {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(len(content)))
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestSearchAndDownloadOverLoopback is the composed P1 exchange: engine
// B searches, the scripted servent answers with a QUERYHIT naming its
// HTTP payload listener, and SearchAndDownload fetches the file the hit
// advertised. Engine A is the second engine on the wire, answering with
// a QUERYHIT that selection must skip (no file hits).
func TestSearchAndDownloadOverLoopback(t *testing.T) {
	const (
		fileName = "album-track.mp3"
		index    = 7
	)
	content := testContent(2048)

	// Engine A: real engine, catalogue field set, answers QUERYs. Its
	// catalogue is empty so its answer carries no file hits; see the
	// file comment for why a populated catalogue would make the
	// selection racy rather than harder.
	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue:         []FileEntry{},
	})
	defer cancelA()

	srv := startPayloadServent(t, index, content)
	servent := serventQueryHit(t, srv, index, uint32(len(content)), fileName)

	var sawHit atomic.Bool
	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engA.Addr().String()},
		OnQueryHit: func(_ net.Addr, _ [idSize]byte, qh QueryHit) {
			if len(qh.Hits) > 0 && qh.Hits[0].FileName == fileName {
				sawHit.Store(true)
			}
		},
	})
	defer cancelB()

	answerQueriesAs(t, engB.Addr().String(), servent)
	// The dial loop and the accept path connect asynchronously;
	// searching before both handshakes finished would write QUERY
	// bytes into a handshake.
	waitForPeers(t, engB, 2)
	time.Sleep(150 * time.Millisecond)

	dir := t.TempDir()
	job, err := engB.SearchAndDownload(context.Background(), Query{Search: "album"}, dir)
	if err != nil {
		t.Fatalf("SearchAndDownload: %v", err)
	}

	// The search leg: the job carries the servent's hit, and the
	// OnQueryHit surface saw the same QUERYHIT arrive over the wire.
	if job.Hit == nil {
		t.Fatal("job.Hit is nil, want the QUERYHIT that answered the search")
	}
	if job.Hit.Port != servent.Port || job.Hit.IP != servent.IP {
		t.Errorf("job hit source = %v:%d, want %v:%d (engine A's skipped answer must not win)",
			job.Hit.IP, job.Hit.Port, servent.IP, servent.Port)
	}
	if len(job.Hit.Hits) != 1 || job.Hit.Hits[0].FileName != fileName {
		t.Errorf("job hit files = %+v, want the single %q hit", job.Hit.Hits, fileName)
	}
	if !sawHit.Load() {
		t.Error("OnQueryHit never saw the servent's QUERYHIT; the job's hit was not delivered on the wire")
	}

	// The download leg: the bytes on disk are the servent's payload,
	// and the file's size is the size the QUERYHIT declared.
	if want := filepath.Join(dir, fileName); job.Path != want {
		t.Errorf("job path = %q, want %q", job.Path, want)
	}
	onDisk, err := os.ReadFile(job.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("file on disk (%d bytes) does not match the servent's payload (%d bytes)",
			len(onDisk), len(content))
	}
	fi, err := os.Stat(job.Path)
	if err != nil {
		t.Fatalf("stat downloaded file: %v", err)
	}
	if want := int64(len(content)); fi.Size() != want {
		t.Errorf("file size = %d, want %d (the QUERYHIT's declared size)", fi.Size(), want)
	}
	if declared := int64(job.Hit.Hits[0].FileSize); fi.Size() != declared {
		t.Errorf("file size = %d, want the declared %d", fi.Size(), declared)
	}
	if job.Size != fi.Size() {
		t.Errorf("job size = %d, want %d", job.Size, fi.Size())
	}
}

// TestSearchAndDownloadRefusesMismatchedLength pins the integrity check
// on the fused path: the servent answers the QUERY honestly but serves
// a body shorter than it declared. The transfer must be refused with
// ErrSizeMismatch and the destination left at the offset it started
// from, so a later resume finds exactly the partial it would have found
// without this call.
func TestSearchAndDownloadRefusesMismatchedLength(t *testing.T) {
	const (
		fileName = "liar.bin"
		index    = 9
		size     = 512
	)
	content := testContent(size)

	engA, cancelA := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		Catalogue:         []FileEntry{},
	})
	defer cancelA()

	// Declares the full size, then serves one byte less, chunked so
	// net/http cannot paper over the lie with a Content-Length.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Gnutella-Content-Length", strconv.Itoa(size))
		writeChunked(w, content[:size-1])
	}))
	t.Cleanup(srv.Close)
	servent := serventQueryHit(t, srv, index, size, fileName)

	engB, cancelB := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     1 * time.Second,
		Peers:             []string{engA.Addr().String()},
	})
	defer cancelB()

	answerQueriesAs(t, engB.Addr().String(), servent)
	waitForPeers(t, engB, 2)
	time.Sleep(150 * time.Millisecond)

	dir := t.TempDir()
	job, err := engB.SearchAndDownload(context.Background(), Query{Search: "liar"}, dir)
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("SearchAndDownload error = %v, want ErrSizeMismatch (job = %+v)", err, job)
	}
	if job != nil {
		t.Errorf("SearchAndDownload returned a job (%+v) alongside a refused transfer", job)
	}
	// The destination started at offset 0 and must be left there: the
	// refused body may have been created, but not kept.
	dest := filepath.Join(dir, fileName)
	fi, err := os.Stat(dest)
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat destination: %v", err)
		}
		return // never created; starting offset untouched
	}
	if fi.Size() != 0 {
		t.Errorf("destination holds %d bytes after a refused transfer, want it left at offset 0", fi.Size())
	}
}

// TestSearchAndDownloadNoSuitableHit pins ErrNoSuitableHit and the
// "writes nothing" contract: a peer that never answers, a peer whose
// QUERYHIT names no dialable source, and a peer whose QUERYHIT carries
// no files are each unusable, and an unusable answer must not be
// fetched, guessed at, or written around.
func TestSearchAndDownloadNoSuitableHit(t *testing.T) {
	// silent: completes the handshake and then never answers.
	silent := func(t *testing.T, engB *Engine, _ QueryHit) {
		r, _ := dialEngine(t, engB.Addr().String())
		_ = r // the QUERY arrives and is never answered
	}
	// noPort: answers with a QUERYHIT whose source port is zero, which
	// no client can dial.
	noPort := func(t *testing.T, engB *Engine, qh QueryHit) {
		qh.Port = 0
		answerQueriesAs(t, engB.Addr().String(), qh)
	}
	// noFiles: answers with a QUERYHIT that advertises no files at
	// all.
	noFiles := func(t *testing.T, engB *Engine, qh QueryHit) {
		qh.Hits = nil
		answerQueriesAs(t, engB.Addr().String(), qh)
	}

	for _, tc := range []struct {
		name string
		wire func(t *testing.T, engB *Engine, qh QueryHit)
	}{
		{"no answer", silent},
		{"hit with no dialable address", noPort},
		{"hit with no files", noFiles},
	} {
		t.Run(tc.name, func(t *testing.T) {
			engA, cancelA := startEngine(t, Options{
				KeepAliveInterval: time.Hour,
				IdleTimeout:       10 * time.Second,
				Catalogue:         []FileEntry{},
			})
			defer cancelA()

			srv := startPayloadServent(t, 1, testContent(64))
			servent := serventQueryHit(t, srv, 1, 64, "never-fetched.bin")

			engB, cancelB := startEngine(t, Options{
				KeepAliveInterval: time.Hour,
				IdleTimeout:       10 * time.Second,
				SearchTimeout:     200 * time.Millisecond,
				Peers:             []string{engA.Addr().String()},
			})
			defer cancelB()

			tc.wire(t, engB, servent)
			waitForPeers(t, engB, 2)
			time.Sleep(150 * time.Millisecond)

			dir := t.TempDir()
			job, err := engB.SearchAndDownload(context.Background(), Query{Search: "absent"}, dir)
			if !errors.Is(err, ErrNoSuitableHit) {
				t.Fatalf("SearchAndDownload error = %v, want ErrNoSuitableHit (job = %+v)", err, job)
			}
			if job != nil {
				t.Errorf("SearchAndDownload returned a job (%+v) with no usable hit", job)
			}
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatalf("read destination dir: %v", err)
			}
			if len(entries) != 0 {
				t.Errorf("destination holds %d entries, want none: an unusable hit must write nothing", len(entries))
			}
		})
	}
}
