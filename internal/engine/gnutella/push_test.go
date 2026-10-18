// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Requester-side PUSH tests (spec §2.2.8) in two layers: the codec and
// the push registry are unit-tested directly, and the wire behaviour is
// asserted over real TCP with a scripted peer that answers a QUERY with
// a QUERYHIT advertising a source that cannot be dialled. Nothing here
// reaches the network: the unreachable source is either the reserved
// TEST-NET-1 address or a transport that refuses every dial.

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"
)

// TestEncodeDecodePushRoundTrip pins the codec, including the byte
// layout itself: a big-endian file index would survive a matching pair
// of encode/decode mutations while being wrong on the wire, so the raw
// bytes are asserted before the round trip.
func TestEncodeDecodePushRoundTrip(t *testing.T) {
	p := Push{
		Target:    testID(0x5A),
		FileIndex: 0x01020304,
		IP:        [4]byte{192, 0, 2, 9},
		Port:      0x1234,
	}
	b := EncodePush(p)
	if len(b) != pushPayloadSize {
		t.Fatalf("EncodePush produced %d bytes, want %d", len(b), pushPayloadSize)
	}
	if !bytes.Equal(b[0:idSize], p.Target[:]) {
		t.Errorf("target field = %x, want %x", b[0:idSize], p.Target)
	}
	if got := binary.LittleEndian.Uint32(b[16:20]); got != 0x01020304 {
		t.Errorf("file index little-endian = %#x, want 0x01020304", got)
	}
	if !bytes.Equal(b[20:24], p.IP[:]) {
		t.Errorf("requester ip = %v, want %v", b[20:24], p.IP)
	}
	if got := binary.LittleEndian.Uint16(b[24:26]); got != 0x1234 {
		t.Errorf("requester port little-endian = %#x, want 0x1234", got)
	}
	dec, err := DecodePush(b)
	if err != nil {
		t.Fatalf("DecodePush: %v", err)
	}
	if dec != p {
		t.Errorf("round trip: got %+v, want %+v", dec, p)
	}
}

// TestDecodePushRejectsShortPayload covers the error boundary: every
// payload shorter than the fixed fields is refused, an exact one
// decodes, and the optional trailing GGEP of §2.2.8 is skipped rather
// than rejected.
func TestDecodePushRejectsShortPayload(t *testing.T) {
	for n := 0; n < pushPayloadSize; n++ {
		if _, err := DecodePush(make([]byte, n)); !errors.Is(err, ErrPushBadFormat) {
			t.Errorf("DecodePush(%d bytes) err = %v, want ErrPushBadFormat", n, err)
		}
	}
	if _, err := DecodePush(make([]byte, pushPayloadSize)); err != nil {
		t.Errorf("DecodePush(%d bytes) err = %v, want nil", pushPayloadSize, err)
	}
	long := append(make([]byte, pushPayloadSize), 0x67, 0x65, 0x70, 0x31, 0x00, 0x01, 0x2f)
	if _, err := DecodePush(long); err != nil {
		t.Errorf("DecodePush with trailing GGEP: %v, want nil", err)
	}
}

// TestPushRegistryReportsMissingPath covers every way a PUSH can find
// no live connection to go down: a registry that was never wired, a hit
// with no connection recorded, and an address nothing is registered
// under. All three must surface ErrNoPushPath rather than panic or
// silently succeed.
func TestPushRegistryReportsMissingPath(t *testing.T) {
	id := testID(0x11)
	someAddr := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6346}

	var nilReg *pushRegistry
	if err := nilReg.send(someAddr, id, 1); !errors.Is(err, ErrNoPushPath) {
		t.Errorf("nil registry: err = %v, want ErrNoPushPath", err)
	}

	r := newPushRegistry()
	if err := r.send(nil, id, 1); !errors.Is(err, ErrNoPushPath) {
		t.Errorf("nil via: err = %v, want ErrNoPushPath", err)
	}
	if err := r.send(someAddr, id, 1); !errors.Is(err, ErrNoPushPath) {
		t.Errorf("unregistered via: err = %v, want ErrNoPushPath", err)
	}
}

// TestPushRegistryNilSafe: an engine that never wired a registry (a
// caller that built Options by hand) must tolerate add/remove without
// panicking, not only send.
func TestPushRegistryNilSafe(t *testing.T) {
	var r *pushRegistry
	r.add(&peer{})
	r.remove(&peer{})
}

// TestPushRegistryRemoveKeepsReconnectedPeer pins the identity check in
// remove: two connections whose addresses collide is exactly what a
// peer reconnecting from the same port looks like to the registry, and
// the old connection's deferred remove must not evict the new
// registration. net.Pipe addresses both render as "pipe", which gives
// that collision deterministically.
func TestPushRegistryRemoveKeepsReconnectedPeer(t *testing.T) {
	r := newPushRegistry()
	c1, d1 := net.Pipe()
	c2, d2 := net.Pipe()
	t.Cleanup(func() {
		_ = c1.Close()
		_ = d1.Close()
		_ = c2.Close()
		_ = d2.Close()
	})
	old := &peer{conn: c1}
	fresh := &peer{conn: c2}
	r.add(old)
	r.add(fresh)  // same key: the reconnected peer now owns it
	r.remove(old) // the old connection's defer runs after this

	r.mu.Lock()
	got := r.byAddr[c1.RemoteAddr().String()]
	r.mu.Unlock()
	if got != fresh {
		t.Fatalf("registry holds %p after the old connection was removed, want the reconnected peer %p", got, fresh)
	}
	r.remove(fresh)
	r.mu.Lock()
	n := len(r.byAddr)
	r.mu.Unlock()
	if n != 0 {
		t.Errorf("registry has %d entries after removing both, want 0", n)
	}
}

// TestEngineDownloaderPushWiring pins when Engine.Downloader attaches a
// RequestPush closure at all: a hit with a live connection and a
// servent identifier gets one (and calling it with the connection since
// gone reports the missing path instead of panicking), while a hit
// missing either half of the route gets none.
func TestEngineDownloaderPushWiring(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})
	via := &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 6346}
	hit := FileHit{FileIndex: 5, FileSize: 10, FileName: "x.bin"}

	wired := eng.Downloader(
		QueryHit{IP: [4]byte{192, 0, 2, 1}, Port: 6346, Via: via, ClientID: testID(0x21)},
		hit,
	)
	if wired.RequestPush == nil {
		t.Fatal("Downloader gave no RequestPush closure for a hit with Via and ClientID")
	}
	if err := wired.RequestPush(); !errors.Is(err, ErrNoPushPath) {
		t.Errorf("RequestPush with a dead path: err = %v, want ErrNoPushPath", err)
	}

	noID := eng.Downloader(
		QueryHit{IP: [4]byte{192, 0, 2, 1}, Port: 6346, Via: via},
		hit,
	)
	if noID.RequestPush != nil {
		t.Error("Downloader wired a push for a hit with no ClientID (nowhere to address it)")
	}

	noVia := eng.Downloader(
		QueryHit{IP: [4]byte{192, 0, 2, 1}, Port: 6346, ClientID: testID(0x21)},
		hit,
	)
	if noVia.RequestPush != nil {
		t.Error("Downloader wired a push for a hit with no Via (no connection to send it down)")
	}
}

// waitForPushPath waits until the engine's push registry holds at least
// want live connections. Registration happens only after a handshake
// completes, so its return also proves the connection is past the
// handshake and safe to drive; unlike waitForPeers it needs no sleep
// after it.
func waitForPushPath(t *testing.T, eng *Engine, want int) {
	t.Helper()
	deadline := time.Now().Add(testDeadline)
	for {
		eng.pushes.mu.Lock()
		n := len(eng.pushes.byAddr)
		eng.pushes.mu.Unlock()
		if n >= want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("push registry has %d live connections, want at least %d", n, want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// answerQueryWithHit runs the scripted half of a search over real TCP:
// it lets the engine send its QUERY, replies with a QUERYHIT echoing
// the QUERY's descriptor id whose source is srcIP:srcPort and whose
// trailing servent identifier is serventID, then returns the search's
// single hit together with that echoed descriptor id. The Via and
// ClientID checks run on every test that uses it, because both are the
// precondition for any PUSH at all; the id comes back so a test can
// prove a later PUSH did not reuse it.
func answerQueryWithHit(t *testing.T, eng *Engine, r *bufio.Reader, conn net.Conn, srcIP [4]byte, srcPort uint16, serventID [idSize]byte, size uint32) (QueryHit, [idSize]byte) {
	t.Helper()
	type result struct {
		hits []QueryHit
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		hits, err := eng.Search("firewalled")
		resCh <- result{hits, err}
	}()

	qhdr, _ := readMsg(t, r)
	if qhdr.Type != MsgQuery {
		t.Fatalf("first message = %s, want QUERY", typeName(qhdr.Type))
	}

	hit := FileHit{FileIndex: 42, FileSize: size, FileName: "firewalled.bin"}
	reply := EncodeQueryHit(QueryHit{
		HitCount: 1,
		IP:       srcIP,
		Port:     srcPort,
		Hits:     []FileHit{hit},
		ClientID: serventID,
	})
	sendMsg(t, conn, Header{
		ID:     qhdr.ID,
		Type:   MsgQueryHit,
		TTL:    7,
		Hops:   0,
		Length: uint32(len(reply)),
	}, reply)

	res := <-resCh
	if res.err != nil {
		t.Fatalf("Search: %v", res.err)
	}
	if len(res.hits) != 1 {
		t.Fatalf("Search returned %d hits, want 1", len(res.hits))
	}
	got := res.hits[0]
	if len(got.Hits) != 1 || got.Hits[0].FileIndex != 42 {
		t.Fatalf("hit set = %+v, want exactly the file index 42 that was replied", got.Hits)
	}
	if got.ClientID != serventID {
		t.Errorf("hit ClientID = %x, want the trailing servent id %x", got.ClientID, serventID)
	}
	if got.Via == nil {
		t.Fatal("hit Via is nil, want the connection the QUERYHIT arrived on")
	}
	if want := conn.LocalAddr().String(); got.Via.String() != want {
		t.Errorf("hit Via = %s, want %s (this connection)", got.Via, want)
	}
	return got, qhdr.ID
}

// readNoPush asserts that nothing more arrives on the scripted
// connection within a short window: after a fetch that must not
// produce a PUSH, silence on the wire is the evidence. The deadline is
// per-direction and only disturbs this connection's read side; the
// test ends right after.
func readNoPush(t *testing.T, r *bufio.Reader, conn net.Conn) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(250 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, _, err := readMsgErr(r)
	assertTimeout(t, err)
}

// TestUnreachableSourceGetsPushedDownHitConnection is the end-to-end
// requester-side PUSH over real TCP: the scripted peer answers with a
// QUERYHIT whose source is TEST-NET-1 (reserved for documentation,
// routable nowhere) and a known trailing servent identifier; the
// download of that source fails at the transport level; and the PUSH
// must arrive on the very connection the hit came in on, addressed to
// that identifier, carrying the hit's file index and our own listen
// address.
func TestUnreachableSourceGetsPushedDownHitConnection(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     500 * time.Millisecond,
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPushPath(t, eng, 1)

	serventID := testID(0xA7)
	got, queryID := answerQueryWithHit(t, eng, r, conn,
		[4]byte{192, 0, 2, 1}, 6346, serventID, 4096)

	// The transport refuses every dial, which is what a source behind a
	// firewall looks like from here: the GET never goes on the wire.
	d := eng.Downloader(got, got.Hits[0])
	if d.RequestPush == nil {
		t.Fatal("Downloader has no RequestPush closure for a hit with Via and ClientID")
	}
	d.Client = &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return nil, fmt.Errorf("dial %s: connection refused", addr)
		},
	}}
	if _, err := d.Fetch(context.Background(), t.TempDir()); err == nil {
		t.Fatal("Fetch succeeded against an unreachable source, want an error")
	}

	phdr, ppayload := readMsg(t, r)
	if phdr.Type != MsgPush {
		t.Fatalf("message after failed fetch = %s (%d bytes), want PUSH (0x40)", typeName(phdr.Type), len(ppayload))
	}
	if phdr.ID == queryID {
		t.Error("PUSH reused the QUERYHIT's descriptor id, want a fresh one (§2.2.8)")
	}
	if phdr.TTL < 1 || phdr.TTL > 7 {
		t.Errorf("PUSH TTL = %d, want 1..7", phdr.TTL)
	}
	if phdr.Hops != 0 {
		t.Errorf("PUSH hops = %d, want 0 on a message we originate", phdr.Hops)
	}
	if len(ppayload) != pushPayloadSize {
		t.Fatalf("PUSH payload = %d bytes, want %d", len(ppayload), pushPayloadSize)
	}
	// Raw wire assertions first: the target is the hit's servent id and
	// the file index is little-endian, pinned here so a matching
	// encode/decode mutation cannot hide behind the round trip.
	if !bytes.Equal(ppayload[0:idSize], serventID[:]) {
		t.Errorf("PUSH target = %x, want the servent id %x", ppayload[0:idSize], serventID)
	}
	if idx := binary.LittleEndian.Uint32(ppayload[16:20]); idx != 42 {
		t.Errorf("PUSH file index = %d (LE), want 42", idx)
	}
	push, err := DecodePush(ppayload)
	if err != nil {
		t.Fatalf("DecodePush: %v", err)
	}
	ta, ok := eng.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("engine address is %T, want *net.TCPAddr", eng.Addr())
	}
	if push.IP != [4]byte{127, 0, 0, 1} {
		t.Errorf("requester IP = %v, want 127.0.0.1 as this engine is bound to it", net.IP(push.IP[:]))
	}
	if push.Port != uint16(ta.Port) {
		t.Errorf("requester port = %d, want the engine's listen port %d", push.Port, ta.Port)
	}
}

// TestSuccessfulDownloadSendsNoPush pins the other half: the push
// request exists for a dead source, not for a transfer that worked.
// The downloader here is fully wired (the closure is asserted to be
// present, so the silence that follows proves the guard, not a missing
// wiring), the source serves over real HTTP, and Fetch completes; after
// that nothing more may arrive on the scripted connection.
func TestSuccessfulDownloadSendsNoPush(t *testing.T) {
	content := testContent(2048)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(content)))
		_, _ = w.Write(content)
	}))
	t.Cleanup(srv.Close)
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	srcIP4 := ta.IP.To4()
	if srcIP4 == nil {
		t.Fatalf("listener address %s is not IPv4", ta)
	}

	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     500 * time.Millisecond,
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPushPath(t, eng, 1)

	serventID := testID(0xB3)
	got, _ := answerQueryWithHit(t, eng, r, conn,
		[4]byte{srcIP4[0], srcIP4[1], srcIP4[2], srcIP4[3]},
		uint16(ta.Port), serventID, uint32(len(content)))

	d := eng.Downloader(got, got.Hits[0])
	if d.RequestPush == nil {
		t.Fatal("Downloader has no RequestPush closure; the silence below would prove nothing")
	}
	if _, err := d.Fetch(context.Background(), t.TempDir()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	readNoPush(t, r, conn)
}

// TestCancelledDownloadDoesNotPush pins the context guard: a caller
// that cancels the fetch made a decision, and the engine must not turn
// it into a PUSH on the wire, however unreachable the source is.
func TestCancelledDownloadDoesNotPush(t *testing.T) {
	eng, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     500 * time.Millisecond,
	})
	r, conn := dialEngine(t, eng.Addr().String())
	waitForPushPath(t, eng, 1)

	serventID := testID(0xC4)
	got, _ := answerQueryWithHit(t, eng, r, conn,
		[4]byte{192, 0, 2, 1}, 6346, serventID, 4096)

	d := eng.Downloader(got, got.Hits[0])
	if d.RequestPush == nil {
		t.Fatal("Downloader has no RequestPush closure; the silence below would prove nothing")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := d.Fetch(ctx, t.TempDir()); err == nil {
		t.Fatal("Fetch with a cancelled context succeeded, want an error")
	}
	readNoPush(t, r, conn)
}
