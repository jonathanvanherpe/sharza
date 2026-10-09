// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// GWebCache tests. Every server is an httptest loopback listener: no
// test reaches a live cache, because the real ones are not something a
// CI run may depend on. The bare-list and parameterised request shapes
// are the two forms the caches still alive in 2026 answer.

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// cacheTestServer serves body for whichever request shape fn accepts.
type cacheTest struct {
	mu        sync.Mutex
	bare      int
	param     int
	paramQrys []string // raw query strings of parameterised requests
}

func (c *cacheTest) record(r *http.Request) {
	q := r.URL.Query()
	c.mu.Lock()
	defer c.mu.Unlock()
	if q.Get("get") == "1" {
		c.param++
		c.paramQrys = append(c.paramQrys, r.URL.RawQuery)
		return
	}
	c.bare++
}

func (c *cacheTest) counts() (bare, param int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.bare, c.param
}

// TestFetchHostsBareList covers the older caches: the list arrives on a
// plain GET, and the parameterised request (which this cache does not
// understand) comes back empty. The bare response must win.
func TestFetchHostsBareList(t *testing.T) {
	const body = "H|64.12.34.56:6346|1700000000\n" +
		"U|http://example.org/gwebcache/gwebcache.php|1700000001\n" +
		"I|AccessPeriod|12\n" +
		"I|HostSharePercentage|100\n"

	var rec cacheTest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		if r.URL.Query().Get("get") == "1" {
			// This cache serves the bare list only.
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)

	res, err := FetchHosts(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchHosts: %v", err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("hosts = %v, want exactly [64.12.34.56:6346]", res.Hosts)
	}
	if res.Hosts[0].Addr != "64.12.34.56:6346" {
		t.Errorf("host addr = %q, want 64.12.34.56:6346", res.Hosts[0].Addr)
	}
	if res.Hosts[0].Seen != 1700000000 {
		t.Errorf("host seen = %d, want 1700000000", res.Hosts[0].Seen)
	}
	if len(res.URLs) != 1 || res.URLs[0] != "http://example.org/gwebcache/gwebcache.php" {
		t.Errorf("urls = %v, want the one U| line", res.URLs)
	}
	if len(res.Info) != 2 {
		t.Fatalf("info = %v, want the two I| lines", res.Info)
	}
	if res.Info[0] != (CacheInfo{Key: "AccessPeriod", Value: "12"}) {
		t.Errorf("info[0] = %+v, want AccessPeriod=12", res.Info[0])
	}
	if res.Info[1] != (CacheInfo{Key: "HostSharePercentage", Value: "100"}) {
		t.Errorf("info[1] = %+v, want HostSharePercentage=100", res.Info[1])
	}

	bare, param := rec.counts()
	if bare != 1 || param != len(cacheNets) {
		t.Errorf("requests: %d bare, %d parameterised; want one bare and one per cache net (%d)",
			bare, param, len(cacheNets))
	}
}

// TestFetchHostsParamForm covers the gweb3/4octets family: nothing comes
// back until the request carries get=1, client and a net the cache
// knows. One request is sent per cacheNets entry.
func TestFetchHostsParamForm(t *testing.T) {
	var rec cacheTest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec.record(r)
		q := r.URL.Query()
		if q.Get("get") == "1" && q.Get("client") != "" && q.Get("net") == "gnutella2" {
			fmt.Fprint(w, "H|8.8.4.4:6346|1700000000\n")
			return
		}
		// Bare GET: this cache refuses to answer.
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	res, err := FetchHosts(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchHosts: %v", err)
	}
	if len(res.Hosts) != 1 || res.Hosts[0].Addr != "8.8.4.4:6346" {
		t.Fatalf("hosts = %v, want [8.8.4.4:6346]", res.Hosts)
	}

	bare, param := rec.counts()
	if bare != 1 || param != len(cacheNets) {
		t.Errorf("requests: %d bare, %d parameterised; want one bare and one per cache net (%d)",
			bare, param, len(cacheNets))
	}
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.paramQrys) != len(cacheNets) {
		t.Fatalf("parameterised requests = %v, want one per cache net", rec.paramQrys)
	}
	var g2 string
	for _, q := range rec.paramQrys {
		if !strings.Contains(q, "get=1") {
			t.Errorf("parameterised query %q is missing get=1", q)
		}
		if !strings.Contains(q, "client=") || !strings.Contains(q, "+") {
			t.Errorf("parameterised query %q has no client=<ver>+<name> parameter", q)
		}
		if strings.Contains(q, "net=gnutella2") {
			g2 = q
		}
	}
	if g2 == "" {
		t.Fatalf("no parameterised request asked for net=gnutella2: %v", rec.paramQrys)
	}
}

// TestFetchHostsDropsMalformedAndFiltered is the host filter: broken
// host:port values, unspecified addresses and loopback addresses must
// never reach the dial loops. An unusable epoch keeps the host (with
// Seen 0); an unusable host drops the line.
func TestFetchHostsDropsMalformedAndFiltered(t *testing.T) {
	const body = "" +
		"H|1.2.3.4\n" + // no port
		"H|9.9.9.9:99999|1\n" + // port out of range
		"H|9.9.9.9:0|1\n" + // port 0 dials nothing
		"H|0.0.0.0:6346|1\n" + // unspecified IPv4
		"H|[::]:6346|1\n" + // unspecified IPv6
		"H|127.0.0.1:6346|1\n" + // loopback IPv4
		"H|[::1]:6346|1\n" + // loopback IPv6
		"H|localhost:6346|1\n" + // loopback by name
		"H|:6346|1\n" + // no host
		"H||1\n" + // empty host
		"H|1.2.3.4 :6346|1\n" + // whitespace in the host
		"H|\n" + // nothing at all
		"not a gwebcache line\n" +
		"H|64.9.1.1:6346|notanum\n" + // bad epoch: keep the host, Seen 0
		"H|router.example.org:6346|7\n" + // hostname is a valid host
		"H|8.8.8.8:6346|1700000000\n"

	srv := serveBody(t, body)
	res, err := FetchHosts(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchHosts: %v", err)
	}

	want := []CacheHost{
		{Addr: "64.9.1.1:6346", Seen: 0},
		{Addr: "router.example.org:6346", Seen: 7},
		{Addr: "8.8.8.8:6346", Seen: 1700000000},
	}
	if len(res.Hosts) != len(want) {
		t.Fatalf("hosts = %+v, want %+v (malformed/loopback/unspecified must be dropped)", res.Hosts, want)
	}
	for i := range want {
		if res.Hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %+v, want %+v", i, res.Hosts[i], want[i])
		}
	}
}

// TestFetchHostsDeduplicates proves one entry per host:port, first-seen
// order preserved, freshest epoch kept.
func TestFetchHostsDeduplicates(t *testing.T) {
	const body = "H|1.2.3.4:6346|100\n" +
		"H|5.6.7.8:6346|200\n" +
		"H|1.2.3.4:6346|300\n" +
		"H|5.6.7.8:6347|50\n" +
		"U|http://a.example/gwc.php|1\n" +
		"U|http://a.example/gwc.php|9\n"

	srv := serveBody(t, body)
	res, err := FetchHosts(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchHosts: %v", err)
	}
	want := []CacheHost{
		{Addr: "1.2.3.4:6346", Seen: 300}, // duplicate collapsed, freshest seen
		{Addr: "5.6.7.8:6346", Seen: 200},
		{Addr: "5.6.7.8:6347", Seen: 50}, // different port is a different host
	}
	if len(res.Hosts) != len(want) {
		t.Fatalf("hosts = %+v, want %+v", res.Hosts, want)
	}
	for i := range want {
		if res.Hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %+v, want %+v", i, res.Hosts[i], want[i])
		}
	}
	if len(res.URLs) != 1 || res.URLs[0] != "http://a.example/gwc.php" {
		t.Errorf("urls = %v, want the U| line once", res.URLs)
	}
}

// TestFetchHostsMergesPerNetResponses covers the 2026 split: the same
// cache serves one host population on net=gnutella (the gtk-gnutella
// ultrapeers that complete a handshake) and a different one on
// net=gnutella2 (the Shielded Shareaza leaves). The merged result must
// carry both, one entry per address with the freshest Seen, which is
// why the two requests cannot simply race for a single winner.
func TestFetchHostsMergesPerNetResponses(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Query().Get("net") {
		case "gnutella":
			fmt.Fprint(w, "H|1.1.1.1:6346|100\nH|2.2.2.2:6346|200\n")
		case "gnutella2":
			fmt.Fprint(w, "H|2.2.2.2:6346|50\nH|3.3.3.3:6346|300\n")
		default:
			// Bare GET: this cache answers per net only.
			w.WriteHeader(http.StatusOK)
		}
	}))
	t.Cleanup(srv.Close)

	res, err := FetchHosts(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchHosts: %v", err)
	}
	want := []CacheHost{
		{Addr: "1.1.1.1:6346", Seen: 100},
		{Addr: "2.2.2.2:6346", Seen: 200}, // seen under both nets: freshest kept
		{Addr: "3.3.3.3:6346", Seen: 300},
	}
	if len(res.Hosts) != len(want) {
		t.Fatalf("hosts = %+v, want %+v (both networks merged)", res.Hosts, want)
	}
	for i := range want {
		if res.Hosts[i] != want[i] {
			t.Errorf("hosts[%d] = %+v, want %+v", i, res.Hosts[i], want[i])
		}
	}
}

// TestFetchHostsAcceptsLowercaseLineTypes covers two things the live
// 2026 caches actually do: DKAC serves lowercase `h|` lines, and Beacon
// Cache sends a four-field `I|access|period|33`. The same host under
// both cases must still collapse to one entry.
func TestFetchHostsAcceptsLowercaseLineTypes(t *testing.T) {
	const body = "h|4.4.4.4:6346|10\n" +
		"u|http://lower.example/gwc.php|11\n" +
		"i|access|period|33\n" +
		"H|4.4.4.4:6346|20\n"

	srv := serveBody(t, body)
	res, err := FetchHosts(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchHosts: %v", err)
	}
	if len(res.Hosts) != 1 {
		t.Fatalf("hosts = %+v, want one entry for the host named twice", res.Hosts)
	}
	if res.Hosts[0] != (CacheHost{Addr: "4.4.4.4:6346", Seen: 20}) {
		t.Errorf("host = %+v, want 4.4.4.4:6346 with the freshest seen 20", res.Hosts[0])
	}
	if len(res.URLs) != 1 || res.URLs[0] != "http://lower.example/gwc.php" {
		t.Errorf("urls = %v, want the lowercase u| line", res.URLs)
	}
	if len(res.Info) != 1 {
		t.Fatalf("info = %+v, want the i| line", res.Info)
	}
	want := CacheInfo{Key: "access|period", Value: "33"}
	if res.Info[0] != want {
		t.Errorf("info[0] = %+v, want %+v (multi-segment key, value last)", res.Info[0], want)
	}
}

// TestFetchHostsCapsHostCount guards the fan-out bound: one response
// contributes at most maxCacheHosts dialable addresses, so a hostile
// cache cannot turn a megabyte of well-formed H| lines into that many
// dial goroutines retrying every dialBackoff.
func TestFetchHostsCapsHostCount(t *testing.T) {
	var b strings.Builder
	for i := 0; i < maxCacheHosts*3; i++ {
		fmt.Fprintf(&b, "H|10.0.%d.%d:6346|%d\n", i/256, i%256, i)
	}

	srv := serveBody(t, b.String())
	res, err := FetchHosts(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("FetchHosts: %v", err)
	}
	if len(res.Hosts) != maxCacheHosts {
		t.Fatalf("hosts = %d, want the cap of %d", len(res.Hosts), maxCacheHosts)
	}
	if res.Hosts[0].Addr != "10.0.0.0:6346" {
		t.Errorf("first host = %q, want the first line of the response", res.Hosts[0].Addr)
	}
}

// TestFetchHostsContextCancelled is the cancellation contract: the
// client is context-aware and does not retry, so a cancelled context
// surfaces as an error rather than a request that outlives its caller.
func TestFetchHostsContextCancelled(t *testing.T) {
	srv := serveBody(t, "H|8.8.8.8:6346|1\n")

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := FetchHosts(ctx, srv.URL); err == nil {
		t.Fatal("FetchHosts on a cancelled context returned no error")
	}
}

// TestFetchHostsRejectsNonHTTPURL: the config validates this too, but
// the client must not build a request from a URL it cannot speak.
func TestFetchHostsRejectsNonHTTPURL(t *testing.T) {
	for _, bad := range []string{
		"ftp://example.org/gwc.php",
		"example.org/gwc.php",
		"http://",
		"file:///tmp/gwc",
	} {
		if _, err := FetchHosts(context.Background(), bad); err == nil {
			t.Errorf("FetchHosts(%q) = nil error, want rejection", bad)
		}
	}
}

// TestEngineDialsCacheFetchedPeer is the bootstrap loop closed: an
// engine with an empty Peers list is configured only with a cache URL,
// the cache hands back a second engine's loopback address, and the
// first engine's own dial machinery must connect to it. This is what
// "a fresh daemon finds peers without a hand-maintained gnutella_peers
// list" means in practice.
func TestEngineDialsCacheFetchedPeer(t *testing.T) {
	// The peer to discover: a second engine, listening on loopback.
	target, _ := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
	})

	var fetches atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetches.Add(1)
		fmt.Fprintf(w, "H|%s|1700000000\n", target.Addr().String())
	}))
	t.Cleanup(srv.Close)

	src, _ := startEngine(t, Options{
		Caches: []string{srv.URL},
		// The cache's host is 127.0.0.1, which FetchHosts filters in
		// production; a test may only reach loopback, so relax it.
		cacheAllowLoopback: true,
		KeepAliveInterval:  time.Hour,
		IdleTimeout:        10 * time.Second,
	})
	if len(src.opts.Peers) != 0 {
		t.Fatalf("Peers = %v, want empty: discovery must be the cache's doing", src.opts.Peers)
	}

	deadline := time.Now().Add(testDeadline)
	for {
		sent, got := peerCount(src), peerCount(target)
		if sent > 0 && got > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("cache-fetched peer never dialed: src peers=%d, target peers=%d, cache fetches=%d",
				sent, got, fetches.Load())
		}
		time.Sleep(20 * time.Millisecond)
	}
	if fetches.Load() == 0 {
		t.Fatal("the engine never consulted the cache")
	}

	// The connection must be a completed handshake, not a dial that
	// raced and died: it should still be up a moment later.
	time.Sleep(300 * time.Millisecond)
	if peerCount(src) == 0 || peerCount(target) == 0 {
		t.Errorf("connection did not survive the handshake: src peers=%d, target peers=%d",
			peerCount(src), peerCount(target))
	}
}

// peerCount reports how many peer connections an engine holds. It reads
// the engine's own bookkeeping, which is only reachable because the
// tests live in the package.
func peerCount(e *Engine) int {
	e.mu.Lock()
	defer e.mu.Unlock()
	return len(e.peers)
}

// serveBody starts a cache that answers a bare GET with body and an
// empty parameterised response, and closes it with the test.
func serveBody(t *testing.T, body string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("get") == "1" {
			return
		}
		fmt.Fprint(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}
