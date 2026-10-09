// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// A GWebCache (GWC) client: the bootstrap half of Gnutella host
// discovery. A webcache is a plain HTTP endpoint that answers a GET
// with a body of pipe-separated lines, in the 2002 format the handful
// of caches still alive in 2026 speak (line types are matched
// case-insensitively; DKAC serves `h|` where the others serve `H|`):
//
//	H|host:port|seen	a host to dial, and the cache's seen value
//	U|url|seen		another cache's URL, for later polling
//	I|key|value		information, e.g. I|access|period|33
//
// The client turns a URL into dialable addresses and nothing else: it
// retries nothing, dials nothing, and never blocks the engine. A failed
// fetch is the engine's to log, and the dial loops and their backoff
// are the engine's too, so one dead cache cannot stall bootstrap or
// open a second connection to a peer we already have.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/version"
)

const (
	// cacheTimeout bounds one FetchHosts call, all requests together.
	// The context is the real cancellation path; this exists so a cache
	// that accepts a connection and then says nothing cannot hold the
	// bootstrap goroutine (and with it engine shutdown) indefinitely.
	cacheTimeout = 10 * time.Second

	// maxCacheBody caps how much of a response is read. A webcache is
	// untrusted input; a megabyte is far more than a real host list.
	maxCacheBody = 1 << 20

	// maxCacheHosts caps how many hosts one response may contribute.
	// The body cap bounds memory but not consequence: without this, a
	// hostile or compromised cache (these are cleartext http:// URLs to
	// third-party servers) could list tens of thousands of addresses
	// and turn them into that many dial goroutines retrying every
	// dialBackoff, each logging a failure. Real caches serve a few
	// dozen hosts, so 64 never truncates an honest list. The bound is
	// per response: one cache URL issues one request per request shape
	// (fetchHosts), so its worst case is maxCacheHosts times the shape
	// count -- still bounded, and the shapes carry different host
	// populations that must not evict each other to stay under it.
	maxCacheHosts = 64

	// cacheClientID is the client= query parameter: a four-part version
	// and the client name, which is the shape the gweb3/4octets family
	// requires before it will answer at all.
	cacheClientID = "0.1.0.0+Sharza"
)

// cacheNets are the networks the parameterised request form asks for,
// one request per network. The live 2026 caches answer per network,
// with different populations behind each name: net=gnutella serves the
// gtk-gnutella 1.3.1 ultrapeers that complete a handshake with us,
// net=gnutella2 the Shareaza-family leaves that mostly shield
// themselves with 503 but still exchange handshake headers. Both feed
// the same dial loop, so both are fetched and merged; a cache that
// knows only one errors on the other request, which counts as a failed
// shape, not a failed cache.
var cacheNets = []string{"gnutella", "gnutella2"}

// CacheHost is one host:port a cache returned, with the line's third
// field as Seen. Caches disagree on what that field is (a unix epoch,
// an age in seconds), so it is carried through as given rather than
// interpreted; Seen is 0 when the line carried none or a value that
// does not parse, which is common enough not to drop the host for.
type CacheHost struct {
	Addr string
	Seen int64
}

// CacheInfo is one I| line: Key is everything between the first and
// last pipe (so `I|access|period|33` keys as `access|period`) and Value
// is the last field. The values are kept so pacing can be applied
// later, but nothing consumes them yet.
type CacheInfo struct {
	Key   string
	Value string
}

// CacheResult is a parsed webcache response. Hosts are deduplicated in
// first-seen order with the freshest Seen kept per address.
type CacheResult struct {
	Hosts []CacheHost
	URLs  []string
	Info  []CacheInfo
}

// FetchHosts fetches rawURL and returns the host list it serves.
//
// Two request shapes exist in the wild: the older caches serve the bare
// list on GET, while the gweb3/4octets.co.uk family only answers
// ?client=<4>+<ver>&get=1&net=<net> -- and that family answers per
// network, with different hosts behind net=gnutella and net=gnutella2.
// So the bare GET plus one parameterised GET per cacheNets entry are
// tried, once each, and the parses are merged: hosts keep first-seen
// order with the freshest Seen per address, URLs and info lines
// deduplicate. A cache that errors on a shape it does not know (they
// answer "ERROR Unsupported network" for a foreign net=) contributes
// nothing from that shape. That is the whole retry policy: no loop, no
// second pass.
//
// Unusable hosts are dropped: malformed or out-of-range host:port,
// 0.0.0.0 and other unspecified addresses, and loopback addresses. A
// cache handing out 127.0.0.1 is either broken or steering us at a
// local service, and neither is a reason to dial it.
func FetchHosts(ctx context.Context, rawURL string) (CacheResult, error) {
	return fetchHosts(ctx, rawURL, false)
}

// fetchHosts is FetchHosts with the loopback policy made explicit, so
// tests can point a cache at a listener on 127.0.0.1 (which is also all
// a test is allowed to reach). Production always passes false.
func fetchHosts(ctx context.Context, rawURL string, allowLoopback bool) (CacheResult, error) {
	if err := checkCacheURL(rawURL); err != nil {
		return CacheResult{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, cacheTimeout)
	defer cancel()

	// One request per shape, sequential and shared under one deadline:
	// the bare list, then one parameterised request per cacheNets
	// entry. Every successful parse merges into one result, and only a
	// cache that fails every shape is an error.
	var (
		merged CacheResult
		errs   []error
		ok     int
	)
	reqs := make([]string, 0, 1+len(cacheNets))
	reqs = append(reqs, rawURL)
	for _, net := range cacheNets {
		reqs = append(reqs, paramURL(rawURL, net))
	}
	for _, u := range reqs {
		body, err := getCacheBody(ctx, u)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		ok++
		mergeCacheResult(&merged, parseCacheBody(body, allowLoopback))
	}
	if ok == 0 {
		return CacheResult{}, fmt.Errorf("gnutella: webcache %s: %w", rawURL, errors.Join(errs...))
	}
	return merged, nil
}

// checkCacheURL rejects anything that is not an absolute http(s) URL
// with a host, before a request is built from it.
func checkCacheURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("gnutella: webcache URL %q: %w", rawURL, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("gnutella: webcache URL %q must be http or https, got scheme %q",
			rawURL, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("gnutella: webcache URL %q has no host", rawURL)
	}
	return nil
}

// paramURL adds the query the gweb3/4octets family requires, preserving
// any query the operator's URL already carries. net is the network to
// ask for; the caches answer with that network's hosts only.
func paramURL(rawURL, net string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL // unreachable: fetchHosts checked it first
	}
	q := u.Query()
	q.Set("get", "1")
	q.Set("client", cacheClientID)
	q.Set("net", net)
	// Encode would escape the '+' in client=<ver>+<name> to %2B. The
	// 2002-era caches split their query strings naively and expect the
	// literal '+', so send that.
	u.RawQuery = strings.ReplaceAll(q.Encode(), "%2B", "+")
	return u.String()
}

// mergeCacheResult folds src into dst. Hosts keep first-seen order
// across responses with the freshest Seen kept per address; URLs and
// info lines deduplicate. Parsing the same body under every request
// shape (a cache that answers identically to all of them) therefore
// merges back into a single copy.
func mergeCacheResult(dst *CacheResult, src CacheResult) {
	index := make(map[string]int, len(dst.Hosts))
	for i, h := range dst.Hosts {
		index[h.Addr] = i
	}
	for _, h := range src.Hosts {
		if i, dup := index[h.Addr]; dup {
			if h.Seen > dst.Hosts[i].Seen {
				dst.Hosts[i].Seen = h.Seen
			}
			continue
		}
		index[h.Addr] = len(dst.Hosts)
		dst.Hosts = append(dst.Hosts, h)
	}

	seenURL := make(map[string]bool, len(dst.URLs))
	for _, u := range dst.URLs {
		seenURL[u] = true
	}
	for _, u := range src.URLs {
		if seenURL[u] {
			continue
		}
		seenURL[u] = true
		dst.URLs = append(dst.URLs, u)
	}

	seenInfo := make(map[CacheInfo]bool, len(dst.Info))
	for _, in := range dst.Info {
		seenInfo[in] = true
	}
	for _, in := range src.Info {
		if seenInfo[in] {
			continue
		}
		seenInfo[in] = true
		dst.Info = append(dst.Info, in)
	}
}

// getCacheBody performs exactly one GET and returns its body. One
// request, no retry: a cache that fails here is a cache the engine logs
// and moves past.
func getCacheBody(ctx context.Context, rawURL string) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", version.UserAgent())
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		// Drain a little so the connection can be reused, then let the
		// defer close it; an error page is not a host list.
		_, _ = io.CopyN(io.Discard, resp.Body, 4096)
		return "", fmt.Errorf("status %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxCacheBody))
	if err != nil {
		return "", err
	}
	return string(body), nil
}

// parseCacheBody splits a webcache response into hosts, cache URLs and
// information lines. Anything unparseable is dropped rather than
// guessed at: a bad H| line is not worth a dial attempt.
//
// Line types are matched case-insensitively because the caches do not
// agree on case: DKAC serves `h|` where the others serve `H|`, and
// Shareaza matches `i|` case-insensitively too.
func parseCacheBody(body string, allowLoopback bool) CacheResult {
	var res CacheResult
	index := make(map[string]int) // host addr -> position in res.Hosts
	seenURL := make(map[string]bool)

	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.Split(line, "|")
		switch {
		case len(fields) >= 2 && strings.EqualFold(fields[0], "H"):
			addr, ok := dialableAddr(fields[1], allowLoopback)
			if !ok {
				continue
			}
			var seen int64
			if len(fields) >= 3 {
				// An unusable seen value keeps the host; the address
				// is the part worth dialing, the seen field is only
				// advisory (and caches disagree on whether it is an
				// epoch or an age).
				if v, err := strconv.ParseInt(strings.TrimSpace(fields[2]), 10, 64); err == nil {
					seen = v
				}
			}
			if i, dup := index[addr]; dup {
				if seen > res.Hosts[i].Seen {
					res.Hosts[i].Seen = seen
				}
				continue
			}
			if len(res.Hosts) >= maxCacheHosts {
				// Beyond the cap the line is dropped no matter how
				// well-formed it is: one response contributes at
				// most maxCacheHosts dials.
				continue
			}
			index[addr] = len(res.Hosts)
			res.Hosts = append(res.Hosts, CacheHost{Addr: addr, Seen: seen})

		case len(fields) >= 2 && strings.EqualFold(fields[0], "U"):
			u := strings.TrimSpace(fields[1])
			if u == "" || seenURL[u] || !isHTTPURL(u) {
				continue
			}
			seenURL[u] = true
			res.URLs = append(res.URLs, u)

		case len(fields) >= 3 && strings.EqualFold(fields[0], "I"):
			// The canonical line is I|<key>|<value>, but the live
			// caches send multi-segment keys, e.g. Beacon Cache's
			// I|access|period|33. Keep the middle segments as the key
			// (pipes intact) and the last as the value, which is
			// exactly the brief's shape when there are three fields
			// and loses nothing when there are four.
			key := strings.TrimSpace(strings.Join(fields[1:len(fields)-1], "|"))
			if key == "" {
				continue
			}
			res.Info = append(res.Info, CacheInfo{
				Key:   key,
				Value: strings.TrimSpace(fields[len(fields)-1]),
			})
		}
	}
	return res
}

// dialableAddr validates the host field of an H| line. It returns the
// address in the host:port form the dial loops take, and false when the
// address is malformed, out of range, unspecified or loopback.
func dialableAddr(hostport string, allowLoopback bool) (string, bool) {
	hostport = strings.TrimSpace(hostport)
	host, port, err := net.SplitHostPort(hostport)
	if err != nil || host == "" {
		return "", false
	}
	if strings.ContainsAny(host, " \t\r\n") {
		// A hostname may not contain whitespace. Without this a line
		// like "H|1.2.3.4 :6346" would pass as a hostname, reach the
		// dial loop, and fail there forever with a log line per retry.
		return "", false
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 1 || n > 65535 {
		return "", false
	}
	if strings.EqualFold(host, "localhost") {
		// Loopback by name, so it obeys the same rule as the literal
		// addresses below: dropped unless the caller allows loopback.
		if !allowLoopback {
			return "", false
		}
		return hostport, true
	}
	if ip := net.ParseIP(host); ip != nil {
		if ip.IsUnspecified() {
			return "", false
		}
		if ip.IsLoopback() && !allowLoopback {
			return "", false
		}
	}
	return hostport, true
}

// isHTTPURL reports whether u is a usable http(s) URL for the U| lines,
// which are other caches we may poll later.
func isHTTPURL(u string) bool {
	parsed, err := url.Parse(u)
	if err != nil {
		return false
	}
	return (parsed.Scheme == "http" || parsed.Scheme == "https") && parsed.Host != ""
}
