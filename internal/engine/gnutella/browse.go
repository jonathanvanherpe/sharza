// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// The Gnutella 1 browse-host client: the HTTP GET a servent answers with
// a listing of the files it shares. This is the transport slice only:
// the response body is returned verbatim together with its Content-Type,
// and no parsing into a file list or profile happens here.
//
// A browse request first tries /gnutella/browse/v1 (the "new browse"
// path Shareaza uses); if that path is refused, it falls back to the
// legacy root path /. The Accept header is selected by an accept mode so
// the caller can ask for XML, Gnutella 1 packets, or Gnutella 2 packets.

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"

	"github.com/jonathanvanherpe/sharza/internal/version"
)

// browseAcceptValues maps an accept mode to the Accept header value sent
// to the peer: 0 = text/xml, 1 = application/x-gnutella-packets,
// 2 = application/x-gnutella2.
var browseAcceptValues = []string{
	"text/xml",
	"application/x-gnutella-packets",
	"application/x-gnutella2",
}

// defaultBrowseClient performs one browse GET. It reuses the engine's
// dial timeout, refuses to wait on a peer that accepts and never sends
// headers, and keeps the body on the wire untouched: a transparently
// decompressed body would not be the bytes the peer sent, and the
// caller is what decides whether to inflate a deflate-encoded response.
var defaultBrowseClient = &http.Client{
	Transport: &http.Transport{
		DialContext:           (&net.Dialer{Timeout: dialTimeout}).DialContext,
		ResponseHeaderTimeout: downloadHeaderTimeout,
		DisableCompression:    true,
	},
}

// BrowseHost performs an HTTP GET against the servent at addr and returns
// its response body and Content-Type. accept selects the Accept header
// (0 = text/xml, 1 = application/x-gnutella-packets, 2 =
// application/x-gnutella2). A nil client selects defaultBrowseClient.
//
// The request is first sent to /gnutella/browse/v1; if that path is
// refused (a non-2xx status), it is retried against /. The headers
// follow the servent convention: User-Agent, the selected Accept,
// Accept-Encoding: deflate, and Connection: close.
func BrowseHost(ctx context.Context, client *http.Client, addr string, accept int) ([]byte, string, error) {
	if client == nil {
		client = defaultBrowseClient
	}
	if tr, ok := client.Transport.(*http.Transport); ok && tr.ResponseHeaderTimeout == 0 {
		tr.ResponseHeaderTimeout = downloadHeaderTimeout
	}
	if accept < 0 || accept >= len(browseAcceptValues) {
		accept = 0
	}

	paths := []string{"/gnutella/browse/v1", "/"}

	var lastErr error
	for i, path := range paths {
		body, contentType, status, err := browseOnce(ctx, client, addr, path, browseAcceptValues[accept])
		if err != nil {
			return nil, "", err
		}
		if status/100 == 2 {
			return body, contentType, nil
		}
		// Non-2xx: refused. Fall back from the v1 path to the root.
		lastErr = fmt.Errorf("gnutella: browse %s: status %d", path, status)
		if i == len(paths)-1 {
			return nil, "", lastErr
		}
	}
	return nil, "", lastErr
}

// browseOnce performs a single GET and returns the body, Content-Type and
// status code. A transport-level failure is reported through err.
func browseOnce(ctx context.Context, client *http.Client, addr, path, accept string) ([]byte, string, int, error) {
	rawURL := fmt.Sprintf("http://%s%s", addr, path)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, "", 0, fmt.Errorf("gnutella: browse request %s: %w", rawURL, err)
	}
	req.Header.Set("User-Agent", version.UserAgent())
	req.Header.Set("Accept", accept)
	req.Header.Set("Accept-Encoding", "deflate")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		return nil, "", 0, fmt.Errorf("gnutella: browse %s: %w", rawURL, err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, "", resp.StatusCode, fmt.Errorf("gnutella: browse %s: %w", rawURL, err)
	}
	return body, resp.Header.Get("Content-Type"), resp.StatusCode, nil
}