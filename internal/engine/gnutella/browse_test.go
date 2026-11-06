// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// Tests for the Gnutella 1 browse-host client. The peer is an
// httptest.NewServer, which is a real TCP listener speaking real HTTP,
// so the transfer goes through the same net/http path a live servent
// would take; nothing here reaches the network.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func browseAddr(t *testing.T, srv *httptest.Server) string {
	t.Helper()
	ta, ok := srv.Listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address is %T, want *net.TCPAddr", srv.Listener.Addr())
	}
	return fmt.Sprintf("%s:%d", ta.IP.String(), ta.Port)
}

func TestBrowseHostRequestPathAndHeaders(t *testing.T) {
	for _, mode := range []int{0, 1, 2} {
		mode := mode
		t.Run(fmt.Sprintf("accept-%d", mode), func(t *testing.T) {
			wantAccept := browseAcceptValues[mode]

			var got struct {
				path, accept, acceptEnc, conn, ua string
				count                             int
			}
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				got.count++
				got.path = r.URL.Path
				got.accept = r.Header.Get("Accept")
				got.acceptEnc = r.Header.Get("Accept-Encoding")
				got.conn = r.Header.Get("Connection")
				got.ua = r.Header.Get("User-Agent")
				w.Header().Set("Content-Type", "text/xml")
				_, _ = w.Write([]byte("ok"))
			}))
			defer srv.Close()

			body, ct, err := BrowseHost(context.Background(), nil, browseAddr(t, srv), mode)
			if err != nil {
				t.Fatalf("BrowseHost: %v", err)
			}
			if got.count != 1 {
				t.Errorf("request count = %d, want 1", got.count)
			}
			if got.path != "/gnutella/browse/v1" {
				t.Errorf("request path = %q, want /gnutella/browse/v1", got.path)
			}
			if got.accept != wantAccept {
				t.Errorf("Accept = %q, want %q", got.accept, wantAccept)
			}
			if !strings.EqualFold(got.acceptEnc, "deflate") {
				t.Errorf("Accept-Encoding = %q, want deflate", got.acceptEnc)
			}
			if !strings.EqualFold(got.conn, "close") {
				t.Errorf("Connection = %q, want close", got.conn)
			}
			if got.ua == "" {
				t.Error("User-Agent is empty")
			}
			if string(body) != "ok" {
				t.Errorf("body = %q, want ok", body)
			}
			if ct != "text/xml" {
				t.Errorf("content type = %q, want text/xml", ct)
			}
		})
	}
}

func TestBrowseHostFallbackToRoot(t *testing.T) {
	var paths []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		paths = append(paths, r.URL.Path)
		if r.URL.Path == "/gnutella/browse/v1" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/x-gnutella2")
		_, _ = w.Write([]byte("root-body"))
	}))
	defer srv.Close()

	body, ct, err := BrowseHost(context.Background(), nil, browseAddr(t, srv), 2)
	if err != nil {
		t.Fatalf("BrowseHost: %v", err)
	}
	if len(paths) != 2 || paths[0] != "/gnutella/browse/v1" || paths[1] != "/" {
		t.Errorf("paths = %v, want v1 then /", paths)
	}
	if string(body) != "root-body" {
		t.Errorf("body = %q, want root-body", body)
	}
	if ct != "application/x-gnutella2" {
		t.Errorf("content type = %q", ct)
	}
}

func TestBrowseHostSuccessBody(t *testing.T) {
	content := []byte("hello browse")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/x-gnutella-packets")
		_, _ = w.Write(content)
	}))
	defer srv.Close()

	body, ct, err := BrowseHost(context.Background(), nil, browseAddr(t, srv), 1)
	if err != nil {
		t.Fatalf("BrowseHost: %v", err)
	}
	if string(body) != string(content) {
		t.Errorf("body = %q, want %q", body, content)
	}
	if ct != "application/x-gnutella-packets" {
		t.Errorf("content type = %q", ct)
	}
}

func TestBrowseHostRefusesNon2xx(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	_, _, err := BrowseHost(context.Background(), nil, browseAddr(t, srv), 0)
	if err == nil {
		t.Fatal("BrowseHost accepted a non-2xx response")
	}
}

func TestBrowseHostHeaderTimeout(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Never send headers; return when the client goes away so the
		// server can close without waiting for the sleep to finish.
		select {
		case <-time.After(time.Hour):
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	_, _, err := BrowseHost(ctx, nil, browseAddr(t, srv), 0)
	if err == nil {
		t.Fatal("BrowseHost returned no error on a header timeout")
	}
	if !errors.Is(err, context.DeadlineExceeded) && !strings.Contains(err.Error(), "timeout") && !strings.Contains(err.Error(), "deadline") {
		// Accept any error; but log for diagnosis.
		t.Logf("err = %v", err)
	}
}

func TestBrowseHostBadAcceptMode(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept") != "text/xml" {
			t.Errorf("Accept = %q, want text/xml for out-of-range mode", r.Header.Get("Accept"))
		}
		w.Header().Set("Content-Type", "text/xml")
		_, _ = w.Write([]byte("x"))
	}))
	defer srv.Close()

	if _, _, err := BrowseHost(context.Background(), nil, browseAddr(t, srv), 99); err != nil {
		t.Fatalf("BrowseHost: %v", err)
	}
}