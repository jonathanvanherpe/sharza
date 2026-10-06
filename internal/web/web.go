// SPDX-License-Identifier: GPL-3.0-or-later

// Package web serves the embedded browser UI and a small status API.
//
// In P0 the UI is a status page only. It exists now so the transport, the
// embedding and the loopback binding are proven before there is anything
// complicated to serve.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/rpc"
	"github.com/jonathanvanherpe/sharza/internal/store"
	"github.com/jonathanvanherpe/sharza/internal/supervisor"
)

//go:embed assets
var assets embed.FS

// Serve starts the web server on listen, which must already have been
// validated as loopback by the config package.
//
// The browser UI has no login in P0. It is safe only because the listener is
// bound to loopback; see config.Config.checkLoopback.
func Serve(ctx context.Context, listen, socketPath string) (*http.Server, error) {
	mux := http.NewServeMux()
	mux.Handle("/api/status", statusHandler(socketPath))
	mux.Handle("/api/jobs", jobsHandler(socketPath))

	sub, err := fsSub(assets, "assets")
	if err != nil {
		return nil, fmt.Errorf("web: mount assets: %w", err)
	}
	mux.Handle("/", noCache(http.FileServer(http.FS(sub))))

	srv := &http.Server{
		Handler: mux,
		// The UI is served from memory, so these timeouts only exist to
		// stop a stuck browser from pinning a connection open.
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	ln, err := net.Listen("tcp", listen)
	if err != nil {
		return nil, fmt.Errorf("web: listen on %s: %w", listen, err)
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			// Serve only returns on a real failure; swallowing it would
			// leave the daemon running with a dead UI and no signal.
			fmt.Fprintf(stderr, "web: serve: %v\n", err)
		}
	}()

	return srv, nil
}

func statusHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		c, err := rpc.Dial(socketPath, 2*time.Second)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "daemon unavailable: " + err.Error(),
			})
			return
		}
		defer c.Close()

		var out supervisor.Status
		if err := c.Call(ctx, rpc.MethodStatus, nil, &out); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func jobsHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()

		c, err := rpc.Dial(socketPath, 2*time.Second)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "daemon unavailable: " + err.Error(),
			})
			return
		}
		defer c.Close()

		var out []store.Job
		if err := c.Call(ctx, rpc.MethodJobsList, nil, &out); err != nil {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(v)
}

// noCache keeps a stale shell from outliving a code change during
// development, which otherwise produces "I fixed it but the page did not
// change" confusion.
func noCache(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}
