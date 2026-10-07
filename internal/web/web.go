// SPDX-License-Identifier: GPL-3.0-or-later

// Package web serves the embedded browser UI and a JSON API that proxies the
// daemon's RPC surface.
//
// In P0 the UI is a control page: network toggles, a log tail, job
// management, and honest placeholders where the protocols are not wired yet.
// It exists now so the transport, the embedding and the loopback binding are
// proven before there is anything complicated to serve.
package web

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/role"
	"github.com/jonathanvanherpe/sharza/internal/rpc"
	"github.com/jonathanvanherpe/sharza/internal/store"
	"github.com/jonathanvanherpe/sharza/internal/supervisor"
)

//go:embed assets
var assets embed.FS

// Serve starts the web server on listen, which the config package has already
// validated: loopback-only unless the operator set web_expose.
//
// The browser UI has no login in P0. It is safe only because the listener is
// bound to loopback unless config.Config.ExposeWeb was explicitly set; see
// config.Config.checkLoopback.
func Serve(ctx context.Context, listen, socketPath string) (*http.Server, error) {
	srv := &http.Server{
		Handler: NewMux(socketPath),
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

// NewMux builds the API and asset routes. It is separate from Serve so tests
// can mount the mux on an httptest server against a control socket.
func NewMux(socketPath string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.Handle("/api/status", statusHandler(socketPath))
	mux.Handle("/api/jobs", jobsHandler(socketPath))
	mux.HandleFunc("POST /api/jobs", jobsCreateHandler(socketPath))
	mux.HandleFunc("POST /api/jobs/{id}/pause", jobMutateHandler(socketPath, rpc.MethodJobsPause))
	mux.HandleFunc("POST /api/jobs/{id}/resume", jobMutateHandler(socketPath, rpc.MethodJobsResume))
	mux.HandleFunc("POST /api/jobs/{id}/remove", jobMutateHandler(socketPath, rpc.MethodJobsRemove))
	mux.HandleFunc("POST /api/roles/{role}/pause", roleMutateHandler(socketPath, rpc.MethodRolesPause))
	mux.HandleFunc("POST /api/roles/{role}/resume", roleMutateHandler(socketPath, rpc.MethodRolesResume))
	mux.HandleFunc("GET /api/logs", logsHandler(socketPath))

	sub, err := fsSub(assets, "assets")
	if err != nil {
		// The embed is part of the binary; a missing dir is a build bug and
		// its symptom is a UI that serves nothing. Surface it as a handler
		// so tests and operators see it, not as a silent empty page.
		mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "web: assets missing: "+err.Error(), http.StatusInternalServerError)
		})
		return mux
	}
	mux.Handle("/", noCache(http.FileServer(http.FS(sub))))
	return mux
}

// callRPC makes one JSON-RPC call over the daemon's control socket. A dial
// failure is a different, distinguishable error from an RPC failure: the
// former means the daemon is down, the latter that it answered with an error.
func callRPC(socketPath, method string, params, out any) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	c, err := rpc.Dial(socketPath, 2*time.Second)
	if err != nil {
		return &dialError{err}
	}
	defer c.Close()
	return c.Call(ctx, method, params, out)
}

type dialError struct{ err error }

func (e *dialError) Error() string { return "daemon unavailable: " + e.err.Error() }
func (e *dialError) Unwrap() error { return e.err }

// httpStatus maps an RPC error onto an HTTP status the UI can react to.
func httpStatus(err error) int {
	var re *rpc.Error
	if errors.As(err, &re) {
		switch re.Code {
		case rpc.CodeInvalidParams:
			return http.StatusBadRequest
		case rpc.CodeFailedPrecond:
			return http.StatusConflict
		case rpc.CodeUnauthorized:
			return http.StatusForbidden
		case rpc.CodeUnavailable:
			return http.StatusServiceUnavailable
		}
		return http.StatusBadGateway
	}
	var de *dialError
	if errors.As(err, &de) {
		return http.StatusServiceUnavailable
	}
	return http.StatusBadGateway
}

func writeError(w http.ResponseWriter, err error) {
	writeJSON(w, httpStatus(err), map[string]string{"error": err.Error()})
}

func statusHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var out supervisor.Status
		if err := callRPC(socketPath, rpc.MethodStatus, nil, &out); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func jobsHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var out []store.Job
		if err := callRPC(socketPath, rpc.MethodJobsList, nil, &out); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func jobsCreateHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var p supervisor.AddJobParams
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{
				"error": "invalid job: " + err.Error(),
			})
			return
		}
		var out supervisor.AddJobReply
		if err := callRPC(socketPath, rpc.MethodJobsAdd, p, &out); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func jobMutateHandler(socketPath, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if id == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "id is required"})
			return
		}
		var out supervisor.JobReply
		if err := callRPC(socketPath, method, struct {
			ID string `json:"id"`
		}{ID: id}, &out); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func roleMutateHandler(socketPath, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		name := r.PathValue("role")
		if name == "" {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": "role is required"})
			return
		}
		var out supervisor.RoleReply
		if err := callRPC(socketPath, method, supervisor.RoleParam{
			Role: role.Role(name),
		}, &out); err != nil {
			writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, out)
	}
}

func logsHandler(socketPath string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := 200
		if v := r.URL.Query().Get("limit"); v != "" {
			n, err := strconv.Atoi(v)
			if err != nil || n < 1 || n > 1000 {
				writeJSON(w, http.StatusBadRequest, map[string]string{
					"error": "limit must be an integer between 1 and 1000",
				})
				return
			}
			limit = n
		}
		var out supervisor.LogsTailReply
		if err := callRPC(socketPath, rpc.MethodLogsTail, supervisor.LogsTailParams{
			Limit: limit,
		}, &out); err != nil {
			writeError(w, err)
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
