// SPDX-License-Identifier: GPL-3.0-or-later

// Package config resolves Sharza's runtime paths and settings.
//
// Paths follow the XDG base directory spec so the daemon needs no privileges
// and lands where a Linux user expects: downloaded data under
// $XDG_DATA_HOME, persistent state under $XDG_STATE_HOME, and the control
// socket under $XDG_RUNTIME_DIR. Every path is overridable in the config
// file, and the daemon creates what is missing at startup.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/jonathanvanherpe/sharza/internal/role"
)

// Directory names under the XDG bases. State and runtime carry the daemon's
// own name because they belong to sharzad; downloaded data carries the project
// name because it belongs to the user.
const (
	dataDirName  = "sharza"
	stateDirName = "sharzad"
)

// defaultWebListen lives one above the Gnutella/Gnutella2 port (6346), on
// loopback, so the UI port is easy to remember and unreachable from the
// network.
const defaultWebListen = "127.0.0.1:6347"

// Config is the resolved runtime configuration.
type Config struct {
	// DataDir holds downloaded file data. It follows $XDG_DATA_HOME and is
	// deliberately separate from StateDir, so backing up the small state
	// file does not drag a directory of downloads with it.
	DataDir string `json:"data_dir"`

	// StateDir holds the database and logs. It follows $XDG_STATE_HOME,
	// the spec's home for persistent state that is not user-facing data.
	StateDir string `json:"state_dir"`

	// RuntimeDir holds the control socket. It follows $XDG_RUNTIME_DIR,
	// which is a tmpfs cleared at logout, so a stale socket cannot outlive
	// the session that made it.
	RuntimeDir string `json:"runtime_dir"`

	// SocketPath is the control socket, inside RuntimeDir by default.
	SocketPath string `json:"socket_path"`

	// WebListen is the web UI bind address. By default it must be a
	// loopback address: the web UI has no authentication of its own and
	// relies on the loopback interface being unreachable from the network.
	//
	// The default, 127.0.0.1:6347, is one above the Gnutella and
	// Gnutella2 default port (6346) so the UI port is easy to remember
	// next to the network ports. The web listener lives on the host, never
	// inside a worker namespace, so the two never collide.
	WebListen string `json:"web_listen"`

	// ExposeWeb permits binding the web UI off-host. It is off by default
	// because the P0 UI has no authentication; the future desktop or CLI
	// client may connect from another machine, so expose is the deliberate
	// opt-in escape hatch. With ExposeWeb set, WebListen may name any
	// address, including 0.0.0.0. A loopback WebListen with ExposeWeb set
	// is harmless and still valid.
	ExposeWeb bool `json:"web_expose"`

	// WorkerRoles lists the worker roles to spawn.
	WorkerRoles []role.Role `json:"worker_roles"`

	// WorkerRestartDelay is how long to wait before respawning a worker
	// that exited. A zero value means use the default.
	WorkerRestartDelay string `json:"worker_restart_delay"`

	// DownloadDir is where completed files land, inside DataDir by default.
	DownloadDir string `json:"download_dir"`

	// GnutellaEnabled turns the g2 worker's Gnutella engine on. The
	// engine is new, so it defaults to off and reports "gnutella
	// disabled" rather than appearing to work while silent.
	GnutellaEnabled bool `json:"gnutella_enabled"`

	// GnutellaListen is the address the Gnutella engine accepts
	// connections on. 6346 is the conventional Gnutella port; the web
	// UI default sits one above it.
	GnutellaListen string `json:"gnutella_listen"`

	// GnutellaPeers lists host:port addresses the engine dials and
	// keeps connected, for pairing with an oracle node or a seeder.
	GnutellaPeers []string `json:"gnutella_peers"`

	// GnutellaCaches lists GWebCache URLs the engine queries once at
	// startup for host addresses, so a fresh daemon can bootstrap
	// without a hand-maintained peer list. Each must be an http(s) URL.
	GnutellaCaches []string `json:"gnutella_caches"`

	// ConfigPath records where this Config was loaded from, so a worker
	// can be spawned against the same file. Empty means built-in
	// defaults. Not serialised: it describes where we came from, not
	// what we are.
	ConfigPath string `json:"-"`
}

// Default returns a configuration rooted at the user's XDG directories.
func Default() *Config {
	c := &Config{WebListen: defaultWebListen}
	c.applyDefaults()
	return c
}

// applyDefaults fills every unset field. It is the single place defaults are
// resolved, so Default and a partially-specified config file agree on what an
// omitted key means.
func (c *Config) applyDefaults() {
	if c.DataDir == "" {
		c.DataDir = defaultDataDir()
	}
	if c.StateDir == "" {
		c.StateDir = defaultStateDir()
	}
	if c.RuntimeDir == "" {
		c.RuntimeDir = defaultRuntimeDir(c.StateDir)
	}
	if c.SocketPath == "" {
		c.SocketPath = filepath.Join(c.RuntimeDir, rpcSocketName)
	}
	if c.WebListen == "" {
		c.WebListen = defaultWebListen
	}
	if len(c.WorkerRoles) == 0 {
		c.WorkerRoles = role.WorkerRoles()
	}
	if c.DownloadDir == "" {
		c.DownloadDir = filepath.Join(c.DataDir, "downloads")
	}
	if c.GnutellaListen == "" {
		c.GnutellaListen = "0.0.0.0:6346"
	}
}

const rpcSocketName = "sharzad.sock"

// xdgBase resolves an XDG base directory: the environment variable when it is
// set to an absolute path, otherwise the fallback the spec names under the
// user's home. A relative env value is ignored rather than joined, because
// "relative to what" has no good answer for a daemon started by systemd.
func xdgBase(env, fallback string) string {
	if v := os.Getenv(env); v != "" && filepath.IsAbs(v) {
		return v
	}
	return filepath.Join(homeDir(), fallback)
}

// homeDir resolves the user's home, falling back to the temp dir so a daemon
// with no HOME still resolves a usable, absolute base instead of an empty one.
func homeDir() string {
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		return home
	}
	return os.TempDir()
}

func defaultDataDir() string {
	return filepath.Join(xdgBase("XDG_DATA_HOME", ".local/share"), dataDirName)
}

func defaultStateDir() string {
	return filepath.Join(xdgBase("XDG_STATE_HOME", ".local/state"), stateDirName)
}

// defaultRuntimeDir uses $XDG_RUNTIME_DIR when it is set, and otherwise keeps
// the socket in a run/ subdirectory of the state directory. A daemon started
// as a system service has no session runtime dir, and the socket still has to
// live somewhere writable that only its owner can reach.
func defaultRuntimeDir(stateDir string) string {
	if v := os.Getenv("XDG_RUNTIME_DIR"); v != "" && filepath.IsAbs(v) {
		return filepath.Join(v, stateDirName)
	}
	return filepath.Join(stateDir, "run")
}

// Load reads a config file. An empty path yields Default. A missing file at an
// explicit path is an error, because silently running with defaults after the
// user asked for a specific config is how a daemon ends up in the wrong place.
func Load(path string) (*Config, error) {
	if path == "" {
		return Default(), nil
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("config %s does not exist", path)
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}

	c := &Config{}
	dec := json.NewDecoder(strings.NewReader(string(data)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(c); err != nil {
		// An unknown field is almost always a typo that would otherwise
		// be silently ignored and leave the daemon misconfigured.
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config %s: %w", path, err)
	}
	c.ConfigPath = path
	return c, nil
}

// StatePath returns the state file path.
func (c *Config) StatePath() string {
	return filepath.Join(c.StateDir, "state.json")
}

// Validate checks the configuration for things that would fail late and
// confusingly at runtime.
func (c *Config) Validate() error {
	// Every writable root is checked the same way. A relative path would
	// resolve against whatever cwd the service manager handed the process,
	// and a path that exists as a regular file can never become a
	// directory; both are cheap to reject here and expensive to debug later.
	for _, d := range []struct{ field, path string }{
		{"data_dir", c.DataDir},
		{"state_dir", c.StateDir},
		{"runtime_dir", c.RuntimeDir},
	} {
		if err := validateAbsDir(d.field, d.path); err != nil {
			return err
		}
	}
	if !c.ExposeWeb {
		if err := c.checkLoopback(); err != nil {
			return err
		}
	}
	for _, r := range c.WorkerRoles {
		if !role.IsWorker(r) {
			return fmt.Errorf("worker_roles contains %q, which is not a worker role", r)
		}
	}
	// Caught here rather than at the first worker death: a restart delay that
	// does not parse is a daemon that restarts workers at a rate the operator
	// never chose, and it is much cheaper to say so at startup.
	//
	// Non-positive is rejected too, and not on taste: the whole point of the
	// delay is that a worker failing at startup does not spin the CPU, so
	// "0s" configures the exact behaviour the default exists to prevent. An
	// empty setting is fine and keeps meaning "use the default".
	if c.WorkerRestartDelay != "" {
		d, err := time.ParseDuration(c.WorkerRestartDelay)
		if err != nil {
			return fmt.Errorf("worker_restart_delay %q is not a duration such as \"2s\" or \"500ms\": %w",
				c.WorkerRestartDelay, err)
		}
		if d <= 0 {
			return fmt.Errorf("worker_restart_delay %q is %s; it must be positive, "+
				"since the delay is what stops a worker that fails at startup from spinning the CPU",
				c.WorkerRestartDelay, d)
		}
	}
	// Gnutella addresses are validated even while the engine is
	// disabled: flipping gnutella_enabled later must not turn a
	// long-running daemon into a worker that dies at startup over a
	// mistyped address.
	if err := validateAddr("gnutella_listen", c.GnutellaListen, false); err != nil {
		return err
	}
	for i, addr := range c.GnutellaPeers {
		if err := validateAddr(fmt.Sprintf("gnutella_peers[%d]", i), addr, true); err != nil {
			return err
		}
	}
	// Same reasoning as the addresses above: a mistyped cache URL must
	// be caught here, not by a worker that dies at its first fetch.
	for i, cache := range c.GnutellaCaches {
		if err := validateURL(fmt.Sprintf("gnutella_caches[%d]", i), cache); err != nil {
			return err
		}
	}
	return nil
}

// validateAbsDir checks a directory the daemon will write to. It is pure: it
// may stat the path to catch a regular file in the way, but it never creates
// anything. Creation and the writability probe belong to EnsureDirs, which
// runs once at startup.
func validateAbsDir(field, path string) error {
	if path == "" {
		return fmt.Errorf("%s is required", field)
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("%s must be an absolute path, got %q", field, path)
	}
	if fi, err := os.Stat(path); err == nil && !fi.IsDir() {
		return fmt.Errorf("%s %q exists but is not a directory", field, path)
	}
	return nil
}

// validateAddr checks a host:port value. A port of 0 is allowed (it
// means "pick one", which tests use); a peer address without a host is
// unusable, so requireHost rejects it.
func validateAddr(field, addr string, requireHost bool) error {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("%s %q is not host:port: %w", field, addr, err)
	}
	if requireHost && host == "" {
		return fmt.Errorf("%s %q has no host address", field, addr)
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("%s %q has a port of %q, not a number in 0..65535", field, addr, port)
	}
	return nil
}

// validateURL checks that a setting is an absolute http(s) URL with a
// host: the GWebCache client only speaks those two schemes, and a value
// with no scheme at all is a typo rather than a working cache.
func validateURL(field, raw string) error {
	if raw == "" {
		return fmt.Errorf("%s is empty; each entry must be an http or https URL", field)
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("%s %q is not a URL: %w", field, raw, err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("%s %q must be an http or https URL, got scheme %q", field, raw, u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("%s %q has no host", field, raw)
	}
	return nil
}

// checkLoopback refuses a web listener reachable off-host. The web UI has no
// authentication in P0; binding it to 0.0.0.0 would expose full control of the
// daemon to the network. Validate skips this check only when the operator
// explicitly set web_expose.
func (c *Config) checkLoopback() error {
	host := c.WebListen
	if i := strings.LastIndex(host, ":"); i >= 0 {
		host = host[:i]
	}
	host = strings.Trim(host, "[]")
	switch host {
	case "127.0.0.1", "::1", "localhost":
		return nil
	case "":
		return fmt.Errorf("web_listen must name a loopback address, got %q "+
			"(set web_expose: true to bind any address)", c.WebListen)
	default:
		return fmt.Errorf(
			"web_listen %q is not a loopback address: the web UI is unauthenticated in P0, "+
				"so binding it off-host would expose the daemon (set web_expose: true to allow it)",
			c.WebListen)
	}
}

// EnsureDirs creates every directory Sharza writes to and probes each one for
// writability. It runs once at startup, so a misconfigured or read-only path
// fails the daemon with a message naming the directory rather than surfacing
// later as a store write that silently cannot happen.
func (c *Config) EnsureDirs() error {
	// DataDir first: DownloadDir defaults to a subdirectory of it, and
	// creating the parent before the child keeps the intent obvious even
	// though MkdirAll would succeed in either order.
	for _, d := range []string{c.DataDir, c.StateDir, c.RuntimeDir, c.DownloadDir} {
		if err := ensureDir(d); err != nil {
			return err
		}
	}
	return nil
}

// ensureDir creates dir if it is missing, then proves it is writable with a
// probe file. Existing is not the same as usable: a directory can sit on a
// read-only mount or be owned by another user, and os.MkdirAll reports
// success in both cases.
func ensureDir(dir string) error {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	f, err := os.CreateTemp(dir, ".sharza-write-probe-*")
	if err != nil {
		return fmt.Errorf("%s is not writable: %w", dir, err)
	}
	name := f.Name()
	_ = f.Close()
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove write probe in %s: %w", dir, err)
	}
	return nil
}
