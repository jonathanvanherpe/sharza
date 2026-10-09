// SPDX-License-Identifier: GPL-3.0-or-later

// Package config resolves Sharza's runtime paths and settings.
//
// Sharza keeps everything under a single state directory so the whole
// installation is one directory to back up, one to move between hosts, and
// one to remove. Nothing is written outside it, and nothing requires
// privileges to create.
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

// DefaultStateDir is used when no config file names one. It follows XDG.
const DefaultStateDirName = ".local/share/sharza"

// Config is the resolved runtime configuration.
type Config struct {
	// StateDir holds the database, socket and logs.
	StateDir string `json:"state_dir"`

	// SocketPath is the control socket.
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

	// DownloadDir is where completed files land.
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

// Default returns a configuration rooted at the user's XDG data dir.
func Default() *Config {
	base, err := os.UserHomeDir()
	if err != nil {
		base = os.TempDir()
	}
	stateDir := filepath.Join(base, DefaultStateDirName)
	c := &Config{
		StateDir:  stateDir,
		WebListen: "127.0.0.1:6347",
	}
	c.applyDefaults()
	return c
}

func (c *Config) applyDefaults() {
	if c.StateDir == "" {
		c.StateDir = Default().StateDir
	}
	if c.SocketPath == "" {
		c.SocketPath = filepath.Join(c.StateDir, rpcSocketName)
	}
	if c.WebListen == "" {
		c.WebListen = "127.0.0.1:6347"
	}
	if len(c.WorkerRoles) == 0 {
		c.WorkerRoles = role.WorkerRoles()
	}
	if c.DownloadDir == "" {
		c.DownloadDir = filepath.Join(c.StateDir, "downloads")
	}
	if c.GnutellaListen == "" {
		c.GnutellaListen = "0.0.0.0:6346"
	}
}

const rpcSocketName = "sharzad.sock"

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
	if c.StateDir == "" {
		return fmt.Errorf("state_dir is required")
	}
	if !filepath.IsAbs(c.StateDir) {
		return fmt.Errorf("state_dir must be an absolute path, got %q", c.StateDir)
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

// EnsureDirs creates the directories Sharza writes to.
func (c *Config) EnsureDirs() error {
	for _, d := range []string{c.StateDir, c.DownloadDir} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			return fmt.Errorf("create %s: %w", d, err)
		}
	}
	return nil
}
