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
	"os"
	"path/filepath"
	"strings"

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

	// WebListen is the local web UI bind address. It must be a loopback
	// address: the web UI has no authentication of its own and relies on
	// the loopback interface being unreachable from the network.
	WebListen string `json:"web_listen"`

	// WorkerRoles lists the worker roles to spawn.
	WorkerRoles []role.Role `json:"worker_roles"`

	// WorkerRestartDelay is how long to wait before respawning a worker
	// that exited. A zero value means use the default.
	WorkerRestartDelay string `json:"worker_restart_delay"`

	// DownloadDir is where completed files land.
	DownloadDir string `json:"download_dir"`

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
		WebListen: "127.0.0.1:8710",
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
		c.WebListen = "127.0.0.1:8710"
	}
	if len(c.WorkerRoles) == 0 {
		c.WorkerRoles = role.WorkerRoles()
	}
	if c.DownloadDir == "" {
		c.DownloadDir = filepath.Join(c.StateDir, "downloads")
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
	if err := c.checkLoopback(); err != nil {
		return err
	}
	for _, r := range c.WorkerRoles {
		if !role.IsWorker(r) {
			return fmt.Errorf("worker_roles contains %q, which is not a worker role", r)
		}
	}
	return nil
}

// checkLoopback refuses a web listener reachable off-host. The web UI has no
// authentication in P0; binding it to 0.0.0.0 would expose full control of the
// daemon to the network.
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
		return fmt.Errorf("web_listen must name a loopback address, got %q", c.WebListen)
	default:
		return fmt.Errorf(
			"web_listen %q is not a loopback address: the web UI is unauthenticated in P0, "+
				"so binding it off-host would expose the daemon", c.WebListen)
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
