// SPDX-License-Identifier: GPL-3.0-or-later

package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jonathanvanherpe/sharza/internal/role"
)

func TestDefaultIsUsable(t *testing.T) {
	c := Default()
	if err := c.Validate(); err != nil {
		t.Fatalf("Default().Validate() = %v, want nil", err)
	}
	if c.SocketPath == "" || !strings.HasSuffix(c.SocketPath, rpcSocketName) {
		t.Errorf("SocketPath = %q, want it to end in %q", c.SocketPath, rpcSocketName)
	}
	if len(c.WorkerRoles) == 0 {
		t.Error("Default() spawns no workers")
	}
	if filepath.Dir(c.SocketPath) != c.StateDir {
		t.Errorf("socket %q is not inside state dir %q", c.SocketPath, c.StateDir)
	}
}

// The web UI has no authentication in P0, so a non-loopback bind would hand
// full control of the daemon to the network. This is the check that prevents
// it, so it gets tested like a security control rather than a validation.
func TestNonLoopbackWebListenIsRefused(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{
		"0.0.0.0:8710",
		":8710",
		"192.168.1.10:8710",
		"[::]:8710",
		"example.org:8710",
		"10.0.0.5:80",
	} {
		c := &Config{StateDir: t.TempDir(), WebListen: listen}
		c.applyDefaults()
		if err := c.Validate(); err == nil {
			t.Errorf("web_listen %q was accepted, want rejection", listen)
		}
	}
}

func TestLoopbackWebListenIsAccepted(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{
		"127.0.0.1:8710",
		"127.0.0.1:0",
		"localhost:8710",
		"[::1]:8710",
	} {
		c := &Config{StateDir: t.TempDir(), WebListen: listen}
		c.applyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("web_listen %q rejected: %v", listen, err)
		}
	}
}

func TestStateDirMustBeAbsolute(t *testing.T) {
	t.Parallel()
	// A relative state dir would resolve against whatever cwd the service
	// manager happened to hand the process.
	c := &Config{StateDir: "relative/path"}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("relative state_dir was accepted, want rejection")
	}
}

func TestWorkerRoleValidation(t *testing.T) {
	t.Parallel()
	c := &Config{StateDir: t.TempDir()}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Fatalf("default worker roles rejected: %v", err)
	}

	// A supervisor listed as a worker would try to spawn itself, forever.
	c.WorkerRoles = append(c.WorkerRoles, role.Supervisor)
	if err := c.Validate(); err == nil {
		t.Error("supervisor listed as a worker role was accepted, want rejection")
	}
}

// worker_restart_delay is advertised in the config and read by the
// supervisor, so an unparseable value is a startup error rather than a silent
// fallback: a supervisor that ignores the delay restarts workers on a schedule
// the operator never chose, and the only symptom is a crash loop.
func TestWorkerRestartDelayMustBeADuration(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"100", "abc", "2", "1s5", " 2s", "2 s", "2s!"} {
		c := &Config{StateDir: t.TempDir(), WorkerRestartDelay: bad}
		c.applyDefaults()
		err := c.Validate()
		if err == nil {
			t.Errorf("worker_restart_delay %q was accepted, want rejection", bad)
			continue
		}
		// The message has to name the field, or an operator reads "invalid
		// duration" and looks in the wrong place.
		if !strings.Contains(err.Error(), "worker_restart_delay") {
			t.Errorf("worker_restart_delay %q error does not name the field: %v", bad, err)
		}
	}
}

func TestWorkerRestartDelayAccepted(t *testing.T) {
	t.Parallel()
	// Empty means "use the built-in default", which must not be a parse
	// failure: the supervisor resolves the default itself.
	for _, ok := range []string{"", "2s", "500ms", "1m30s", "0s"} {
		c := &Config{StateDir: t.TempDir(), WorkerRestartDelay: ok}
		c.applyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("worker_restart_delay %q rejected: %v", ok, err)
		}
	}
}

// A bad delay must stop the daemon, not be discovered at the first worker
// death, which is when an operator least expects a complaint about their
// config file.
func TestLoadRejectsUnparseableWorkerRestartDelay(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sharza.json")
	body := `{"state_dir": "/tmp/x", "web_listen": "127.0.0.1:1", "worker_restart_delay": "100"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted a worker_restart_delay of \"100\", want error")
	}
}

func TestLoadMissingFileIsAnError(t *testing.T) {
	t.Parallel()
	// Silently falling back to defaults after the user named a specific
	// config is how a daemon ends up managing the wrong directory.
	if _, err := Load(filepath.Join(t.TempDir(), "absent.json")); err == nil {
		t.Error("Load of a missing explicit config = nil, want error")
	}
}

func TestLoadEmptyPathYieldsDefaults(t *testing.T) {
	t.Parallel()
	c, err := Load("")
	if err != nil {
		t.Fatalf("Load(\"\") = %v, want defaults", err)
	}
	if c.StateDir == "" {
		t.Error("defaults have no state dir")
	}
	if c.ConfigPath != "" {
		t.Errorf("ConfigPath = %q, want empty for built-in defaults", c.ConfigPath)
	}
}

func TestLoadReadsConfigAndRecordsPath(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	path := filepath.Join(dir, "sharza.json")
	body := `{
  "state_dir": "/tmp/sharza-test-state",
  "web_listen": "127.0.0.1:9999",
  "worker_roles": ["bt", "g2"],
  "download_dir": "/tmp/sharza-test-dl"
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}

	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if c.StateDir != "/tmp/sharza-test-state" {
		t.Errorf("state_dir = %q", c.StateDir)
	}
	if c.WebListen != "127.0.0.1:9999" {
		t.Errorf("web_listen = %q", c.WebListen)
	}
	if len(c.WorkerRoles) != 2 {
		t.Errorf("worker_roles = %v, want 2 entries", c.WorkerRoles)
	}
	if c.ConfigPath != path {
		t.Errorf("ConfigPath = %q, want %q so workers inherit it", c.ConfigPath, path)
	}
	if c.StatePath() != "/tmp/sharza-test-state/state.json" {
		t.Errorf("StatePath = %q", c.StatePath())
	}
}

// A typo'd key silently ignored leaves the daemon misconfigured, which is
// worse than refusing to start.
func TestLoadRejectsUnknownField(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sharza.json")
	body := `{"state_dir": "/tmp/x", "web_lisen": "127.0.0.1:1"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted an unknown config field, want error")
	}
}

func TestLoadRejectsBadWebListen(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sharza.json")
	body := `{"state_dir": "/tmp/x", "web_listen": "0.0.0.0:8710"}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	if _, err := Load(path); err == nil {
		t.Error("Load accepted a non-loopback web_listen, want error")
	}
}

func TestEnsureDirsCreatesBoth(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	c := &Config{
		StateDir:    filepath.Join(base, "state"),
		DownloadDir: filepath.Join(base, "downloads"),
	}
	c.applyDefaults()
	if err := c.EnsureDirs(); err != nil {
		t.Fatalf("EnsureDirs: %v", err)
	}
	for _, d := range []string{c.StateDir, c.DownloadDir} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Errorf("stat %s: %v", d, err)
			continue
		}
		if !fi.IsDir() {
			t.Errorf("%s is not a directory", d)
		}
		// The state dir holds the user's whole download queue and search
		// history, so it must not be world-readable.
		if perm := fi.Mode().Perm(); perm != 0o700 {
			t.Errorf("%s mode = %04o, want 0700", d, perm)
		}
	}
}
