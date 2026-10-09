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

// web_expose is the deliberate, off-by-default escape hatch for a desktop or
// CLI client on another machine. The security control is that it has to be
// asked for: the refusal test above pins that not asking is refused, and the
// test below pins that asking works.
func TestExposedWebListenAcceptsNonLoopback(t *testing.T) {
	t.Parallel()
	for _, listen := range []string{
		"0.0.0.0:6347",
		":6347",
		"192.168.1.10:6347",
		"[::]:6347",
		"example.org:6347",
	} {
		c := &Config{StateDir: t.TempDir(), WebListen: listen, ExposeWeb: true}
		c.applyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("web_listen %q with web_expose rejected: %v", listen, err)
		}
	}
}

// Expose only permits a non-loopback bind; it must not require one.
func TestExposedWebListenStillAcceptsLoopback(t *testing.T) {
	t.Parallel()
	c := &Config{StateDir: t.TempDir(), WebListen: "127.0.0.1:6347", ExposeWeb: true}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		t.Errorf("loopback web_listen with web_expose rejected: %v", err)
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
	for _, ok := range []string{"", "2s", "500ms", "1m30s", "1ns"} {
		c := &Config{StateDir: t.TempDir(), WorkerRestartDelay: ok}
		c.applyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("worker_restart_delay %q rejected: %v", ok, err)
		}
	}
}

// A zero or negative delay parses fine and is still wrong: it configures the
// immediate respawn that the delay exists to prevent, turning a worker that
// fails at startup into a busy loop. Rejecting it is not a style preference.
func TestWorkerRestartDelayMustBePositive(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"0s", "0", "-1s", "-500ms"} {
		c := &Config{StateDir: t.TempDir(), WorkerRestartDelay: bad}
		c.applyDefaults()
		err := c.Validate()
		if err == nil {
			t.Errorf("worker_restart_delay %q was accepted, want rejection", bad)
			continue
		}
		if !strings.Contains(err.Error(), "worker_restart_delay") {
			t.Errorf("worker_restart_delay %q error does not name the field: %v", bad, err)
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
	// The default web listen sits one above the Gnutella/Gnutella2 port
	// (6346) and stays on the loopback interface. Pinning it here means a
	// rename cannot silently move the UI port again.
	if c.WebListen != "127.0.0.1:6347" {
		t.Errorf("default web_listen = %q, want 127.0.0.1:6347", c.WebListen)
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

// The Gnutella engine is new, so it must be off unless explicitly asked
// for: a worker that silently does nothing while looking enabled is how
// a P2P daemon ships a hole.
func TestGnutellaDefaultsToDisabled(t *testing.T) {
	t.Parallel()
	c := Default()
	if c.GnutellaEnabled {
		t.Error("Default().GnutellaEnabled = true, want false")
	}
	if c.GnutellaListen != "0.0.0.0:6346" {
		t.Errorf("default gnutella_listen = %q, want 0.0.0.0:6346", c.GnutellaListen)
	}
	if len(c.GnutellaPeers) != 0 {
		t.Errorf("default gnutella_peers = %v, want empty", c.GnutellaPeers)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("Default().Validate() = %v, want nil", err)
	}
}

func TestGnutellaListenValidation(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{
		"0.0.0.0:6346",
		"127.0.0.1:0",
		":6346",
		"localhost:6346",
		"[::1]:6346",
	} {
		c := &Config{StateDir: t.TempDir(), GnutellaListen: ok}
		c.applyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("gnutella_listen %q rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"6346",          // no host part
		"1.2.3.4",       // no port
		"1.2.3.4:99999", // port out of range
		"1.2.3.4:http",  // non-numeric port
		"1.2.3.4:-5",    // negative port
	} {
		c := &Config{StateDir: t.TempDir(), GnutellaListen: bad}
		c.applyDefaults()
		err := c.Validate()
		if err == nil {
			t.Errorf("gnutella_listen %q was accepted, want rejection", bad)
			continue
		}
		if !strings.Contains(err.Error(), "gnutella_listen") {
			t.Errorf("gnutella_listen %q error does not name the field: %v", bad, err)
		}
	}
}

// A peer address without a host is unusable: the engine would dial
// ":6346" and fail forever.
func TestGnutellaPeersValidation(t *testing.T) {
	t.Parallel()
	for _, ok := range []string{"127.0.0.1:6346", "oracle.example.org:6346", "[::1]:6346"} {
		c := &Config{StateDir: t.TempDir(), GnutellaPeers: []string{ok}}
		c.applyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("gnutella_peers [%q] rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{":6346", "1.2.3.4", "127.0.0.1:70000"} {
		c := &Config{StateDir: t.TempDir(), GnutellaPeers: []string{bad}}
		c.applyDefaults()
		err := c.Validate()
		if err == nil {
			t.Errorf("gnutella_peers [%q] was accepted, want rejection", bad)
			continue
		}
		if !strings.Contains(err.Error(), "gnutella_peers") {
			t.Errorf("gnutella_peers [%q] error does not name the field: %v", bad, err)
		}
	}
}

// Validation runs while the engine is disabled too: flipping
// gnutella_enabled later must not turn a running daemon's worker into a
// crash-at-startup loop over a typo.
func TestGnutellaAddressesValidatedWhileDisabled(t *testing.T) {
	t.Parallel()
	c := &Config{StateDir: t.TempDir(), GnutellaListen: "127.0.0.1:notaport", GnutellaPeers: []string{"nohost:6346"}}
	c.applyDefaults()
	if err := c.Validate(); err == nil {
		t.Error("bad gnutella addresses accepted with gnutella_enabled false, want rejection")
	}
}

func TestLoadReadsGnutellaSettings(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sharza.json")
	body := `{
  "state_dir": "/tmp/sharza-test-state",
  "gnutella_enabled": true,
  "gnutella_listen": "127.0.0.1:6348",
  "gnutella_peers": ["127.0.0.1:6346", "10.0.0.9:6346"]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !c.GnutellaEnabled {
		t.Error("gnutella_enabled = false, want true")
	}
	if c.GnutellaListen != "127.0.0.1:6348" {
		t.Errorf("gnutella_listen = %q, want 127.0.0.1:6348", c.GnutellaListen)
	}
	if len(c.GnutellaPeers) != 2 || c.GnutellaPeers[1] != "10.0.0.9:6346" {
		t.Errorf("gnutella_peers = %v, want both addresses", c.GnutellaPeers)
	}
}

// A webcache URL that is not an http(s) URL with a host would fail at
// the engine's first fetch, so it is caught here like gnutella_peers
// is: even while the engine is disabled.
func TestGnutellaCachesValidation(t *testing.T) {
	t.Parallel()
	if n := len(Default().GnutellaCaches); n != 0 {
		t.Errorf("default gnutella_caches = %d entries, want none (no surprise network I/O)", n)
	}
	for _, ok := range []string{
		"http://dkac.trillinux.org/",
		"https://gweb3.4octets.co.uk/gwebcache/gwebcache2.php",
		"http://midian.jayl.de/g2/gwc.php?foo=bar",
	} {
		c := &Config{StateDir: t.TempDir(), GnutellaCaches: []string{ok}}
		c.applyDefaults()
		if err := c.Validate(); err != nil {
			t.Errorf("gnutella_caches [%q] rejected: %v", ok, err)
		}
	}
	for _, bad := range []string{
		"",
		"example.org/gwc.php", // no scheme
		"ftp://example.org/gwc.php",
		"http://", // no host
	} {
		c := &Config{StateDir: t.TempDir(), GnutellaCaches: []string{bad}}
		c.applyDefaults()
		err := c.Validate()
		if err == nil {
			t.Errorf("gnutella_caches [%q] was accepted, want rejection", bad)
			continue
		}
		if !strings.Contains(err.Error(), "gnutella_caches") {
			t.Errorf("gnutella_caches [%q] error does not name the field: %v", bad, err)
		}
	}
}

// The JSON key must round-trip: Load uses DisallowUnknownFields, so a
// stale tag would reject a config file that spells the key correctly.
func TestLoadReadsGnutellaCaches(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "sharza.json")
	body := `{
  "state_dir": "/tmp/sharza-test-state",
  "gnutella_caches": ["http://cache.example.org/gwc.php"]
}`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(c.GnutellaCaches) != 1 || c.GnutellaCaches[0] != "http://cache.example.org/gwc.php" {
		t.Errorf("gnutella_caches = %v, want the one URL", c.GnutellaCaches)
	}
}
