// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// TestGTK_GnutellaOracle is the opt-in differential check for the P1 exit
// gate: a controlled local search+download exchange against a real
// gtk-gnutella instance. It is skipped loudly unless GTK_GNUTELLA_BIN
// points at an executable gtk-gnutella binary. A skip is not a pass.

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestGTK_GnutellaOracle(t *testing.T) {
	bin := os.Getenv("GTK_GNUTELLA_BIN")
	if bin == "" {
		t.Skip("gtk-gnutella oracle unavailable: GTK_GNUTELLA_BIN is not set; skipping (not passing)")
	}
	st, err := os.Stat(bin)
	if err != nil || st.IsDir() || st.Mode()&0111 == 0 {
		t.Skipf("gtk-gnutella oracle unavailable: GTK_GNUTELLA_BIN=%q is not an executable file; skipping (not passing)", bin)
	}

	const gtkPort = 6346
	content := testContent(1234)

	// Isolated config/share dirs so the oracle never touches a public swarm.
	configDir := t.TempDir()
	shareDir := filepath.Join(configDir, "share")
	if err := os.MkdirAll(shareDir, 0o755); err != nil {
		t.Fatalf("mkdir share dir: %v", err)
	}
	seedPath := filepath.Join(shareDir, "sharzaoracle.bin")
	if err := os.WriteFile(seedPath, content, 0o644); err != nil {
		t.Fatalf("write seed file: %v", err)
	}

	// Minimal config: loopback listener, one shared directory, no outbound
	// ultrapeer connections (so no public swarm is contacted).
	configPath := filepath.Join(configDir, "config_gnet")
	cfg := fmt.Sprintf("listen_port = %d\nshared_dirs_paths = %s\nscan_extensions = --all--\nonline_mode = 0\nmax_ultrapeers = 0\nmax_connections = 8\n", gtkPort, shareDir)
	if err := os.WriteFile(configPath, []byte(cfg), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}

	logFile, _ := os.Create(filepath.Join(configDir, "gtkg.log"))
	cmd := exec.Command(bin, "--topless", "--no-supervise", "--no-restart")
	cmd.Env = append(os.Environ(), "GTK_GNUTELLA_DIR="+configDir)
	cmd.Stdout = logFile
	cmd.Stderr = logFile
	if err := cmd.Start(); err != nil {
		t.Fatalf("start gtk-gnutella: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
		_ = logFile.Close()
	})

	// Wait for the listener to come up.
	deadline := time.Now().Add(15 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", gtkPort), 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("gtk-gnutella did not start listening on %d", gtkPort)
		}
		time.Sleep(250 * time.Millisecond)
	}
	// Give the library scan a moment to index the seeded file.
	time.Sleep(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	// Searcher engine dials the local gtk-gnutella instance.
	eng, cancelEng := startEngine(t, Options{
		KeepAliveInterval: time.Hour,
		IdleTimeout:       10 * time.Second,
		SearchTimeout:     5 * time.Second,
		Peers:             []string{fmt.Sprintf("127.0.0.1:%d", gtkPort)},
	})
	defer cancelEng()

	waitForPeers(t, eng, 1)
	time.Sleep(500 * time.Millisecond)

	hits, err := eng.Search("sharzaoracle")
	if err != nil {
		t.Fatalf("Search: %v", err)
	}
	if len(hits) == 0 {
		t.Fatal("Search returned no hits from gtk-gnutella")
	}
	qh := hits[0]
	if len(qh.Hits) == 0 {
		t.Fatalf("hit %+v has no file hits", qh)
	}
	hit := qh.Hits[0]
	if hit.FileSize != uint32(len(content)) {
		t.Fatalf("hit size = %d, want %d", hit.FileSize, len(content))
	}

	// gtk-gnutella advertises its own listen address in the hit.
	if qh.Port != gtkPort {
		// Some builds report a different port; trust the hit's address
		// but it must still be loopback.
		if !net.IP(qh.IP[:]).IsLoopback() {
			t.Fatalf("hit source %s is not loopback", net.JoinHostPort(net.IP(qh.IP[:]).String(), fmt.Sprintf("%d", qh.Port)))
		}
	}

	destDir := t.TempDir()
	res, err := eng.Downloader(qh, hit).Fetch(ctx, destDir)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if res.Bytes != int64(len(content)) {
		t.Errorf("result bytes = %d, want %d", res.Bytes, len(content))
	}
	onDisk, err := os.ReadFile(res.Path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(onDisk, content) {
		t.Errorf("downloaded file (%d bytes) does not match source (%d bytes)", len(onDisk), len(content))
	}
	if fi, err := os.Stat(res.Path); err != nil || fi.Size() != int64(len(content)) {
		t.Errorf("on-disk size = %d, want %d", fi.Size(), len(content))
	}
}
