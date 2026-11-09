// SPDX-License-Identifier: GPL-3.0-or-later

package bt

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/anacrolix/torrent"
)

// freePort asks the kernel for an unused loopback TCP port.
func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestTransmissionOracle(t *testing.T) {
	bin := os.Getenv("TRANSMISSION_BIN")
	if bin == "" {
		t.Skip("TRANSMISSION_BIN is not set; skipping transmission oracle test (a skip is not a pass)")
	}
	info, err := os.Stat(bin)
	if err != nil || info.IsDir() || info.Mode()&0o111 == 0 {
		t.Skipf("TRANSMISSION_BIN=%q is not an executable file; skipping transmission oracle test", bin)
	}

	transmissionCreate := filepath.Join(filepath.Dir(bin), "transmission-create")
	if st, err := os.Stat(transmissionCreate); err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		if p, err := exec.LookPath("transmission-create"); err == nil {
			transmissionCreate = p
		} else {
			t.Skipf("transmission-create not found alongside TRANSMISSION_BIN or on PATH; skipping transmission oracle test")
		}
	}

	// Copy the daemon binary to a fresh path so an AppArmor profile attached to
	// the original location does not confine our loopback-only instance.
	binData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read transmission binary: %v", err)
	}
	daemonBin := filepath.Join(t.TempDir(), "transmission-daemon")
	if err := os.WriteFile(daemonBin, binData, 0o755); err != nil {
		t.Fatalf("stage transmission binary: %v", err)
	}

	seedContent := []byte("hello, transmission oracle\n")
	seedName := "greeting"

	dataDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dataDir, seedName), seedContent, 0o644); err != nil {
		t.Fatal(err)
	}

	watchDir := t.TempDir()
	torrentPath := filepath.Join(watchDir, seedName+".torrent")
	if out, err := exec.Command(transmissionCreate, "-o", torrentPath, filepath.Join(dataDir, seedName)).CombinedOutput(); err != nil {
		t.Fatalf("transmission-create: %v\n%s", err, out)
	}
	torrentBytes, err := os.ReadFile(torrentPath)
	if err != nil {
		t.Fatalf("read torrent: %v", err)
	}

	cfgDir := t.TempDir()
	peerPort := freePort(t)
	rpcPort := freePort(t)

	args := []string{
		"-f",
		"-g", cfgDir,
		"-w", dataDir,
		"-c", watchDir,
		"-i", "127.0.0.1",
		"-I", "::1",
		"-O", "-Y", "-M",
		"-T",
		"-r", "127.0.0.1",
		"-P", strconv.Itoa(peerPort),
		"-p", strconv.Itoa(rpcPort),
		"--no-incomplete-dir",
		"--log-level=error",
	}
	cmd := exec.Command(daemonBin, args...)
	logFile, _ := os.Create(filepath.Join(t.TempDir(), "transmission.log"))
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start transmission-daemon: %v", err)
	}
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
		if logFile != nil {
			logFile.Close()
		}
	})

	// Wait for the daemon to ingest the watched torrent.
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(torrentPath + ".added"); err == nil {
			break
		}
		if _, err := os.Stat(torrentPath); os.IsNotExist(err) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	time.Sleep(1 * time.Second)

	leecherDataDir := t.TempDir()
	leecher, err := New(Options{
		DataDir:         leecherDataDir,
		ListenPort:      0,
		NoDHT:           true,
		DisableTrackers: true,
		Seed:            false,
	})
	if err != nil {
		t.Fatalf("leecher New: %v", err)
	}
	defer leecher.Close()

	lt, err := leecher.AddTorrent(bytes.NewReader(torrentBytes))
	if err != nil {
		t.Fatalf("leecher AddTorrent: %v", err)
	}
	lt.DownloadAll()
	lt.AddPeers([]torrent.PeerInfo{{
		Addr:   &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: peerPort},
		Source: torrent.PeerSourceDirect,
	}})

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	select {
	case <-lt.Complete().On():
	case <-ctx.Done():
		t.Fatalf("leecher did not complete: %v (bytes=%d/%d)", ctx.Err(), lt.BytesCompleted(), lt.Length())
	}

	if got := lt.BytesCompleted(); got != lt.Length() {
		t.Errorf("BytesCompleted=%d, want Length=%d", got, lt.Length())
	}
	if err := lt.VerifyData(); err != nil {
		t.Errorf("VerifyData: %v", err)
	}

	outPath := filepath.Join(leecherDataDir, lt.Name())
	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if !bytes.Equal(data, seedContent) {
		t.Errorf("downloaded bytes = %q, want %q", string(data), string(seedContent))
	}
}
