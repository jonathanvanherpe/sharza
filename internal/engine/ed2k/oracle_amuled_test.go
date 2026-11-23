// SPDX-License-Identifier: GPL-3.0-or-later

package ed2k

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"golang.org/x/crypto/md4"
)

// freePort asks the kernel for an unused loopback TCP port.
func freePortED2K(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freePort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func TestAmuledOracle(t *testing.T) {
	bin := os.Getenv("AMULED_BIN")
	if bin == "" {
		t.Skip("amuled oracle unavailable: AMULED_BIN is not set; skipping (not passing)")
	}
	st, err := os.Stat(bin)
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		t.Skipf("amuled oracle unavailable: AMULED_BIN=%q is not an executable file; skipping (not passing)", bin)
	}

	// Stage the binary into a temp dir so an AppArmor profile attached to
	// the original location does not confine our loopback-only instance.
	binData, err := os.ReadFile(bin)
	if err != nil {
		t.Fatalf("read amuled binary: %v", err)
	}
	daemonBin := filepath.Join(t.TempDir(), "amuled")
	if err := os.WriteFile(daemonBin, binData, 0o755); err != nil {
		t.Fatalf("stage amuled binary: %v", err)
	}

	// Prepare isolated config/share dirs.
	cfgDir := t.TempDir()
	incomingDir := filepath.Join(cfgDir, "Incoming")
	tempDir := filepath.Join(cfgDir, "Temp")
	if err := os.MkdirAll(incomingDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(tempDir, 0o755); err != nil {
		t.Fatal(err)
	}

	// Seed a known file.
	seedContent := []byte("hello, amuled oracle seed data for sharza differential test\n")
	seedName := "sharzaoracle.bin"
	seedPath := filepath.Join(incomingDir, seedName)
	if err := os.WriteFile(seedPath, seedContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// Generate a default config by running amuled once (it exits because
	// external connections are disabled in the default config).
	genCmd := exec.Command(daemonBin, "-c", cfgDir, "-o")
	genCmd.Env = os.Environ()
	_ = genCmd.Run()

	// Locate the generated config.
	confPath := filepath.Join(cfgDir, "amule.conf")
	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read generated amule.conf: %v", err)
	}
	conf := string(confBytes)

	// Patch config for an isolated, loopback-only instance.
	pwHash := "5ebe2294ecd0e0f08eab7690d2a6ee69" // md5("secret")
	repls := map[string]string{
		"AcceptExternalConnections=0": "AcceptExternalConnections=1",
		"ECPassword=":                "ECPassword=" + pwHash,
		"ConnectToED2K=1":             "ConnectToED2K=0",
		"ConnectToKad=1":              "ConnectToKad=0",
		"FilterLanIPs=1":              "FilterLanIPs=0",
	}
	for old, neu := range repls {
		conf = replaceFirst(conf, old, neu)
	}
	// Point dirs at our isolated locations.
	conf = setConfValue(conf, "TempDir", tempDir)
	conf = setConfValue(conf, "IncomingDir", incomingDir)
	conf = setConfValue(conf, "OSDirectory", cfgDir+"/")
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	// Free ports.
	tcpPort := freePortED2K(t)
	udpPort := freePortED2K(t)
	ecPort := freePortED2K(t)
	conf = setConfValue(conf, "Port", strconv.Itoa(tcpPort))
	conf = setConfValue(conf, "UDPPort", strconv.Itoa(udpPort))
	conf = setConfValue(conf, "ECPort", strconv.Itoa(ecPort))
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	amuledAddr := fmt.Sprintf("127.0.0.1:%d", tcpPort)

	// Start amuled.
	logFile, _ := os.Create(filepath.Join(t.TempDir(), "amuled.log"))
	cmd := exec.Command(daemonBin, "-c", cfgDir, "-o")
	cmd.Env = os.Environ()
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start amuled: %v", err)
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

	// Wait for the ed2k listener.
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		c, err := net.DialTimeout("tcp", amuledAddr, 500*time.Millisecond)
		if err == nil {
			_ = c.Close()
			break
		}
		time.Sleep(250 * time.Millisecond)
		if time.Now().After(deadline) {
			t.Fatalf("amuled did not start listening on %s", amuledAddr)
		}
	}

	// Wait for amuled to hash the seeded file.
	hashDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(hashDeadline) {
		data, err := os.ReadFile(filepath.Join(cfgDir, "known.met"))
		if err == nil && len(data) > 5 {
			break
		}
		time.Sleep(1 * time.Second)
	}

	// Compute the ed2k (MD4) file hash.
	h := md4.New()
	h.Write(seedContent)
	fileHash := h.Sum(nil)
	var hash [16]byte
	copy(hash[:], fileHash)

	// Run a Sharza Engine against amuled.
	eng := New()
	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()
	engCtx, engCancel := context.WithCancel(ctx)
	defer engCancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- eng.Run(engCtx, Options{
			Servers: []string{amuledAddr},
			Logf:    t.Logf,
		})
	}()
	select {
	case <-eng.Ready():
	case <-time.After(10 * time.Second):
		t.Fatal("engine did not become ready")
	}

	// Download the seeded file from amuled.
	buf := &bytes.Buffer{}
	downloader := eng.Downloader(amuledAddr, hash)
	pi, ans, _, n, err := downloader.Fetch(ctx, buf)
	if err != nil {
		t.Fatalf("download from amuled: %v", err)
	}
	t.Logf("peer=%+v answer=%+v bytes=%d", pi, ans, n)

	if n != len(seedContent) {
		t.Errorf("downloaded %d bytes, want %d", n, len(seedContent))
	}
	if !bytes.Equal(buf.Bytes(), seedContent) {
		t.Errorf("downloaded bytes do not match seed")
	}


	engCancel()
	select {
	case err := <-errCh:
		if err != nil && ctx.Err() == nil {
			t.Errorf("engine Run returned %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Error("engine did not stop")
	}
}

// helpers
func replaceFirst(s, old, neu string) string {
	i := indexOf(s, old)
	if i < 0 {
		return s
	}
	return s[:i] + neu + s[i+len(old):]
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

func setConfValue(conf, key, val string) string {
	lines := splitLines(conf)
	out := make([]string, 0, len(lines))
	found := false
	prefix := key + "="
	for _, ln := range lines {
		if startsWith(ln, prefix) {
			out = append(out, prefix+val)
			found = true
		} else {
			out = append(out, ln)
		}
	}
	if !found {
		out = append(out, prefix+val)
	}
	return joinLines(out)
}

func splitLines(s string) []string {
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

func joinLines(lines []string) string {
	return join(lines, "\n")
}

func join(elems []string, sep string) string {
	if len(elems) == 0 {
		return ""
	}
	out := elems[0]
	for i := 1; i < len(elems); i++ {
		out += sep + elems[i]
	}
	return out
}

func startsWith(s, prefix string) bool {
	return len(s) >= len(prefix) && s[:len(prefix)] == prefix
}
