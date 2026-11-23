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
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/md4"
)

func TestAmuledNetnsOracle(t *testing.T) {
	bin := os.Getenv("AMULED_BIN")
	if bin == "" {
		t.Skip("amuled netns oracle unavailable: AMULED_BIN is not set; skipping (not passing)")
	}
	st, err := os.Stat(bin)
	if err != nil || st.IsDir() || st.Mode()&0o111 == 0 {
		t.Skipf("amuled netns oracle unavailable: AMULED_BIN=%q is not an executable file; skipping (not passing)", bin)
	}

	// Functional probe: creating a network namespace requires root/CAP_SYS_ADMIN
	// and a working `ip netns`. If this fails, skip loudly.
	suffix := fmt.Sprintf("%x", time.Now().UnixNano()&0xfffff)
	probeNs := "sharza-tns-probe-" + suffix
	if err := runNetnsCmd("ip", "netns", "add", probeNs); err != nil {
		t.Skipf("amuled netns oracle unavailable: cannot create network namespace (%v); need root/CAP_SYS_ADMIN and working `ip netns`; skipping (not passing)", err)
	}
	_ = runNetnsCmd("ip", "netns", "delete", probeNs)

	// Stage the binary into a temp dir (avoids AppArmor confinement).
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
	seedContent := []byte("hello, amuled netns oracle seed data for sharza differential test\n")
	seedPath := filepath.Join(incomingDir, "sharzaoracle.bin")
	if err := os.WriteFile(seedPath, seedContent, 0o644); err != nil {
		t.Fatal(err)
	}

	// ---- Create the throwaway namespace with loopback + veth pair ----
	ns := "sharza-tns-" + suffix
	octet := (os.Getpid() % 254) + 1
	hostIP := fmt.Sprintf("10.200.%d.1/24", octet)
	nsIP := fmt.Sprintf("10.200.%d.2/24", octet)
	nsIPBare := fmt.Sprintf("10.200.%d.2", octet)
	hostVeth := "vh" + suffix
	nsVeth := "vn" + suffix

	// Cleanup registration (LIFO: namespace teardown runs after amuled kill).
	t.Cleanup(func() {
		_ = runNetnsCmd("ip", "netns", "delete", ns)
		_ = runNetnsCmd("ip", "link", "delete", hostVeth)
	})

	if err := runNetnsCmd("ip", "netns", "add", ns); err != nil {
		t.Fatalf("create netns: %v", err)
	}
	if err := runNetnsCmd("ip", "netns", "exec", ns, "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatalf("bring up loopback in netns: %v", err)
	}
	if err := runNetnsCmd("ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth); err != nil {
		t.Fatalf("create veth pair: %v", err)
	}
	if err := runNetnsCmd("ip", "link", "set", nsVeth, "netns", ns); err != nil {
		t.Fatalf("move veth into netns: %v", err)
	}
	if err := runNetnsCmd("ip", "addr", "add", hostIP, "dev", hostVeth); err != nil {
		t.Fatalf("assign host veth ip: %v", err)
	}
	if err := runNetnsCmd("ip", "netns", "exec", ns, "ip", "addr", "add", nsIP, "dev", nsVeth); err != nil {
		t.Fatalf("assign netns veth ip: %v", err)
	}
	if err := runNetnsCmd("ip", "link", "set", hostVeth, "up"); err != nil {
		t.Fatalf("bring up host veth: %v", err)
	}
	if err := runNetnsCmd("ip", "netns", "exec", ns, "ip", "link", "set", nsVeth, "up"); err != nil {
		t.Fatalf("bring up netns veth: %v", err)
	}

	// Generate a default config by running amuled once inside the netns.
	genCmd := exec.Command("ip", "netns", "exec", ns, daemonBin, "-c", cfgDir, "-o")
	genCmd.Env = os.Environ()
	_ = genCmd.Run()

	confPath := filepath.Join(cfgDir, "amule.conf")
	confBytes, err := os.ReadFile(confPath)
	if err != nil {
		t.Fatalf("read generated amule.conf: %v", err)
	}
	conf := string(confBytes)

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
	conf = setConfValue(conf, "TempDir", tempDir)
	conf = setConfValue(conf, "IncomingDir", incomingDir)
	conf = setConfValue(conf, "OSDirectory", cfgDir+"/")

	tcpPort := freePortED2K(t)
	udpPort := freePortED2K(t)
	ecPort := freePortED2K(t)
	conf = setConfValue(conf, "Port", strconv.Itoa(tcpPort))
	conf = setConfValue(conf, "UDPPort", strconv.Itoa(udpPort))
	conf = setConfValue(conf, "ECPort", strconv.Itoa(ecPort))
	if err := os.WriteFile(confPath, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	amuledAddr := net.JoinHostPort(nsIPBare, strconv.Itoa(tcpPort))

	// Start amuled inside the netns.
	logFile, _ := os.Create(filepath.Join(t.TempDir(), "amuled.log"))
	cmd := exec.Command("ip", "netns", "exec", ns, daemonBin, "-c", cfgDir, "-o")
	cmd.Env = os.Environ()
	if logFile != nil {
		cmd.Stdout = logFile
		cmd.Stderr = logFile
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start amuled in netns: %v", err)
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

	// Wait for the ed2k listener (reachable from host over veth).
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

	// Run a Sharza Engine against amuled (host namespace, over veth).
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

	buf := &bytes.Buffer{}
	downloader := eng.Downloader(amuledAddr, hash)
	pi, ans, _, n, err := downloader.Fetch(ctx, buf)
	if err != nil {
		t.Fatalf("download from amuled (netns): %v", err)
	}
	t.Logf("peer=%+v answer=%+v bytes=%d", pi, ans, n)

	if n != len(seedContent) {
		t.Errorf("downloaded %d bytes, want %d", n, len(seedContent))
	}
	if !bytes.Equal(buf.Bytes(), seedContent) {
		t.Errorf("downloaded bytes do not match seed")
	}

	// Best-effort: verify any .part.met produced alongside the download.
	for _, root := range []string{cfgDir, tempDir} {
		_ = filepath.Walk(root, func(p string, fi os.FileInfo, werr error) error {
			if werr != nil || fi == nil || fi.IsDir() {
				return nil
			}
			if !strings.HasSuffix(p, ".part.met") {
				return nil
			}
			raw, rerr := os.ReadFile(p)
			if rerr != nil {
				return nil
			}
			pm, perr := ParsePartMet(raw)
			if perr != nil {
				t.Logf("found .part.met %s but could not parse: %v", p, perr)
				return nil
			}
			pmSize, _, _, _, _ := pm.normalized()
			if pmSize != 0 && pmSize != uint64(len(seedContent)) {
				t.Logf(".part.met %s size=%d differs from seed=%d; skipping verify", p, pmSize, len(seedContent))
				return nil
			}
			ok, bad := PartMetVerify(buf.Bytes(), pm)
			t.Logf(".part.met %s: verify=%v bad=%v", p, ok, bad)
			if !ok {
				t.Logf(".part.met verification reported bad parts %v for %s (non-fatal)", bad, p)
			}
			return nil
		})
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

func runNetnsCmd(args ...string) error {
	cmd := exec.Command(args[0], args[1:]...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}
