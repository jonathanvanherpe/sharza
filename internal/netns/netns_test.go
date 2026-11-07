// SPDX-License-Identifier: GPL-3.0-or-later

package netns

import (
	"os"
	"os/exec"
	"runtime"
	"strings"
	"testing"
)

func TestDropInContainsNetworkNamespacePath(t *testing.T) {
	got := DropIn("/run/netns/sharza-vpn")
	if !strings.Contains(got, "NetworkNamespacePath=/run/netns/sharza-vpn") {
		t.Fatalf("DropIn missing NetworkNamespacePath: %q", got)
	}
	if !strings.HasPrefix(got, "[Service]") {
		t.Fatalf("DropIn missing [Service] header: %q", got)
	}
}

func TestDropInDefaultPath(t *testing.T) {
	got := DropIn("")
	if !strings.Contains(got, "NetworkNamespacePath="+DefaultNetnsPath) {
		t.Fatalf("DropIn default path wrong: %q", got)
	}
}

func TestValidatePath(t *testing.T) {
	cases := []struct {
		path string
		ok   bool
	}{
		{"/run/netns/sharza-vpn", true},
		{"", false},
		{"relative/path", false},
		{"/run/netns/x", true},
	}
	for _, c := range cases {
		err := ValidatePath(c.path)
		if c.ok && err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", c.path, err)
		}
		if !c.ok && err == nil {
			t.Errorf("ValidatePath(%q) = nil, want error", c.path)
		}
	}
}

func TestPrepareSkipsWithoutPrivilege(t *testing.T) {
	// Prepare needs CAP_SYS_ADMIN. On this host we are not root, so it must
	// fail loudly rather than silently succeed or panic.
	if os.Geteuid() == 0 {
		t.Skip("running as root; privilege check not applicable")
	}
	// Also skip if ip(8) is missing entirely.
	if _, err := exec.LookPath("ip"); err != nil {
		t.Skip("ip(8) not installed; cannot exercise Prepare")
	}
	err := Prepare("/tmp/opencode/netns-test-does-not-exist")
	if err == nil {
		t.Fatal("Prepare succeeded without privilege; expected an error")
	}
	_ = runtime.GOOS
}