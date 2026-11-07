// SPDX-License-Identifier: GPL-3.0-or-later

// Package netns prepares the Linux network namespace Sharza's workers run
// inside when VPN isolation is in use.
//
// The daemon itself never requires privilege: it stays in the root
// namespace and spawns workers, which systemd places into the prepared
// namespace via NetworkNamespacePath=. This package holds the privileged
// preparation logic, kept separate so the daemon's unprivileged code path
// never imports it transitively.
//
// Prepare needs CAP_SYS_ADMIN (or root) and is expected to be invoked by
// the privileged sharzad-vpn-netns.service unit, not by the daemon. On a
// host without that capability it returns an error and callers must skip
// loudly rather than silently.
package netns

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// DefaultNetnsPath is where the VPN namespace is expected to live. It
// matches the path referenced by the worker drop-in and by Vopono's own
// namespace convention.
const DefaultNetnsPath = "/run/netns/sharza-vpn"

// DropIn returns the contents of the systemd drop-in that places a worker
// into the namespace at path. It is a pure function so it can be tested
// and rendered without touching the system.
func DropIn(path string) string {
	if path == "" {
		path = DefaultNetnsPath
	}
	return "[Service]\n" +
		"NetworkNamespacePath=" + path + "\n"
}

// ValidatePath checks that path is an absolute, non-empty filesystem path
// suitable for use as a network namespace bind mount. It does not check
// that the namespace exists.
func ValidatePath(path string) error {
	if path == "" {
		return fmt.Errorf("netns: path is empty")
	}
	if !filepath.IsAbs(path) {
		return fmt.Errorf("netns: path %q is not absolute", path)
	}
	if strings.ContainsRune(path, '\x00') {
		return fmt.Errorf("netns: path %q contains a NUL byte", path)
	}
	return nil
}

// Prepare creates the namespace bind mount at path. It requires privilege
// (CAP_SYS_ADMIN). On success the namespace exists and is ready for a
// Vopono-managed tun device to be moved into it; this function does not
// create interfaces or routes, those belong to Vopono.
//
// Prepare is idempotent: an existing namespace at path is left alone.
func Prepare(path string) error {
	if err := ValidatePath(path); err != nil {
		return err
	}
	if path == "" {
		path = DefaultNetnsPath
	}

	// The namespace directory must exist before we can bind-mount into it.
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("netns: create parent of %s: %w", path, err)
	}

	// Check whether the namespace already exists; if so, nothing to do.
	if _, err := os.Stat(path); err == nil {
		return nil
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("netns: stat %s: %w", path, err)
	}

	// Creating a new network namespace requires CAP_SYS_ADMIN. We shell
	// out to iproute2's `ip netns add` so the daemon binary stays free of
	// cgo and privileged syscalls in its own process, and so the same
	// code path is what the sharzad-vpn-netns.service unit runs.
	name := filepath.Base(path)
	cmd := exec.Command("ip", "netns", "add", name)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("netns: ip netns add %s: %w: %s "+
			"(privileged helper must run as root)", name, err, strings.TrimSpace(string(out)))
	}
	return nil
}