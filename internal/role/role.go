// SPDX-License-Identifier: GPL-3.0-or-later

// Package role defines the process roles the daemon can take. A role is fixed
// at process start via --role and is never negotiated at runtime: the
// supervisor spawns workers, and a worker never becomes a supervisor.
package role

import (
	"fmt"
	"sort"
	"strings"
)

// Role is a process role.
type Role string

const (
	// Supervisor owns the RPC endpoint, the store, the scheduler and the
	// web assets. It never opens an outbound protocol connection.
	Supervisor Role = "supervisor"

	// Worker roles own outbound peer traffic and their own network
	// namespace. A worker holds no authoritative state; it reports to the
	// supervisor and dies if it loses the supervisor.
	BT   Role = "bt"
	ED2K Role = "ed2k"
	G2   Role = "g2"
)

// All lists every valid role, in a stable order.
func All() []Role {
	r := []Role{Supervisor, BT, ED2K, G2}
	sort.Slice(r, func(i, j int) bool { return r[i] < r[j] })
	return r
}

// WorkerRoles lists the roles that are spawned as workers.
func WorkerRoles() []Role {
	return []Role{BT, ED2K, G2}
}

// IsWorker reports whether r runs as a spawned worker.
func IsWorker(r Role) bool { return r != Supervisor }

// Parse validates a role string.
func Parse(s string) (Role, error) {
	for _, r := range All() {
		if Role(s) == r {
			return r, nil
		}
	}
	return "", fmt.Errorf("unknown role %q: want one of %s", s, joinRoles())
}

func joinRoles() string {
	rs := All()
	parts := make([]string, 0, len(rs))
	for _, r := range rs {
		parts = append(parts, string(r))
	}
	return strings.Join(parts, ", ")
}
