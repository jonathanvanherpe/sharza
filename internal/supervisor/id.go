// SPDX-License-Identifier: GPL-3.0-or-later

package supervisor

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"strconv"
	"time"
)

// NewJobID generates a job id.
//
// The id is opaque and not a content hash: the same file added twice is two
// jobs, because the user asked for two downloads. Time plus randomness keeps
// ids sortable and collision-free without a central allocator.
func NewJobID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand failing means the machine has no entropy source,
		// which is worth surfacing loudly rather than silently degrading
		// to a guessable id.
		panic("supervisor: crypto/rand unavailable: " + err.Error())
	}
	return "j-" + strconv.FormatInt(time.Now().Unix(), 36) + "-" + hex.EncodeToString(b[:])
}

func selfPID() int { return os.Getpid() }
