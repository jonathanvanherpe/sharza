// SPDX-License-Identifier: GPL-3.0-or-later

package version

// Build metadata. These are overridden at link time with
// -ldflags "-X github.com/jonathanvanherpe/sharza/internal/version.Version=..."
var (
	Version = "0.0.0-dev"
	Commit  = "unknown"
)

// UserAgent is the identifier sent to peers. Protocol networks care that this
// is stable and identifiable, so it must never be blank.
func UserAgent() string {
	return "Sharza/" + Version
}
