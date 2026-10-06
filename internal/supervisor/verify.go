// SPDX-License-Identifier: GPL-3.0-or-later

package supervisor

import "strings"

// allSourcesHashed reports whether every URI carries a content hash, which is
// the precondition for calling a job verified.
//
// This is deliberately conservative and scheme-based. The alternative, trusting
// a client-supplied flag, lets any client claim verification for a job that
// cannot be verified, and that claim is what the UI shows the user. A false
// negative here is harmless: the job is simply shown as unverified. A false
// positive is a silent integrity guarantee.
//
// Recognised as content-addressed:
//
//	magnet:?xt=urn:btih:...        BitTorrent info hash
//	bitinfohash:...                the same, other spellings
//	urn:btih:...                   bare BitTorrent URN
//	ed2k://|file|...               eDonkey file hash in the name
//
// Recognised as NOT content-addressed, and therefore always unverified:
//
//	g2://, gnutella://, g1://       Gnutella has no content addressing at all
func allSourcesHashed(uris []string) bool {
	if len(uris) == 0 {
		return false
	}
	for _, u := range uris {
		if !uriHashed(u) {
			return false
		}
	}
	return true
}

func uriHashed(u string) bool {
	l := strings.ToLower(strings.TrimSpace(u))
	switch {
	case strings.HasPrefix(l, "magnet:"):
		return strings.Contains(l, "xt=urn:btih:") ||
			strings.Contains(l, "xt=urn:btmh:")
	case strings.HasPrefix(l, "bitinfohash:"):
		return true
	case strings.HasPrefix(l, "urn:btih:"), strings.HasPrefix(l, "urn:btmh:"):
		return true
	case strings.HasPrefix(l, "ed2k://"):
		// The ed2k hash lives in the file part of the URL.
		return strings.Contains(l, "|file|")
	case strings.HasPrefix(l, "http://"), strings.HasPrefix(l, "https://"):
		// A bare HTTP source is a whole-file fetch with no integrity
		// guarantee unless it points at a .torrent, whose hash the
		// BitTorrent engine will verify for itself.
		return strings.HasSuffix(l, ".torrent")
	default:
		return false
	}
}
