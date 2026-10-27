// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// DownloadJob is the search-caller view of a finished transfer: the
// QUERYHIT that supplied the source, the path written, and the size the
// hit advertised. It is distinct from the transfer-level DownloadResult,
// which carries resume/offset detail the search layer does not need.
type DownloadJob struct {
	// Hit is the QUERYHIT that supplied the source for the transfer.
	// It is a copy, owned by the caller.
	Hit *QueryHit

	// Path is the file written, always inside the caller's directory.
	Path string

	// Size is the number of bytes the hit advertised and the transfer
	// verified against.
	Size int64
}