// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// DownloadJob is the search-caller view of a finished search-and-download:
// the QUERYHIT that was selected and what the transfer left on disk. It is
// distinct from the transfer-level DownloadResult, which carries resume and
// completion detail.
type DownloadJob struct {
	// Hit is the QUERYHIT the search selected.
	Hit *QueryHit

	// Path is the file written, inside the directory the caller passed.
	Path string

	// Size is the size of the file on disk after the transfer.
	Size int64
}