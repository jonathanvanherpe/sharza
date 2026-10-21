// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// DownloadJob reports one completed search-and-download fused by
// Engine.SearchAndDownload: the QUERYHIT that answered the search, the
// file hit inside it that was fetched, and where the bytes landed.
//
// It is a report, not a handle: the transfer is already finished when a
// DownloadJob is returned, the engine holds no state for it, and
// resuming or re-fetching is another call, exactly like Downloader.Fetch.
type DownloadJob struct {
	// Hit is the QUERYHIT whose answer named the file. It points at a
	// copy of the hit the search collected, not at engine state.
	Hit *QueryHit

	// Path is the file written, always inside the caller's directory.
	Path string

	// Size is the size the QUERYHIT advertised for the file, which is
	// what Fetch verified every declared and received length against.
	Size int64
}
