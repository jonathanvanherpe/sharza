// SPDX-License-Identifier: GPL-3.0-or-later

package gnutella

// DownloadJob is the outcome of Engine.SearchAndDownload: which QUERYHIT
// was chosen, where the bytes landed, and how large the file ended up.
//
// It is deliberately distinct from the transfer-level DownloadResult in
// download.go. That type reports the mechanics of one Fetch call — the
// offset it started at, how many bytes it moved, whether it completed —
// which are of interest to the transfer itself and to a resume-aware job
// store. The job reports what a search caller actually wants to know:
// the hit, the path, the size, and nothing about how the bytes got
// there. A resumed transfer and a clean whole-file transfer both produce
// the same job, and the caller need not learn that one of them resumed.
type DownloadJob struct {
	// Hit is a copy of the QUERYHIT whose file was fetched, taken
	// before the transfer started so the caller holds a stable value
	// regardless of what the network does next. A pointer because
	// QueryHit carries its full Hits slice and the copy is not free;
	// nil only if the job was not created (which is an error path).
	Hit *QueryHit

	// Path is the file written: the hit's sanitised name joined with
	// the directory the caller named. Always inside that directory —
	// the name is reduced to a single path component first, so a
	// hostile QUERYHIT cannot write outside it.
	Path string

	// Size is the completed file's size in bytes — the hit's declared
	// size, which is the only integrity check Gnutella 1 offers. On a
	// resumed transfer it includes the prefix that was already on
	// disk, so the caller sees the whole file's size either way.
	Size int64
}
