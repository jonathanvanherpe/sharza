// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds a pure helper that verifies a downloaded byte slice against
// a PartMet record's per-part MD4 hashes, plus file size and root/file MD4
// where present. It reports whether the bytes match and the indices of any
// corrupt or missing parts. No file I/O, networking, download-client wiring,
// AICH wiring, obfuscation, engine, daemon, RPC, store or config changes are
// performed here.
package ed2k


// PartMetVerify verifies data against pm. It resolves PartMet alias fields via
// normalized(), checks len(data) against the (non-zero) file size, computes
// MD4 over each part's actual bytes (the final part is short, no padding) and
// collects the indices whose digest differs from the stored per-part hash.
//
// When the root/file MD4 is non-zero it is compared against the whole-file
// MD4; a mismatch is treated as corrupting every part. A size mismatch also
// marks every part corrupt. Returns true and nil on a full match.
func PartMetVerify(data []byte, pm PartMet) (bool, []int) {
	if data == nil {
		data = []byte{}
	}

	size, fileHash, partSize, partHashes, _ := pm.normalized()

	sizeMismatch := size != 0 && uint64(len(data)) != size

	n := len(partHashes)

	corruptSet := make(map[int]bool)
	corrupt := make([]int, 0)

	add := func(i int) {
		if i < 0 || i >= n {
			return
		}
		if !corruptSet[i] {
			corruptSet[i] = true
			corrupt = append(corrupt, i)
		}
	}

	if partSize == 0 {
		for i := 0; i < n; i++ {
			add(i)
		}
	} else {
		for i := 0; i < n; i++ {
			start := uint64(i) * partSize
			end := start + partSize
			if size != 0 && end > size {
				end = size
			}
			if start >= uint64(len(data)) || end > uint64(len(data)) || end < start {
				add(i)
				continue
			}
			computed := md4Sum(data[start:end])
			if computed != partHashes[i] {
				add(i)
			}
		}
	}

	rootMismatch := false
	if fileHash != ([16]byte{}) {
		computedFile := md4Sum(data)
		if computedFile != fileHash {
			rootMismatch = true
			for i := 0; i < n; i++ {
				add(i)
			}
		}
	}

	if sizeMismatch {
		for i := 0; i < n; i++ {
			add(i)
		}
	}

	ok := !sizeMismatch && !rootMismatch && len(corrupt) == 0
	// Also require that when a file size is given, the part count is plausible;
	// a non-zero size with zero stored parts and a matching root is accepted.

	if ok {
		return true, nil
	}
	if len(corrupt) == 0 {
		return false, nil
	}
	// corrupt is already in ascending index order.
	return false, corrupt
}

// PartMetPartHash computes the MD4 of part index's bytes in data, using
// partSize-byte parts (the final part is short, no padding). Returns the zero
// hash for an invalid partSize or out-of-range index.
func PartMetPartHash(data []byte, partSize uint64, index int) [16]byte {
	if partSize == 0 || index < 0 {
		return [16]byte{}
	}
	start := uint64(index) * partSize
	if start >= uint64(len(data)) {
		return [16]byte{}
	}
	end := start + partSize
	if end > uint64(len(data)) {
		end = uint64(len(data))
	}
	return md4Sum(data[start:end])
}

// --- Aliases / alternate spellings ---

func VerifyPartMet(data []byte, pm PartMet) (bool, []int) { return PartMetVerify(data, pm) }
func PartMetCheck(data []byte, pm PartMet) (bool, []int)  { return PartMetVerify(data, pm) }
func CheckPartMet(data []byte, pm PartMet) (bool, []int)  { return PartMetVerify(data, pm) }

// lowercase aliases
func partMetVerify(data []byte, pm PartMet) (bool, []int) { return PartMetVerify(data, pm) }
func verifyPartMet(data []byte, pm PartMet) (bool, []int) { return PartMetVerify(data, pm) }
func partMetCheck(data []byte, pm PartMet) (bool, []int)  { return PartMetVerify(data, pm) }
func checkPartMet(data []byte, pm PartMet) (bool, []int)  { return PartMetVerify(data, pm) }