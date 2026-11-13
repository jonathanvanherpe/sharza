// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds AICH (Advanced Intelligent Corruption Handling) verification.
// AICH is a binary Merkle tree over fixed-size blocks of a file's bytes, using
// MD4 as the hash function. AICHRoot computes the root hash of such a tree for
// a byte slice; AICHVerify recomputes it and compares against a trusted root,
// reporting the block indices it considers corrupt when they disagree.
//
// No networking, file I/O, obfuscation, .part.met parsing, range mapping or
// canonical-block integration is performed here. This is a pure hashing helper.
package ed2k

import (
	"golang.org/x/crypto/md4"
)

// AICHBlockSize is eDonkey's default AICH block size: 180 KiB.
const AICHBlockSize = 180 * 1024

// md4Sum returns the MD4 digest of b.
func md4Sum(b []byte) [16]byte {
	h := md4.New()
	_, _ = h.Write(b)
	var out [16]byte
	copy(out[:], h.Sum(nil))
	return out
}

// AICHLeafCount returns the number of AICH blocks (leaves) covering dataLen
// bytes at the given block size. Returns 0 for empty input or an invalid
// (zero) block size.
func AICHLeafCount(dataLen int, blockSize uint64) int {
	if blockSize == 0 || dataLen <= 0 {
		return 0
	}
	bs := int(blockSize)
	return (dataLen + bs - 1) / bs
}

// aichLeafCount is an unexported alias for AICHLeafCount.
func aichLeafCount(dataLen int, blockSize uint64) int { return AICHLeafCount(dataLen, blockSize) }

// AICHDepth returns the height (number of reduction levels above the leaves)
// of the AICH Merkle tree for dataLen bytes at the given block size. Returns 0
// for empty input or an invalid block size. A single block has depth 0.
func AICHDepth(dataLen int, blockSize uint64) int {
	n := AICHLeafCount(dataLen, blockSize)
	if n == 0 {
		return 0
	}
	depth := 0
	for n > 1 {
		n = (n + 1) / 2
		depth++
	}
	return depth
}

// aichDepth is an unexported alias for AICHDepth.
func aichDepth(dataLen int, blockSize uint64) int { return AICHDepth(dataLen, blockSize) }

// AICHRoot computes eDonkey's AICH Merkle root (MD4) over data, using
// blockSize-byte blocks. The final (short) block is zero-padded up to
// blockSize before hashing. Returns the zero hash for empty input or an
// invalid (zero) block size.
func AICHRoot(data []byte, blockSize uint64) [16]byte {
	if blockSize == 0 {
		return [16]byte{}
	}
	n := AICHLeafCount(len(data), blockSize)
	if n == 0 {
		return [16]byte{}
	}
	leaves := make([][16]byte, n)
	bs := int(blockSize)
	for i := 0; i < n; i++ {
		block := make([]byte, bs)
		start := i * bs
		end := start + bs
		if end > len(data) {
			end = len(data)
		}
		copy(block, data[start:end])
		leaves[i] = md4Sum(block)
	}
	level := leaves
	for len(level) > 1 {
		next := make([][16]byte, 0, (len(level)+1)/2)
		for i := 0; i < len(level); i += 2 {
			if i+1 < len(level) {
				buf := make([]byte, 0, 32)
				buf = append(buf, level[i][:]...)
				buf = append(buf, level[i+1][:]...)
				next = append(next, md4Sum(buf))
			} else {
				// Odd trailing node is promoted unchanged.
				next = append(next, level[i])
			}
		}
		level = next
	}
	return level[0]
}

// AICHVerify recomputes the AICH root of data at blockSize and compares it
// against the trusted root. It reports ok=true (and a nil corrupt slice) when
// they match. When they differ it reports ok=false and the indices of every
// block as suspect: the root alone cannot localize which block is corrupt, so
// all blocks are reported and the caller may narrow the set with per-block
// hashes. Returns ok=false with a nil corrupt slice for an invalid (zero)
// block size.
func AICHVerify(data []byte, blockSize uint64, root [16]byte) (bool, []uint64) {
	if blockSize == 0 {
		return false, nil
	}
	computed := AICHRoot(data, blockSize)
	if computed == root {
		return true, nil
	}
	n := AICHLeafCount(len(data), blockSize)
	corrupt := make([]uint64, n)
	for i := 0; i < n; i++ {
		corrupt[i] = uint64(i)
	}
	return false, corrupt
}

// --- Aliases / alternate spellings for the helpers, for compatibility. ---

// NumLeaves / block-count aliases.
func AICHNumLeaves(dataLen int, blockSize uint64) int { return AICHLeafCount(dataLen, blockSize) }
func AICHLeaves(dataLen int, blockSize uint64) int    { return AICHLeafCount(dataLen, blockSize) }
func AICHBlockCount(dataLen int, blockSize uint64) int { return AICHLeafCount(dataLen, blockSize) }
func AICHNumBlocks(dataLen int, blockSize uint64) int  { return AICHLeafCount(dataLen, blockSize) }
func AICHBlocks(dataLen int, blockSize uint64) int     { return AICHLeafCount(dataLen, blockSize) }

// Depth / height aliases.
func AICHTreeDepth(dataLen int, blockSize uint64) int { return AICHDepth(dataLen, blockSize) }
func AICHHeight(dataLen int, blockSize uint64) int     { return AICHDepth(dataLen, blockSize) }
func AICHLevels(dataLen int, blockSize uint64) int     { return AICHDepth(dataLen, blockSize) }

// Lowercase aliases.
func aichNumLeaves(dataLen int, blockSize uint64) int { return AICHLeafCount(dataLen, blockSize) }
func aichLeaves(dataLen int, blockSize uint64) int   { return AICHLeafCount(dataLen, blockSize) }
func aichBlockCount(dataLen int, blockSize uint64) int { return AICHLeafCount(dataLen, blockSize) }
func aichNumBlocks(dataLen int, blockSize uint64) int { return AICHLeafCount(dataLen, blockSize) }
func aichBlocks(dataLen int, blockSize uint64) int    { return AICHLeafCount(dataLen, blockSize) }
func aichTreeDepth(dataLen int, blockSize uint64) int { return AICHDepth(dataLen, blockSize) }
func aichHeight(dataLen int, blockSize uint64) int    { return AICHDepth(dataLen, blockSize) }
func aichLevels(dataLen int, blockSize uint64) int    { return AICHDepth(dataLen, blockSize) }
