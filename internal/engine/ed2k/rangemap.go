// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds a stdlib-only helper that maps eDonkey2000 part ranges
// (part index / byte offset within a file) to and from canonical 1 MiB block
// indices, given the file size, the eDonkey part size and the canonical block
// size. No networking, .part.met I/O or AICH is performed here.
package ed2k

// RangeMap holds the parameters describing how an eDonkey2000 file's parts
// map onto the canonical block map. All fields are sizes in bytes (except
// indices, which are unitless). Zero values are resolved through the alias
// fields below, mirroring the PartMet codec's alias handling.
type RangeMap struct {
	// File size in bytes.
	FileSize  uint64
	Size      uint64
	TotalSize uint64
	Length    uint64

	// eDonkey part size in bytes.
	PartSize uint64
	PartLen  uint64

	// Canonical block size in bytes.
	BlockSize          uint64
	CanonicalBlockSize uint64
	BlockLen           uint64
}

// normalized resolves the alias fields into one canonical set of values.
func (rm RangeMap) normalized() (uint64, uint64, uint64) {
	fileSize := rm.FileSize
	if fileSize == 0 {
		switch {
		case rm.Size != 0:
			fileSize = rm.Size
		case rm.TotalSize != 0:
			fileSize = rm.TotalSize
		case rm.Length != 0:
			fileSize = rm.Length
		}
	}
	partSize := rm.PartSize
	if partSize == 0 && rm.PartLen != 0 {
		partSize = rm.PartLen
	}
	blockSize := rm.BlockSize
	if blockSize == 0 {
		switch {
		case rm.CanonicalBlockSize != 0:
			blockSize = rm.CanonicalBlockSize
		case rm.BlockLen != 0:
			blockSize = rm.BlockLen
		}
	}
	return fileSize, partSize, blockSize
}

// NewRangeMap builds a RangeMap from file size, part size and block size.
func NewRangeMap(fileSize, partSize, blockSize uint64) RangeMap {
	return RangeMap{FileSize: fileSize, PartSize: partSize, BlockSize: blockSize}
}

// NewRangeMapFromParts builds a RangeMap with arguments ordered as
// (partSize, fileSize, blockSize).
func NewRangeMapFromParts(partSize, fileSize, blockSize uint64) RangeMap {
	return RangeMap{FileSize: fileSize, PartSize: partSize, BlockSize: blockSize}
}

// partCount returns the number of eDonkey parts for a file of fileSize bytes.
func partCount(fileSize, partSize uint64) uint64 {
	if fileSize == 0 || partSize == 0 {
		return 0
	}
	return (fileSize + partSize - 1) / partSize
}

// blockCount returns the number of canonical blocks for a file of fileSize bytes.
func blockCount(fileSize, blockSize uint64) uint64 {
	if fileSize == 0 || blockSize == 0 {
		return 0
	}
	return (fileSize + blockSize - 1) / blockSize
}

// partByteRange returns the half-open byte range [start, end) covered by part
// partIndex. ok is false when the inputs are invalid or the index is out of range.
func partByteRange(partIndex, partSize, fileSize uint64) (uint64, uint64, bool) {
	if fileSize == 0 || partSize == 0 {
		return 0, 0, false
	}
	n := partCount(fileSize, partSize)
	if partIndex >= n {
		return 0, 0, false
	}
	// Guard against overflow of partIndex*partSize.
	if partIndex != 0 && partSize > ^uint64(0)/partIndex {
		return 0, 0, false
	}
	start := partIndex * partSize
	end := start + partSize
	if end > fileSize || end < start {
		end = fileSize
	}
	if start >= fileSize {
		return 0, 0, false
	}
	return start, end, true
}

// blockByteRange returns the half-open byte range [start, end) covered by
// canonical block blockIndex.
func blockByteRange(blockIndex, blockSize, fileSize uint64) (uint64, uint64, bool) {
	if fileSize == 0 || blockSize == 0 {
		return 0, 0, false
	}
	n := blockCount(fileSize, blockSize)
	if blockIndex >= n {
		return 0, 0, false
	}
	if blockIndex != 0 && blockSize > ^uint64(0)/blockIndex {
		return 0, 0, false
	}
	start := blockIndex * blockSize
	end := start + blockSize
	if end > fileSize || end < start {
		end = fileSize
	}
	if start >= fileSize {
		return 0, 0, false
	}
	return start, end, true
}

// canonicalBlocksForPartRange is the shared implementation.
func canonicalBlocksForPartRange(partStart, partEnd, blockSize, fileSize uint64) []uint64 {
	if partEnd <= partStart || blockSize == 0 || fileSize == 0 {
		return nil
	}
	// First and last canonical block indices overlapping [partStart, partEnd).
	first := partStart / blockSize
	last := (partEnd - 1) / blockSize
	n := blockCount(fileSize, blockSize)
	if n == 0 {
		return nil
	}
	if first >= n {
		first = n - 1
	}
	if last >= n {
		last = n - 1
	}
	if last < first {
		return nil
	}
	out := make([]uint64, 0, last-first+1)
	for i := first; i <= last; i++ {
		out = append(out, i)
		if i == ^uint64(0) {
			break
		}
	}
	return out
}

// CanonicalBlocksForPart returns the canonical block indices whose byte ranges
// overlap the byte range of eDonkey part partIndex.
func CanonicalBlocksForPart(partIndex, partSize, fileSize, blockSize uint64) []uint64 {
	ps, pe, ok := partByteRange(partIndex, partSize, fileSize)
	if !ok {
		return nil
	}
	return canonicalBlocksForPartRange(ps, pe, blockSize, fileSize)
}

// MapPartToBlocks is an alias for CanonicalBlocksForPart.
func MapPartToBlocks(partIndex, partSize, fileSize, blockSize uint64) []uint64 {
	return CanonicalBlocksForPart(partIndex, partSize, fileSize, blockSize)
}

// partsForBlockRange is the shared implementation.
func partsForBlockRange(blockStart, blockEnd, partSize, fileSize uint64) []uint64 {
	if blockEnd <= blockStart || partSize == 0 || fileSize == 0 {
		return nil
	}
	first := blockStart / partSize
	last := (blockEnd - 1) / partSize
	n := partCount(fileSize, partSize)
	if n == 0 {
		return nil
	}
	if first >= n {
		first = n - 1
	}
	if last >= n {
		last = n - 1
	}
	if last < first {
		return nil
	}
	out := make([]uint64, 0, last-first+1)
	for i := first; i <= last; i++ {
		out = append(out, i)
		if i == ^uint64(0) {
			break
		}
	}
	return out
}

// PartsForBlock returns the eDonkey part indices whose byte ranges overlap the
// byte range of canonical block blockIndex.
func PartsForBlock(blockIndex, partSize, fileSize, blockSize uint64) []uint64 {
	bs, be, ok := blockByteRange(blockIndex, blockSize, fileSize)
	if !ok {
		return nil
	}
	return partsForBlockRange(bs, be, partSize, fileSize)
}

// MapBlockToParts is an alias for PartsForBlock.
func MapBlockToParts(blockIndex, partSize, fileSize, blockSize uint64) []uint64 {
	return PartsForBlock(blockIndex, partSize, fileSize, blockSize)
}

// --- RangeMap methods ---

func (rm RangeMap) sizes() (uint64, uint64, uint64) { return rm.normalized() }

func (rm RangeMap) CanonicalBlocksForPart(partIndex uint64) []uint64 {
	fs, ps, bs := rm.normalized()
	return CanonicalBlocksForPart(partIndex, ps, fs, bs)
}

func (rm RangeMap) MapPartToBlocks(partIndex uint64) []uint64 {
	return rm.CanonicalBlocksForPart(partIndex)
}

func (rm RangeMap) BlocksForPart(partIndex uint64) []uint64 {
	return rm.CanonicalBlocksForPart(partIndex)
}

func (rm RangeMap) PartToBlocks(partIndex uint64) []uint64 {
	return rm.CanonicalBlocksForPart(partIndex)
}

func (rm RangeMap) PartsForBlock(blockIndex uint64) []uint64 {
	fs, ps, bs := rm.normalized()
	return PartsForBlock(blockIndex, ps, fs, bs)
}

func (rm RangeMap) MapBlockToParts(blockIndex uint64) []uint64 {
	return rm.PartsForBlock(blockIndex)
}

func (rm RangeMap) PartsForCanonicalBlock(blockIndex uint64) []uint64 {
	return rm.PartsForBlock(blockIndex)
}

func (rm RangeMap) BlockToParts(blockIndex uint64) []uint64 {
	return rm.PartsForBlock(blockIndex)
}
