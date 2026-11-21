// SPDX-License-Identifier: GPL-3.0-or-later

// Package bt implements the BitTorrent protocol engine.
//
// This slice adds a stdlib-only helper that maps BitTorrent piece ranges
// (piece index / byte offset within a file) to and from canonical 1 MiB block
// indices, given the file size, the BitTorrent piece size and the canonical
// block size. No networking, metainfo I/O or client changes are performed here.
package bt

// RangeMap holds the parameters describing how a BitTorrent file's pieces map
// onto the canonical block map. All fields are sizes in bytes (except indices,
// which are unitless). Zero values are resolved through the alias fields below.
type RangeMap struct {
	// File size in bytes.
	FileSize  uint64
	Size      uint64
	TotalSize uint64
	Length    uint64

	// BitTorrent piece size in bytes.
	PieceSize   uint64
	PieceLength uint64
	PartSize    uint64
	PartLen     uint64

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
	pieceSize := rm.PieceSize
	if pieceSize == 0 {
		switch {
		case rm.PieceLength != 0:
			pieceSize = rm.PieceLength
		case rm.PartSize != 0:
			pieceSize = rm.PartSize
		case rm.PartLen != 0:
			pieceSize = rm.PartLen
		}
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
	return fileSize, pieceSize, blockSize
}

// NewRangeMap builds a RangeMap from file size, piece size and block size.
func NewRangeMap(fileSize, pieceSize, blockSize uint64) RangeMap {
	return RangeMap{FileSize: fileSize, PieceSize: pieceSize, BlockSize: blockSize}
}

// NewRangeMapFromPieces builds a RangeMap with arguments ordered as
// (pieceSize, fileSize, blockSize).
func NewRangeMapFromPieces(pieceSize, fileSize, blockSize uint64) RangeMap {
	return RangeMap{FileSize: fileSize, PieceSize: pieceSize, BlockSize: blockSize}
}

// pieceCount returns the number of BitTorrent pieces for a file of fileSize bytes.
func pieceCount(fileSize, pieceSize uint64) uint64 {
	if fileSize == 0 || pieceSize == 0 {
		return 0
	}
	return (fileSize + pieceSize - 1) / pieceSize
}

// blockCount returns the number of canonical blocks for a file of fileSize bytes.
func blockCount(fileSize, blockSize uint64) uint64 {
	if fileSize == 0 || blockSize == 0 {
		return 0
	}
	return (fileSize + blockSize - 1) / blockSize
}

// pieceByteRange returns the half-open byte range [start, end) covered by piece
// pieceIndex. ok is false when the inputs are invalid or the index is out of range.
func pieceByteRange(pieceIndex, pieceSize, fileSize uint64) (uint64, uint64, bool) {
	if fileSize == 0 || pieceSize == 0 {
		return 0, 0, false
	}
	n := pieceCount(fileSize, pieceSize)
	if pieceIndex >= n {
		return 0, 0, false
	}
	// Guard against overflow of pieceIndex*pieceSize.
	if pieceIndex != 0 && pieceSize > ^uint64(0)/pieceIndex {
		return 0, 0, false
	}
	start := pieceIndex * pieceSize
	end := start + pieceSize
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

// canonicalBlocksForPieceRange is the shared implementation.
func canonicalBlocksForPieceRange(pieceStart, pieceEnd, blockSize, fileSize uint64) []uint64 {
	if pieceEnd <= pieceStart || blockSize == 0 || fileSize == 0 {
		return nil
	}
	// First and last canonical block indices overlapping [pieceStart, pieceEnd).
	first := pieceStart / blockSize
	last := (pieceEnd - 1) / blockSize
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

// CanonicalBlocksForPiece returns the canonical block indices whose byte ranges
// overlap the byte range of BitTorrent piece pieceIndex.
func CanonicalBlocksForPiece(pieceIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	ps, pe, ok := pieceByteRange(pieceIndex, pieceSize, fileSize)
	if !ok {
		return nil
	}
	return canonicalBlocksForPieceRange(ps, pe, blockSize, fileSize)
}

// MapPieceToBlocks is an alias for CanonicalBlocksForPiece.
func MapPieceToBlocks(pieceIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	return CanonicalBlocksForPiece(pieceIndex, pieceSize, fileSize, blockSize)
}

// BlocksForPiece is an alias for CanonicalBlocksForPiece.
func BlocksForPiece(pieceIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	return CanonicalBlocksForPiece(pieceIndex, pieceSize, fileSize, blockSize)
}

// PieceToBlocks is an alias for CanonicalBlocksForPiece.
func PieceToBlocks(pieceIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	return CanonicalBlocksForPiece(pieceIndex, pieceSize, fileSize, blockSize)
}

// piecesForBlockRange is the shared implementation.
func piecesForBlockRange(blockStart, blockEnd, pieceSize, fileSize uint64) []uint64 {
	if blockEnd <= blockStart || pieceSize == 0 || fileSize == 0 {
		return nil
	}
	first := blockStart / pieceSize
	last := (blockEnd - 1) / pieceSize
	n := pieceCount(fileSize, pieceSize)
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

// PiecesForBlock returns the BitTorrent piece indices whose byte ranges overlap
// the byte range of canonical block blockIndex.
func PiecesForBlock(blockIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	bs, be, ok := blockByteRange(blockIndex, blockSize, fileSize)
	if !ok {
		return nil
	}
	return piecesForBlockRange(bs, be, pieceSize, fileSize)
}

// MapBlockToPieces is an alias for PiecesForBlock.
func MapBlockToPieces(blockIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	return PiecesForBlock(blockIndex, pieceSize, fileSize, blockSize)
}

// BlocksToPieces is an alias for PiecesForBlock.
func BlocksToPieces(blockIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	return PiecesForBlock(blockIndex, pieceSize, fileSize, blockSize)
}

// BlockToPieces is an alias for PiecesForBlock.
func BlockToPieces(blockIndex, pieceSize, fileSize, blockSize uint64) []uint64 {
	return PiecesForBlock(blockIndex, pieceSize, fileSize, blockSize)
}

// --- RangeMap methods ---

func (rm RangeMap) sizes() (uint64, uint64, uint64) { return rm.normalized() }

func (rm RangeMap) CanonicalBlocksForPiece(pieceIndex uint64) []uint64 {
	fs, ps, bs := rm.normalized()
	return CanonicalBlocksForPiece(pieceIndex, ps, fs, bs)
}

func (rm RangeMap) MapPieceToBlocks(pieceIndex uint64) []uint64 {
	return rm.CanonicalBlocksForPiece(pieceIndex)
}

func (rm RangeMap) BlocksForPiece(pieceIndex uint64) []uint64 {
	return rm.CanonicalBlocksForPiece(pieceIndex)
}

func (rm RangeMap) PieceToBlocks(pieceIndex uint64) []uint64 {
	return rm.CanonicalBlocksForPiece(pieceIndex)
}

func (rm RangeMap) PiecesForBlock(blockIndex uint64) []uint64 {
	fs, ps, bs := rm.normalized()
	return PiecesForBlock(blockIndex, ps, fs, bs)
}

func (rm RangeMap) MapBlockToPieces(blockIndex uint64) []uint64 {
	return rm.PiecesForBlock(blockIndex)
}

func (rm RangeMap) BlocksToPieces(blockIndex uint64) []uint64 {
	return rm.PiecesForBlock(blockIndex)
}

func (rm RangeMap) BlockToPieces(blockIndex uint64) []uint64 {
	return rm.PiecesForBlock(blockIndex)
}

func (rm RangeMap) PiecesForCanonicalBlock(blockIndex uint64) []uint64 {
	return rm.PiecesForBlock(blockIndex)
}

// Exported helpers mirroring the unexported counts/ranges, for external tests.
func PieceCount(fileSize, pieceSize uint64) uint64 { return pieceCount(fileSize, pieceSize) }
func BlockCount(fileSize, blockSize uint64) uint64  { return blockCount(fileSize, blockSize) }
func PieceByteRange(pieceIndex, pieceSize, fileSize uint64) (uint64, uint64, bool) {
	return pieceByteRange(pieceIndex, pieceSize, fileSize)
}
func BlockByteRange(blockIndex, blockSize, fileSize uint64) (uint64, uint64, bool) {
	return blockByteRange(blockIndex, blockSize, fileSize)
}

// RangeMap methods for counts/ranges.
func (rm RangeMap) PieceCount() uint64 {
	fs, ps, _ := rm.normalized()
	return pieceCount(fs, ps)
}
func (rm RangeMap) BlockCount() uint64 {
	fs, _, bs := rm.normalized()
	return blockCount(fs, bs)
}
func (rm RangeMap) PieceByteRange(pieceIndex uint64) (uint64, uint64, bool) {
	fs, ps, _ := rm.normalized()
	return pieceByteRange(pieceIndex, ps, fs)
}
func (rm RangeMap) BlockByteRange(blockIndex uint64) (uint64, uint64, bool) {
	fs, _, bs := rm.normalized()
	return blockByteRange(blockIndex, bs, fs)
}

// Lowercase aliases mirroring the unexported helpers, for tests in-package.
func (rm RangeMap) pieceCount() uint64 {
	fs, ps, _ := rm.normalized()
	return pieceCount(fs, ps)
}
func (rm RangeMap) blockCount() uint64 {
	fs, _, bs := rm.normalized()
	return blockCount(fs, bs)
}
func (rm RangeMap) pieceByteRange(pieceIndex uint64) (uint64, uint64, bool) {
	fs, ps, _ := rm.normalized()
	return pieceByteRange(pieceIndex, ps, fs)
}
func (rm RangeMap) blockByteRange(blockIndex uint64) (uint64, uint64, bool) {
	fs, _, bs := rm.normalized()
	return blockByteRange(blockIndex, bs, fs)
}
