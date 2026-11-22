// SPDX-License-Identifier: GPL-3.0-or-later

// Package blockmap implements the canonical block map used by Sharza's
// cross-network swarming: a bitmap over a file divided into fixed-size
// blocks (1 MiB by default), tracking which blocks have been verified.
//
// The block map is the shared foundation every swarming component builds on:
// the scheduler, the verified block store, and each engine's range adapter all
// key off these block indices and their half-open byte ranges.
//
// This package is intentionally standalone: it performs no I/O, holds no
// engine or store state, and is safe for concurrent use.
package blockmap

import (
	"math/bits"
	"sync"
)

// DefaultBlockSize is the canonical block size: 1 MiB.
const DefaultBlockSize = 1 << 20

// BlockMap is a bitmap over a file's canonical blocks. A block is marked
// verified once its bytes have been checked against a trusted hash.
type BlockMap struct {
	mu         sync.RWMutex
	fileSize   uint64
	blockSize  uint64
	blockCount uint64
	bits       []uint64 // one bit per block, bit (i % 64) of word (i / 64)
}

// New creates a BlockMap over a file of fileSize bytes using blockSize-byte
// blocks. A blockSize of 0 selects DefaultBlockSize.
func New(fileSize, blockSize uint64) *BlockMap {
	if blockSize == 0 {
		blockSize = DefaultBlockSize
	}
	var count uint64
	if fileSize > 0 {
		count = (fileSize-1)/blockSize + 1
	}
	words := (count + 63) / 64
	return &BlockMap{
		fileSize:   fileSize,
		blockSize:  blockSize,
		blockCount: count,
		bits:       make([]uint64, words),
	}
}

// NewBlockMap is an alias for New.
func NewBlockMap(fileSize, blockSize uint64) *BlockMap {
	return New(fileSize, blockSize)
}

// FileSize returns the size of the file in bytes.
func (bm *BlockMap) FileSize() uint64 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.fileSize
}

// BlockSize returns the canonical block size in bytes.
func (bm *BlockMap) BlockSize() uint64 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.blockSize
}

// BlockCount returns the number of canonical blocks covering the file.
func (bm *BlockMap) BlockCount() uint64 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.blockCount
}

// Blocks is an alias for BlockCount.
func (bm *BlockMap) Blocks() uint64 { return bm.BlockCount() }

// NumBlocks is an alias for BlockCount.
func (bm *BlockMap) NumBlocks() uint64 { return bm.BlockCount() }

// Len is an alias for BlockCount.
func (bm *BlockMap) Len() uint64 { return bm.BlockCount() }

// BlockByteRange returns the half-open byte range [start, end) covered by
// block i. ok is false if i is out of range.
func (bm *BlockMap) BlockByteRange(i uint64) (start, end uint64, ok bool) {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	if i >= bm.blockCount {
		return 0, 0, false
	}
	start = i * bm.blockSize
	end = start + bm.blockSize
	if end > bm.fileSize {
		end = bm.fileSize
	}
	return start, end, true
}

// SetVerified marks block i as verified. Out-of-range indices are ignored.
func (bm *BlockMap) SetVerified(i uint64) {
	bm.mu.Lock()
	defer bm.mu.Unlock()
	if i >= bm.blockCount {
		return
	}
	bm.bits[i/64] |= 1 << (i % 64)
}

// IsVerified reports whether block i has been verified. Out-of-range indices
// report false.
func (bm *BlockMap) IsVerified(i uint64) bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	if i >= bm.blockCount {
		return false
	}
	return bm.bits[i/64]&(1<<(i%64)) != 0
}

// VerifiedCount returns the number of verified blocks.
func (bm *BlockMap) VerifiedCount() uint64 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	var n uint64
	for _, w := range bm.bits {
		n += uint64(popcount(w))
	}
	return n
}

// AllVerified reports whether every block has been verified. An empty file
// (zero blocks) is vacuously verified.
func (bm *BlockMap) AllVerified() bool {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	return bm.VerifiedCount() == bm.blockCount
}

// Unverified returns the indices of all blocks not yet verified, in ascending
// order.
func (bm *BlockMap) Unverified() []uint64 {
	bm.mu.RLock()
	defer bm.mu.RUnlock()
	out := make([]uint64, 0, bm.blockCount-bm.verifiedCountLocked())
	for i := uint64(0); i < bm.blockCount; i++ {
		if bm.bits[i/64]&(1<<(i%64)) == 0 {
			out = append(out, i)
		}
	}
	return out
}

func (bm *BlockMap) verifiedCountLocked() uint64 {
	var n uint64
	for _, w := range bm.bits {
		n += uint64(popcount(w))
	}
	return n
}

func popcount(x uint64) int {
	return bits.OnesCount64(x)
}
