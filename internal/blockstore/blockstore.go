// SPDX-License-Identifier: GPL-3.0-or-later

// Package blockstore implements a verified block store over the canonical
// block map: per-block byte storage plus a per-network verified bitmap.
//
// A BlockStore wraps a *blockmap.BlockMap and records which bytes have been
// fetched for each canonical block and which network has verified them. It is
// safe for concurrent use. Verification is tracked independently per network:
// a block is reported verified only for the network that marked it.
package blockstore

import (
	"bytes"
	"fmt"
	"sort"
	"sync"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
)

// DefaultNetwork is used when a caller marks a block verified without naming
// a network.
const DefaultNetwork = ""

// BlockStore is a thread-safe verified block store over a canonical block map.
type BlockStore struct {
	mu sync.RWMutex

	bm    *blockmap.BlockMap
	count uint64

	// per-block stored bytes (a copy is kept to avoid external mutation).
	data [][]byte

	// per-network verified bitmaps: network -> set of verified block indices.
	verified map[string]map[uint64]struct{}

	// order in which networks first appeared, for deterministic iteration.
	netOrder []string
}

// VerifiedBlockStore is an alias for BlockStore.
type VerifiedBlockStore = BlockStore

// VerifiedStore is an alias for BlockStore.
type VerifiedStore = BlockStore

// New wraps bm in a BlockStore. It also accepts (fileSize, blockSize) so a
// store can be constructed directly, mirroring blockmap.New.
func New(args ...interface{}) *BlockStore {
	bm := parseBlockMap(args)
	if bm == nil {
		bm = blockmap.New(0, 0)
	}
	n := bm.BlockCount()
	bs := &BlockStore{
		bm:       bm,
		count:    n,
		data:     make([][]byte, n),
		verified: make(map[string]map[uint64]struct{}),
	}
	return bs
}

// parseBlockMap interprets the variadic constructor arguments.
func parseBlockMap(args []interface{}) *blockmap.BlockMap {
	switch len(args) {
	case 0:
		return blockmap.New(0, 0)
	case 1:
		switch v := args[0].(type) {
		case *blockmap.BlockMap:
			return v
		case uint64:
			return blockmap.New(v, 0)
		case uint:
			return blockmap.New(uint64(v), 0)
		case int:
			if v < 0 {
				v = 0
			}
			return blockmap.New(uint64(v), 0)
		case int64:
			if v < 0 {
				v = 0
			}
			return blockmap.New(uint64(v), 0)
		}
	case 2:
		fs, bs := toUint64(args[0]), toUint64(args[1])
		return blockmap.New(fs, bs)
	}
	// fall back: try first arg as blockmap
	if len(args) > 0 {
		if v, ok := args[0].(*blockmap.BlockMap); ok {
			return v
		}
	}
	return nil
}

func toUint64(v interface{}) uint64 {
	switch x := v.(type) {
	case uint64:
		return x
	case uint:
		return uint64(x)
	case int:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case int64:
		if x < 0 {
			return 0
		}
		return uint64(x)
	case *blockmap.BlockMap:
		return x.FileSize()
	}
	return 0
}

// BlockMap returns the wrapped canonical block map.
func (s *BlockStore) BlockMap() *blockmap.BlockMap { return s.bm }

// BlockCount returns the number of canonical blocks.
func (s *BlockStore) BlockCount() uint64 { return s.blockCount() }

// Blocks is an alias for BlockCount.
func (s *BlockStore) Blocks() uint64 { return s.BlockCount() }

// NumBlocks is an alias for BlockCount.
func (s *BlockStore) NumBlocks() uint64 { return s.BlockCount() }

// Len is an alias for BlockCount.
func (s *BlockStore) Len() uint64 { return s.BlockCount() }

// FileSize returns the wrapped file size.
func (s *BlockStore) FileSize() uint64 {
	if s.bm != nil {
		return s.bm.FileSize()
	}
	return 0
}

// BlockSize returns the wrapped block size.
func (s *BlockStore) BlockSize() uint64 {
	if s.bm != nil {
		return s.bm.BlockSize()
	}
	return blockmap.DefaultBlockSize
}

// blockCount returns the number of canonical blocks.
func (s *BlockStore) blockCount() uint64 {
	if s.bm != nil {
		return s.bm.BlockCount()
	}
	return s.count
}

// NewBlockStore is an alias for New.
func NewBlockStore(args ...interface{}) *BlockStore { return New(args...) }

// NewVerifiedBlockStore is an alias for New.
func NewVerifiedBlockStore(args ...interface{}) *BlockStore { return New(args...) }

// NewVerifiedStore is an alias for New.
func NewVerifiedStore(args ...interface{}) *BlockStore { return New(args...) }

// --- byte storage ---

// PutBlock stores data for block index. Returns true on success, false if the
// index is out of range.
func (s *BlockStore) PutBlock(index uint64, data []byte) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= s.blockCount() {
		return false
	}
	// store a private copy
	cp := make([]byte, len(data))
	copy(cp, data)
	s.data[index] = cp
	return true
}

// PutBlockBytes is an alias for PutBlock.
func (s *BlockStore) PutBlockBytes(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// StoreBlock is an alias for PutBlock.
func (s *BlockStore) StoreBlock(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// SetBlock is an alias for PutBlock.
func (s *BlockStore) SetBlock(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// WriteBlock is an alias for PutBlock.
func (s *BlockStore) WriteBlock(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// AddBlock is an alias for PutBlock.
func (s *BlockStore) AddBlock(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// InsertBlock is an alias for PutBlock.
func (s *BlockStore) InsertBlock(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// SaveBlock is an alias for PutBlock.
func (s *BlockStore) SaveBlock(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// Put is an alias for PutBlock.
func (s *BlockStore) Put(index uint64, data []byte) bool { return s.PutBlock(index, data) }

// Block returns the stored bytes for block index, or nil if none/out of range.
// A copy is returned so callers cannot mutate stored bytes.
func (s *BlockStore) Block(index uint64) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if index >= s.blockCount() {
		return nil
	}
	if s.data[index] == nil {
		return nil
	}
	cp := make([]byte, len(s.data[index]))
	copy(cp, s.data[index])
	return cp
}

// GetBlock is an alias for Block.
func (s *BlockStore) GetBlock(index uint64) []byte { return s.Block(index) }

// BlockBytes is an alias for Block.
func (s *BlockStore) BlockBytes(index uint64) []byte { return s.Block(index) }

// ReadBlock is an alias for Block.
func (s *BlockStore) ReadBlock(index uint64) []byte { return s.Block(index) }

// Get is an alias for Block.
func (s *BlockStore) Get(index uint64) []byte { return s.Block(index) }

// LoadBlock is an alias for Block.
func (s *BlockStore) LoadBlock(index uint64) []byte { return s.Block(index) }

// FetchBlock is an alias for Block.
func (s *BlockStore) FetchBlock(index uint64) []byte { return s.Block(index) }

// BlockOK returns the stored bytes and whether the block index is in range.
func (s *BlockStore) BlockOK(index uint64) ([]byte, bool) {
	if index >= s.blockCount() {
		return nil, false
	}
	return s.Block(index), true
}

// GetBlockOK is an alias for BlockOK.
func (s *BlockStore) GetBlockOK(index uint64) ([]byte, bool) { return s.BlockOK(index) }

// ReadBlockOK is an alias for BlockOK.
func (s *BlockStore) ReadBlockOK(index uint64) ([]byte, bool) { return s.BlockOK(index) }

// HasBlock reports whether block index has stored bytes.
func (s *BlockStore) HasBlock(index uint64) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if index >= s.blockCount() {
		return false
	}
	return s.data[index] != nil
}

// BlockLen returns the length of stored bytes for block index.
func (s *BlockStore) BlockLen(index uint64) int {
	b := s.Block(index)
	return len(b)
}

// --- verification ---

func (s *BlockStore) ensureNetLocked(network string) {
	if _, ok := s.verified[network]; !ok {
		s.verified[network] = make(map[uint64]struct{})
		s.netOrder = append(s.netOrder, network)
	}
}

// networkName normalises the variadic network argument.
func networkName(args []string) string {
	if len(args) == 0 {
		return DefaultNetwork
	}
	return args[0]
}

// MarkVerified marks block index as verified by network. Returns true if the
// block index is in range.
func (s *BlockStore) MarkVerified(index uint64, network ...string) bool {
	net := networkName(network)
	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= s.blockCount() {
		return false
	}
	s.ensureNetLocked(net)
	s.verified[net][index] = struct{}{}
	return true
}

// SetVerified is an alias for MarkVerified.
func (s *BlockStore) SetVerified(index uint64, network ...string) bool {
	return s.MarkVerified(index, network...)
}

// Verify is an alias for MarkVerified.
func (s *BlockStore) Verify(index uint64, network ...string) bool {
	return s.MarkVerified(index, network...)
}

// VerifyBlock is an alias for MarkVerified.
func (s *BlockStore) VerifyBlock(index uint64, network ...string) bool {
	return s.MarkVerified(index, network...)
}

// MarkBlockVerified is an alias for MarkVerified.
func (s *BlockStore) MarkBlockVerified(index uint64, network ...string) bool {
	return s.MarkVerified(index, network...)
}

// Complete marks a block verified (under the default network) and is provided
// for scheduler-style callers.
func (s *BlockStore) Complete(index uint64) bool {
	return s.MarkVerified(index, DefaultNetwork)
}

// CompleteBlock is an alias for Complete.
func (s *BlockStore) CompleteBlock(index uint64) bool { return s.Complete(index) }

// MarkComplete is an alias for Complete.
func (s *BlockStore) MarkComplete(index uint64) bool { return s.Complete(index) }

// Finish is an alias for Complete.
func (s *BlockStore) Finish(index uint64) bool { return s.Complete(index) }

// IsVerified reports whether block index is verified. With no network
// argument it reports whether any network has verified it; with a network
// argument it reports verification by that network only.
func (s *BlockStore) IsVerified(index uint64, network ...string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if index >= s.blockCount() {
		return false
	}
	if len(network) == 0 {
		for _, m := range s.verified {
			if _, ok := m[index]; ok {
				return true
			}
		}
		return false
	}
	net := network[0]
	m, ok := s.verified[net]
	if !ok {
		return false
	}
	_, ok = m[index]
	return ok
}

// IsVerifiedBy is an alias-style helper taking (index, network).
func (s *BlockStore) IsVerifiedBy(index uint64, network string) bool {
	return s.IsVerified(index, network)
}

// VerifiedBy returns the network that verified block index. If several
// networks verified it, the lexicographically smallest is returned. Returns
// "" if none. An optional network argument is accepted for call-site
// compatibility but does not change the result.
func (s *BlockStore) VerifiedBy(index uint64, _ ...string) string {
	nets := s.VerifiedByNetworks(index)
	if len(nets) == 0 {
		return ""
	}
	return nets[0]
}

// VerifiedByNetworks returns all networks that verified block index, sorted.
func (s *BlockStore) VerifiedByNetworks(index uint64) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if index >= s.blockCount() {
		return nil
	}
	out := make([]string, 0)
	for net, m := range s.verified {
		if _, ok := m[index]; ok {
			out = append(out, net)
		}
	}
	sort.Strings(out)
	return out
}

// VerifiedByList is an alias for VerifiedByNetworks.
func (s *BlockStore) VerifiedByList(index uint64) []string { return s.VerifiedByNetworks(index) }

// VerifiedNetworks is an alias for VerifiedByNetworks.
func (s *BlockStore) VerifiedNetworks(index uint64) []string { return s.VerifiedByNetworks(index) }

// NetworksFor is an alias for VerifiedByNetworks.
func (s *BlockStore) NetworksFor(index uint64) []string { return s.VerifiedByNetworks(index) }

// VerifiedCount returns the number of verified blocks. With no network
// argument it counts blocks verified by at least one network; with a network
// argument it counts blocks verified by that network.
func (s *BlockStore) VerifiedCount(network ...string) uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if len(network) == 0 {
		seen := make(map[uint64]struct{})
		for _, m := range s.verified {
			for idx := range m {
				seen[idx] = struct{}{}
			}
		}
		return uint64(len(seen))
	}
	net := network[0]
	m, ok := s.verified[net]
	if !ok {
		return 0
	}
	return uint64(len(m))
}

// VerifiedCountBy is an alias-style helper taking a network name.
func (s *BlockStore) VerifiedCountBy(network string) uint64 {
	return s.VerifiedCount(network)
}

// VerifiedCountFor is an alias for VerifiedCountBy.
func (s *BlockStore) VerifiedCountFor(network string) uint64 { return s.VerifiedCount(network) }

// AllVerified reports whether every block has been verified by at least one
// network. An empty store (zero blocks) is vacuously verified.
func (s *BlockStore) AllVerified() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.blockCount()
	if n == 0 {
		return true
	}
	seen := make(map[uint64]struct{})
	for _, m := range s.verified {
		for idx := range m {
			seen[idx] = struct{}{}
		}
	}
	return uint64(len(seen)) == n
}

// AllVerifiedBy reports whether every block is verified by the given network.
func (s *BlockStore) AllVerifiedBy(network string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.blockCount()
	m, ok := s.verified[network]
	if !ok {
		return n == 0
	}
	return uint64(len(m)) == n
}

// AllVerifiedFor is an alias for AllVerifiedBy.
func (s *BlockStore) AllVerifiedFor(network string) bool { return s.AllVerifiedBy(network) }

// UnverifiedBlocks returns the indices of blocks not verified by any network,
// in ascending order.
func (s *BlockStore) UnverifiedBlocks() []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.blockCount()
	verified := make(map[uint64]struct{})
	for _, m := range s.verified {
		for idx := range m {
			verified[idx] = struct{}{}
		}
	}
	out := make([]uint64, 0, n-uint64(len(verified)))
	for i := uint64(0); i < n; i++ {
		if _, ok := verified[i]; !ok {
			out = append(out, i)
		}
	}
	return out
}

// Unverified is an alias for UnverifiedBlocks.
func (s *BlockStore) Unverified() []uint64 { return s.UnverifiedBlocks() }

// UnverifiedBy returns blocks not verified by the given network.
func (s *BlockStore) UnverifiedBy(network string) []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	n := s.blockCount()
	m, _ := s.verified[network]
	out := make([]uint64, 0)
	for i := uint64(0); i < n; i++ {
		if _, ok := m[i]; !ok {
			out = append(out, i)
		}
	}
	return out
}

// UnverifiedFor is an alias for UnverifiedBy.
func (s *BlockStore) UnverifiedFor(network string) []uint64 { return s.UnverifiedBy(network) }

// UnverifiedBlocksBy is an alias for UnverifiedBy.
func (s *BlockStore) UnverifiedBlocksBy(network string) []uint64 { return s.UnverifiedBy(network) }

// VerifiedBlocks returns all block indices verified by at least one network.
func (s *BlockStore) VerifiedBlocks() []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	seen := make(map[uint64]struct{})
	for _, m := range s.verified {
		for idx := range m {
			seen[idx] = struct{}{}
		}
	}
	out := make([]uint64, 0, len(seen))
	for idx := range seen {
		out = append(out, idx)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// VerifiedBlocksBy returns blocks verified by the given network.
func (s *BlockStore) VerifiedBlocksBy(network string) []uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	m, ok := s.verified[network]
	if !ok {
		return nil
	}
	out := make([]uint64, 0, len(m))
	for idx := range m {
		out = append(out, idx)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ResetBlock clears stored bytes and verification for a block.
func (s *BlockStore) ResetBlock(index uint64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if index >= s.blockCount() {
		return false
	}
	s.data[index] = nil
	for _, m := range s.verified {
		delete(m, index)
	}
	return true
}

// Clear removes all stored bytes and verification state but keeps the block map.
func (s *BlockStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.data {
		s.data[i] = nil
	}
	for net := range s.verified {
		s.verified[net] = make(map[uint64]struct{})
	}
}

// NetworkCount returns the number of distinct networks that have verified
// at least one block.
func (s *BlockStore) NetworkCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.verified)
}

// Networks returns the distinct networks in first-seen order.
func (s *BlockStore) Networks() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.netOrder))
	copy(out, s.netOrder)
	return out
}

// String returns a summary.
func (s *BlockStore) String() string {
	return fmt.Sprintf("BlockStore{blocks=%d, verified=%d}", s.blockCount(), s.VerifiedCount())
}

// BytesEqual reports whether stored bytes for index equal data.
func (s *BlockStore) BytesEqual(index uint64, data []byte) bool {
	got := s.Block(index)
	return bytes.Equal(got, data)
}

