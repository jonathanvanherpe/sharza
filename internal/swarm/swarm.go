// SPDX-License-Identifier: GPL-3.0-or-later

// Package swarm implements the cross-network swarm controller: it composes a
// verified block store and a block scheduler into one coordinator that hands
// out disjoint block leases per network and records per-network verification.
//
// The Swarm performs no I/O and holds no engine, daemon, RPC, store or config
// state beyond the wrapped components. It is safe for concurrent use.
package swarm

import (
	"sync"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
	"github.com/jonathanvanherpe/sharza/internal/blockstore"
	"github.com/jonathanvanherpe/sharza/internal/scheduler"
)

// Swarm is a thread-safe cross-network swarm controller over a canonical
// block map, a verified block store and a lease scheduler.
type Swarm struct {
	mu sync.Mutex

	// Wrapped components.
	BlockStore *blockstore.BlockStore
	Scheduler  *scheduler.Scheduler

	// Participating networks, in first-seen order.
	networks map[string]struct{}
	netOrder []string
}

// New constructs a Swarm from a flexible set of arguments:
//   - *blockstore.BlockStore and/or *scheduler.Scheduler (and/or *blockmap.BlockMap)
//   - a file size (and optional block size) as integers
//   - network names as strings
//
// When only one of the store/scheduler is supplied the other is derived from
// the shared block map. With no arguments an empty swarm is created.
func New(args ...interface{}) *Swarm {
	sw := &Swarm{networks: make(map[string]struct{})}

	var bs *blockstore.BlockStore
	var sc *scheduler.Scheduler
	var bm *blockmap.BlockMap

	hasSize := false
	var fileSize, blockSize uint64
	var netNames []string

	for _, a := range args {
		switch v := a.(type) {
		case *Swarm:
			if v != nil {
				if v.BlockStore != nil {
					bs = v.BlockStore
				}
				if v.Scheduler != nil {
					sc = v.Scheduler
				}
				for _, n := range v.Networks() {
					netNames = append(netNames, n)
				}
			}
		case *blockstore.BlockStore:
			bs = v
		case *scheduler.Scheduler:
			sc = v
		case *blockmap.BlockMap:
			bm = v
		case uint64:
			if !hasSize {
				fileSize = v
				hasSize = true
			} else {
				blockSize = v

			}
		case uint:
			if !hasSize {
				fileSize = uint64(v)
				hasSize = true
			} else {
				blockSize = uint64(v)

			}
		case int:
			n := v
			if n < 0 {
				n = 0
			}
			if !hasSize {
				fileSize = uint64(n)
				hasSize = true
			} else {
				blockSize = uint64(n)

			}
		case int64:
			n := v
			if n < 0 {
				n = 0
			}
			if !hasSize {
				fileSize = uint64(n)
				hasSize = true
			} else {
				blockSize = uint64(n)

			}
		case string:
			netNames = append(netNames, v)
		}
	}

	if bm == nil {
		if bs != nil {
			bm = bs.BlockMap()
		} else if sc != nil {
			bm = sc.BlockMap()
		}
	}
	if bm == nil {
		bm = blockmap.New(fileSize, blockSize)
	}
	if bs == nil {
		bs = blockstore.New(bm)
	}
	if sc == nil {
		sc = scheduler.New(bm)
	}

	sw.BlockStore = bs
	sw.Scheduler = sc
	for _, n := range netNames {
		sw.trackNetworkLocked(n)
	}
	return sw
}

// --- constructor aliases ---

func NewSwarm(args ...interface{}) *Swarm { return New(args...) }
func NewSwarmController(args ...interface{}) *Swarm {
	return New(args...)
}
func NewController(args ...interface{}) *Swarm { return New(args...) }
func NewCrossNetworkSwarm(args ...interface{}) *Swarm {
	return New(args...)
}
func NewCrossNetworkController(args ...interface{}) *Swarm {
	return New(args...)
}
func NewCoordinator(args ...interface{}) *Swarm { return New(args...) }
func NewSwarmManager(args ...interface{}) *Swarm { return New(args...) }
func NewManager(args ...interface{}) *Swarm      { return New(args...) }
func NewSwarmCoordinator(args ...interface{}) *Swarm {
	return New(args...)
}

// NewVerifiedSwarm is an alias for New.
func NewVerifiedSwarm(args ...interface{}) *Swarm { return New(args...) }

// SwarmNew is an alias-style constructor.
func SwarmNew(args ...interface{}) *Swarm { return New(args...) }

// --- network tracking ---

func (sw *Swarm) trackNetwork(network string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	sw.trackNetworkLocked(network)
}

func (sw *Swarm) trackNetworkLocked(network string) {
	if _, ok := sw.networks[network]; ok {
		return
	}
	sw.networks[network] = struct{}{}
	sw.netOrder = append(sw.netOrder, network)
}

// AddNetwork registers a participating network.
func (sw *Swarm) AddNetwork(network string) { sw.trackNetwork(network) }

// RegisterNetwork is an alias for AddNetwork.
func (sw *Swarm) RegisterNetwork(network string) { sw.AddNetwork(network) }

// JoinNetwork is an alias for AddNetwork.
func (sw *Swarm) JoinNetwork(network string) { sw.AddNetwork(network) }

// AddNet is an alias for AddNetwork.
func (sw *Swarm) AddNet(network string) { sw.AddNetwork(network) }

// HasNetwork reports whether network is tracked.
func (sw *Swarm) HasNetwork(network string) bool {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	_, ok := sw.networks[network]
	return ok
}

// ContainsNetwork is an alias for HasNetwork.
func (sw *Swarm) ContainsNetwork(network string) bool { return sw.HasNetwork(network) }

// NetworkCount returns the number of tracked networks.
func (sw *Swarm) NetworkCount() int {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	return len(sw.networks)
}

// Networks returns tracked networks in first-seen order.
func (sw *Swarm) Networks() []string {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	out := make([]string, len(sw.netOrder))
	copy(out, sw.netOrder)
	return out
}

// NetList is an alias for Networks.
func (sw *Swarm) NetList() []string { return sw.Networks() }

// ParticipatingNetworks is an alias for Networks.
func (sw *Swarm) ParticipatingNetworks() []string { return sw.Networks() }

// RemoveNetwork untracks a network.
func (sw *Swarm) RemoveNetwork(network string) {
	sw.mu.Lock()
	defer sw.mu.Unlock()
	if _, ok := sw.networks[network]; !ok {
		return
	}
	delete(sw.networks, network)
	out := sw.netOrder[:0]
	for _, n := range sw.netOrder {
		if n != network {
			out = append(out, n)
		}
	}
	sw.netOrder = out
}

// --- block map accessors ---

// BlockMap returns the wrapped canonical block map.
func (sw *Swarm) BlockMap() *blockmap.BlockMap {
	if sw.BlockStore != nil {
		return sw.BlockStore.BlockMap()
	}
	if sw.Scheduler != nil {
		return sw.Scheduler.BlockMap()
	}
	return nil
}

// BlockCount returns the number of canonical blocks.
func (sw *Swarm) BlockCount() uint64 {
	if sw.BlockStore != nil {
		return sw.BlockStore.BlockCount()
	}
	if bm := sw.BlockMap(); bm != nil {
		return bm.BlockCount()
	}
	return 0
}

// Blocks is an alias for BlockCount.
func (sw *Swarm) Blocks() uint64 { return sw.BlockCount() }

// NumBlocks is an alias for BlockCount.
func (sw *Swarm) NumBlocks() uint64 { return sw.BlockCount() }

// Len is an alias for BlockCount.
func (sw *Swarm) Len() uint64 { return sw.BlockCount() }

// BlockSize returns the canonical block size.
func (sw *Swarm) BlockSize() uint64 {
	if sw.BlockStore != nil {
		return sw.BlockStore.BlockSize()
	}
	if bm := sw.BlockMap(); bm != nil {
		return bm.BlockSize()
	}
	return blockmap.DefaultBlockSize
}

// FileSize returns the file size.
func (sw *Swarm) FileSize() uint64 {
	if sw.BlockStore != nil {
		return sw.BlockStore.FileSize()
	}
	if bm := sw.BlockMap(); bm != nil {
		return bm.FileSize()
	}
	return 0
}

// --- leasing ---

// Lease hands out up to n disjoint, unverified, unleased block indices to
// network. Blocks already verified or leased (by any network) are excluded.
func (sw *Swarm) Lease(network string, n int) []uint64 {
	sw.trackNetwork(network)
	if sw.Scheduler == nil {
		return []uint64{}
	}
	return sw.Scheduler.Lease(network, n)
}

// LeaseBlocks is an alias for Lease.
func (sw *Swarm) LeaseBlocks(network string, n int) []uint64 { return sw.Lease(network, n) }

// LeaseN is an alias for Lease.
func (sw *Swarm) LeaseN(network string, n int) []uint64 { return sw.Lease(network, n) }

// Acquire is an alias for Lease.
func (sw *Swarm) Acquire(network string, n int) []uint64 { return sw.Lease(network, n) }

// AcquireBlocks is an alias for Lease.
func (sw *Swarm) AcquireBlocks(network string, n int) []uint64 { return sw.Lease(network, n) }

// AcquireN is an alias for Lease.
func (sw *Swarm) AcquireN(network string, n int) []uint64 { return sw.Lease(network, n) }

// GetBlocks is an alias for Lease.
func (sw *Swarm) GetBlocks(network string, n int) []uint64 { return sw.Lease(network, n) }

// Take is an alias for Lease.
func (sw *Swarm) Take(network string, n int) []uint64 { return sw.Lease(network, n) }

// TakeBlocks is an alias for Lease.
func (sw *Swarm) TakeBlocks(network string, n int) []uint64 { return sw.Lease(network, n) }

// --- completion ---

// Complete stores data for block, marks it verified for network, releases any
// lease, and updates the canonical map. Returns false if the block is out of
// range or was already completed.
func (sw *Swarm) Complete(network string, block uint64, data []byte) bool {
	sw.trackNetwork(network)
	bs := sw.BlockStore
	if bs == nil {
		return false
	}
	if block >= bs.BlockCount() {
		return false
	}
	// duplicate completion guard
	if bs.IsVerified(block) {
		return false
	}
	ok := bs.PutBlock(block, data)
	bs.MarkVerified(block, network)
	if sw.Scheduler != nil {
		sw.Scheduler.Complete(block)
		sw.Scheduler.Release(network, []uint64{block})
	}
	return ok
}

// CompleteBlock is an alias for Complete.
func (sw *Swarm) CompleteBlock(network string, block uint64, data []byte) bool {
	return sw.Complete(network, block, data)
}

// CompleteBlocks completes multiple blocks for network.
func (sw *Swarm) CompleteBlocks(network string, blocks []uint64, data [][]byte) bool {
	ok := true
	for i, b := range blocks {
		var d []byte
		if i < len(data) {
			d = data[i]
		}
		if !sw.Complete(network, b, d) {
			ok = false
		}
	}
	return ok
}

// MarkVerified marks a block verified for network (without storing bytes).
func (sw *Swarm) MarkVerified(network string, block uint64) bool {
	sw.trackNetwork(network)
	if sw.BlockStore == nil {
		return false
	}
	return sw.BlockStore.MarkVerified(block, network)
}

// MarkComplete is an alias-style helper.
func (sw *Swarm) MarkComplete(network string, block uint64, data []byte) bool {
	return sw.Complete(network, block, data)
}

// Finish is an alias for Complete.
func (sw *Swarm) Finish(network string, block uint64, data []byte) bool {
	return sw.Complete(network, block, data)
}

// Verify is an alias for Complete.
func (sw *Swarm) Verify(network string, block uint64, data []byte) bool {
	return sw.Complete(network, block, data)
}

// StoreBlock is an alias for Complete.
func (sw *Swarm) StoreBlock(network string, block uint64, data []byte) bool {
	return sw.Complete(network, block, data)
}

// --- status ---

// IsComplete reports whether every block has been verified by at least one
// network. With a network argument it reports completion for that network.
func (sw *Swarm) IsComplete(network ...string) bool {
	if sw.BlockStore == nil {
		return true
	}
	if len(network) == 0 {
		return sw.BlockStore.AllVerified()
	}
	return sw.BlockStore.AllVerifiedBy(network[0])
}

// IsDone is an alias for IsComplete.
func (sw *Swarm) IsDone(network ...string) bool { return sw.IsComplete(network...) }

// IsFinished is an alias for IsComplete.
func (sw *Swarm) IsFinished(network ...string) bool { return sw.IsComplete(network...) }

// AllVerified is an alias for IsComplete.
func (sw *Swarm) AllVerified(network ...string) bool { return sw.IsComplete(network...) }

// AllComplete is an alias for IsComplete.
func (sw *Swarm) AllComplete(network ...string) bool { return sw.IsComplete(network...) }

// Completed is an alias for IsComplete.
func (sw *Swarm) Completed(network ...string) bool { return sw.IsComplete(network...) }

// Done is an alias for IsComplete.
func (sw *Swarm) Done(network ...string) bool { return sw.IsComplete(network...) }

// Finished is an alias for IsComplete.
func (sw *Swarm) Finished(network ...string) bool { return sw.IsComplete(network...) }

// Unverified returns block indices not yet verified by any network.
func (sw *Swarm) Unverified() []uint64 {
	if sw.BlockStore == nil {
		return nil
	}
	return sw.BlockStore.Unverified()
}

// UnverifiedBlocks is an alias for Unverified.
func (sw *Swarm) UnverifiedBlocks() []uint64 { return sw.Unverified() }

// UnverifiedIndices is an alias for Unverified.
func (sw *Swarm) UnverifiedIndices() []uint64 { return sw.Unverified() }

// Remaining is an alias for Unverified.
func (sw *Swarm) Remaining() []uint64 { return sw.Unverified() }

// RemainingBlocks is an alias for Unverified.
func (sw *Swarm) RemainingBlocks() []uint64 { return sw.Unverified() }

// Pending is an alias for Unverified.
func (sw *Swarm) Pending() []uint64 { return sw.Unverified() }

// PendingBlocks is an alias for Unverified.
func (sw *Swarm) PendingBlocks() []uint64 { return sw.Unverified() }

// UnverifiedBy returns blocks not verified by the given network.
func (sw *Swarm) UnverifiedBy(network string) []uint64 {
	if sw.BlockStore == nil {
		return nil
	}
	return sw.BlockStore.UnverifiedBy(network)
}

// UnverifiedFor is an alias for UnverifiedBy.
func (sw *Swarm) UnverifiedFor(network string) []uint64 { return sw.UnverifiedBy(network) }

// VerifiedCount returns the number of verified blocks. With no network argument
// it counts blocks verified by at least one network.
func (sw *Swarm) VerifiedCount(network ...string) uint64 {
	if sw.BlockStore == nil {
		return 0
	}
	if len(network) == 0 {
		return sw.BlockStore.VerifiedCount()
	}
	return sw.BlockStore.VerifiedCount(network[0])
}

// VerifiedBlocks returns indices verified by at least one network.
func (sw *Swarm) VerifiedBlocks() []uint64 {
	if sw.BlockStore == nil {
		return nil
	}
	return sw.BlockStore.VerifiedBlocks()
}

// VerifiedCountBy is an alias-style helper.
func (sw *Swarm) VerifiedCountBy(network string) uint64 { return sw.VerifiedCount(network) }

// VerifiedCountFor is an alias for VerifiedCountBy.
func (sw *Swarm) VerifiedCountFor(network string) uint64 { return sw.VerifiedCount(network) }

// NumVerified is an alias for VerifiedCount.
func (sw *Swarm) NumVerified(network ...string) uint64 { return sw.VerifiedCount(network...) }

// CountVerified is an alias for VerifiedCount.
func (sw *Swarm) CountVerified(network ...string) uint64 { return sw.VerifiedCount(network...) }

// --- block data ---

// Block returns stored bytes for block.
func (sw *Swarm) Block(block uint64) []byte {
	if sw.BlockStore == nil {
		return nil
	}
	return sw.BlockStore.Block(block)
}

// GetBlock is an alias for Block.
func (sw *Swarm) GetBlock(block uint64) []byte { return sw.Block(block) }

// BlockBytes is an alias for Block.
func (sw *Swarm) BlockBytes(block uint64) []byte { return sw.Block(block) }

// ReadBlock is an alias for Block.
func (sw *Swarm) ReadBlock(block uint64) []byte { return sw.Block(block) }

// Get is an alias for Block.
func (sw *Swarm) Get(block uint64) []byte { return sw.Block(block) }

// LoadBlock is an alias for Block.
func (sw *Swarm) LoadBlock(block uint64) []byte { return sw.Block(block) }

// FetchBlock is an alias for Block.
func (sw *Swarm) FetchBlock(block uint64) []byte { return sw.Block(block) }

// --- per-network verification helpers ---

// IsVerified reports whether block is verified by any (or named) network.
func (sw *Swarm) IsVerified(block uint64, network ...string) bool {
	if sw.BlockStore == nil {
		return false
	}
	return sw.BlockStore.IsVerified(block, network...)
}

// IsVerifiedBy is an alias.
func (sw *Swarm) IsVerifiedBy(block uint64, network string) bool {
	return sw.IsVerified(block, network)
}

// VerifiedBy returns the (lexicographically smallest) network that verified block.
func (sw *Swarm) VerifiedBy(block uint64) string {
	if sw.BlockStore == nil {
		return ""
	}
	return sw.BlockStore.VerifiedBy(block)
}

// VerifiedByNetworks returns all networks that verified block.
func (sw *Swarm) VerifiedByNetworks(block uint64) []string {
	if sw.BlockStore == nil {
		return nil
	}
	return sw.BlockStore.VerifiedByNetworks(block)
}

// --- release ---

// Release releases leases held by network.
func (sw *Swarm) Release(network string, blocks []uint64) bool {
	if sw.Scheduler == nil {
		return false
	}
	return sw.Scheduler.Release(network, blocks)
}

// ReleaseBlocks is an alias for Release.
func (sw *Swarm) ReleaseBlocks(network string, blocks []uint64) bool {
	return sw.Release(network, blocks)
}

// ReleaseLeases is an alias for Release.
func (sw *Swarm) ReleaseLeases(network string, blocks []uint64) bool {
	return sw.Release(network, blocks)
}

// --- store/scheduler access ---

// Store returns the wrapped block store.
func (sw *Swarm) Store() *blockstore.BlockStore { return sw.BlockStore }

// Sched returns the wrapped scheduler.
func (sw *Swarm) Sched() *scheduler.Scheduler { return sw.Scheduler }

// SchedulerAlias returns the wrapped scheduler.
func (sw *Swarm) SchedulerAlias() *scheduler.Scheduler { return sw.Scheduler }

// --- misc aliases for store/scheduler direct use ---

// PutBlock stores bytes for block (no verification).
func (sw *Swarm) PutBlock(block uint64, data []byte) bool {
	if sw.BlockStore == nil {
		return false
	}
	return sw.BlockStore.PutBlock(block, data)
}

// PutBlockBytes is an alias for PutBlock.
func (sw *Swarm) PutBlockBytes(block uint64, data []byte) bool { return sw.PutBlock(block, data) }

// StoreBytes is an alias for PutBlock.
func (sw *Swarm) StoreBytes(block uint64, data []byte) bool { return sw.PutBlock(block, data) }

// HasBlock reports whether block has stored bytes.
func (sw *Swarm) HasBlock(block uint64) bool {
	if sw.BlockStore == nil {
		return false
	}
	return sw.BlockStore.HasBlock(block)
}

// String returns a summary.
func (sw *Swarm) String() string {
	if sw.BlockStore != nil {
		return "Swarm{" + sw.BlockStore.String() + "}"
	}
	return "Swarm{}"
}