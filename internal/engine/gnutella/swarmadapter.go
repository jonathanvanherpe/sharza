// SPDX-License-Identifier: GPL-3.0-or-later

// Package gnutella implements the Gnutella/Gnutella2 wire protocol.
//
// This file adds a stdlib-only adapter that lets the Gnutella/Gnutella2
// engines participate in Sharza's cross-network swarm as a whole-file
// source: it wraps a *swarm.Swarm and/or *scheduler.Scheduler (there is no
// RangeMap, because Gnutella/G2 transfer whole files), tracks whole-file
// completion, and exposes Lease/Complete/IsComplete hooks compatible with
// internal/swarm.Swarm and internal/scheduler.Scheduler. No networking,
// query/routing, daemon/RPC/store/config wiring is performed here. G2 is a
// whole-file source only: no UFTT/UFSet/UFGet machinery.
package gnutella

import (
	"sort"
	"sync"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
	"github.com/jonathanvanherpe/sharza/internal/blockstore"
	"github.com/jonathanvanherpe/sharza/internal/scheduler"
	"github.com/jonathanvanherpe/sharza/internal/swarm"
)

// Adapter (also SwarmAdapter) wraps a *swarm.Swarm and/or
// *scheduler.Scheduler and participates in the cross-network swarm as a
// whole-file source. It is safe for concurrent use.
type Adapter struct {
	// Wrapped swarm components.
	Swarm     *swarm.Swarm
	Scheduler *scheduler.Scheduler

	// Default network name used when a caller omits one ("gnutella" or "g2").
	Network string

	mu        sync.Mutex
	completed bool
	verified  map[uint64]struct{} // whole-file parts (single part: 0)
}

// SwarmAdapter is an alias for Adapter.
type SwarmAdapter = Adapter

// GnutellaAdapter is an alias for Adapter.
type GnutellaAdapter = Adapter

// G2Adapter is an alias for Adapter.
type G2Adapter = Adapter

// Gnutella2Adapter is an alias for Adapter.
type Gnutella2Adapter = Adapter

// Gnutella1Adapter is an alias for Adapter.
type Gnutella1Adapter = Adapter

// GnAdapter is an alias for Adapter.
type GnAdapter = Adapter

// AdapterGnutella is an alias for Adapter.
type AdapterGnutella = Adapter

// AdapterG2 is an alias for Adapter.
type AdapterG2 = Adapter

// GnutellaSwarmAdapter is an alias for Adapter.
type GnutellaSwarmAdapter = Adapter

// G2SwarmAdapter is an alias for Adapter.
type G2SwarmAdapter = Adapter

// WholeFileAdapter is an alias for Adapter.
type WholeFileAdapter = Adapter

// FileAdapter is an alias for Adapter.
type FileAdapter = Adapter

// --- constructors ---

func NewAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }

func NewSwarmAdapter(args ...interface{}) *Adapter       { return newAdapter(args...) }
func NewGnutellaAdapter(args ...interface{}) *Adapter    { return newAdapter(args...) }
func NewG2Adapter(args ...interface{}) *Adapter         { return newAdapter(args...) }
func NewGnutella2Adapter(args ...interface{}) *Adapter   { return newAdapter(args...) }
func NewGnutella1Adapter(args ...interface{}) *Adapter   { return newAdapter(args...) }
func NewGnAdapter(args ...interface{}) *Adapter          { return newAdapter(args...) }
func NewSwarmGnutellaAdapter(args ...interface{}) *Adapter {
	return newAdapter(args...)
}
func NewGnutellaSwarmAdapter(args ...interface{}) *Adapter {
	return newAdapter(args...)
}
func NewSwarmG2Adapter(args ...interface{}) *Adapter { return newAdapter(args...) }
func NewG2SwarmAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }
func NewWholeFileAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }
func NewFileAdapter(args ...interface{}) *Adapter      { return newAdapter(args...) }

func AdapterNew(args ...interface{}) *Adapter       { return newAdapter(args...) }
func SwarmAdapterNew(args ...interface{}) *Adapter  { return newAdapter(args...) }
func GnutellaAdapterNew(args ...interface{}) *Adapter { return newAdapter(args...) }
func G2AdapterNew(args ...interface{}) *Adapter     { return newAdapter(args...) }
func SwarmNewAdapter(args ...interface{}) *Adapter  { return newAdapter(args...) }

func newAdapter(args ...interface{}) *Adapter {
	a := &Adapter{Network: "gnutella", verified: make(map[uint64]struct{})}

	var sw *swarm.Swarm
	var sc *scheduler.Scheduler
	var bm *blockmap.BlockMap
	var bs *blockstore.BlockStore

	hasSize := false
	var fileSize, blockSize uint64
	var netNames []string

	for _, arg := range args {
		switch v := arg.(type) {
		case *Adapter:
			if v != nil {
				if v.Swarm != nil {
					sw = v.Swarm
				}
				if v.Scheduler != nil {
					sc = v.Scheduler
				}
				if v.Network != "" {
					a.Network = v.Network
				}
				if v.Swarm != nil {
					for _, n := range v.Swarm.Networks() {
						netNames = append(netNames, n)
					}
				}
			}
		case *swarm.Swarm:
			sw = v
		case *scheduler.Scheduler:
			sc = v
		case *blockmap.BlockMap:
			bm = v
		case *blockstore.BlockStore:
			bs = v
		case uint64:
			if !hasSize {
				fileSize = v
				hasSize = true
			} else if blockSize == 0 {
				blockSize = v
			}
		case uint:
			n := uint64(v)
			if !hasSize {
				fileSize = n
				hasSize = true
			} else if blockSize == 0 {
				blockSize = n
			}
		case int:
			n := v
			if n < 0 {
				n = 0
			}
			if !hasSize {
				fileSize = uint64(n)
				hasSize = true
			} else if blockSize == 0 {
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
			} else if blockSize == 0 {
				blockSize = uint64(n)
			}
		case string:
			netNames = append(netNames, v)
			if len(netNames) == 1 {
				a.Network = v
			}
		}
	}

	// Resolve block map.
	if bm == nil && bs != nil {
		bm = bs.BlockMap()
	}
	if bm == nil && sc != nil {
		bm = sc.BlockMap()
	}
	if bm == nil && sw != nil {
		bm = sw.BlockMap()
	}
	if bm != nil {
		if fileSize == 0 {
			fileSize = bm.FileSize()
		}
		if blockSize == 0 {
			blockSize = bm.BlockSize()
		}
	}
	if fileSize == 0 && sw != nil {
		fileSize = sw.FileSize()
	}
	if blockSize == 0 && sw != nil {
		blockSize = sw.BlockSize()
	}
	if blockSize == 0 {
		blockSize = blockmap.DefaultBlockSize
	}
	if bm == nil {
		bm = blockmap.New(fileSize, blockSize)
	}

	// Resolve scheduler.
	if sc == nil {
		sc = scheduler.New(bm)
	}
	// Resolve swarm.
	if sw == nil && sc != nil {
		args := []interface{}{sc}
		for _, n := range netNames {
			args = append(args, n)
		}
		sw = swarm.New(args...)
	}
	if sc == nil && sw != nil {
		sc = sw.Sched()
	}
	if sw == nil {
		sw = swarm.New(sc, a.Network)
	}
	if sw != nil {
		for _, n := range netNames {
			sw.AddNetwork(n)
		}
		sw.AddNetwork(a.Network)
	}
	a.Swarm = sw
	a.Scheduler = sc
	if a.Network == "" {
		a.Network = "gnutella"
	}
	return a
}

// SwarmNetworks returns tracked networks from the wrapped swarm.
func (a *Adapter) SwarmNetworks() []string {
	if a.Swarm != nil {
		return a.Swarm.Networks()
	}
	return nil
}

func (a *Adapter) defaultNetwork() string {
	if a.Network != "" {
		return a.Network
	}
	return "gnutella"
}

func (a *Adapter) blockCount() uint64 {
	if a.Swarm != nil {
		return a.Swarm.BlockCount()
	}
	if a.Scheduler != nil {
		if bm := a.Scheduler.BlockMap(); bm != nil {
			return bm.BlockCount()
		}
	}
	return 0
}

func (a *Adapter) fileSize() uint64 {
	if a.Swarm != nil {
		return a.Swarm.FileSize()
	}
	if a.Scheduler != nil {
		if bm := a.Scheduler.BlockMap(); bm != nil {
			return bm.FileSize()
		}
	}
	return 0
}

func (a *Adapter) blockSize() uint64 {
	if a.Swarm != nil {
		return a.Swarm.BlockSize()
	}
	if a.Scheduler != nil {
		if bm := a.Scheduler.BlockMap(); bm != nil {
			return bm.BlockSize()
		}
	}
	return blockmap.DefaultBlockSize
}

// --- whole-file completion tracking ---

func (a *Adapter) MarkCompleteWholeFile() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.completed = true
	a.verified[0] = struct{}{}
}

func (a *Adapter) IsWholeFileVerified() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.verified[0]
	return ok || a.completed
}

func (a *Adapter) IsFileVerified() bool { return a.IsWholeFileVerified() }
func (a *Adapter) IsVerifiedWholeFile() bool { return a.IsWholeFileVerified() }
func (a *Adapter) WholeFileVerified() bool  { return a.IsWholeFileVerified() }
func (a *Adapter) FileVerified() bool       { return a.IsWholeFileVerified() }

func (a *Adapter) IsPartVerified(part uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.verified[part]
	return ok
}
func (a *Adapter) IsVerifiedPart(part uint64) bool { return a.IsPartVerified(part) }
func (a *Adapter) PartVerified(part uint64) bool    { return a.IsPartVerified(part) }

func (a *Adapter) VerifiedParts() []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]uint64, 0, len(a.verified))
	for p := range a.verified {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func (a *Adapter) VerifiedPartList() []uint64     { return a.VerifiedParts() }
func (a *Adapter) VerifiedPartIndices() []uint64  { return a.VerifiedParts() }
func (a *Adapter) VerifiedPartCount() uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	return uint64(len(a.verified))
}

// --- Lease / Complete / IsComplete ---

func (a *Adapter) parseLeaseArgs(args []interface{}) (string, int) {
	network := ""
	n := 0
	hasN := false
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			if network == "" {
				network = v
			}
		case int:
			if !hasN {
				n = v
				hasN = true
			}
		case int64:
			if !hasN {
				n = int(v)
				hasN = true
			}
		case uint64:
			if !hasN {
				n = int(v)
				hasN = true
			}
		case uint:
			if !hasN {
				n = int(v)
				hasN = true
			}
		}
	}
	if n < 0 {
		n = 0
	}
	return network, n
}

func (a *Adapter) Lease(args ...interface{}) []uint64 {
	network, _ := a.parseLeaseArgs(args)
	if network == "" {
		network = a.defaultNetwork()
	}
	bc := a.blockCount()

	// Attempt to lease all outstanding blocks in the wrapped components.
	if a.Swarm != nil {
		a.Swarm.Lease(network, int(bc))
	} else if a.Scheduler != nil {
		a.Scheduler.Lease(network, int(bc))
	}

	// Return outstanding (unverified) canonical block indices as one
	// whole-file lease.
	out := make([]uint64, 0)
	for i := uint64(0); i < bc; i++ {
		verified := false
		if a.Swarm != nil {
			verified = a.Swarm.IsVerified(i)
		} else if a.Scheduler != nil {
			if bm := a.Scheduler.BlockMap(); bm != nil {
				verified = bm.IsVerified(i)
			}
		}
		if verified {
			continue
		}
		out = append(out, i)
	}
	if out == nil {
		out = []uint64{}
	}
	return out
}

// Alias methods for Lease.
func (a *Adapter) LeaseBlocks(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) LeaseFiles(args ...interface{}) []uint64  { return a.Lease(args...) }
func (a *Adapter) LeaseFile(args ...interface{}) []uint64   { return a.Lease(args...) }
func (a *Adapter) LeaseWholeFile(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) Acquire(args ...interface{}) []uint64     { return a.Lease(args...) }
func (a *Adapter) AcquireBlocks(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) AcquireFiles(args ...interface{}) []uint64  { return a.Lease(args...) }
func (a *Adapter) GetBlocks(args ...interface{}) []uint64     { return a.Lease(args...) }
func (a *Adapter) GetFiles(args ...interface{}) []uint64      { return a.Lease(args...) }
func (a *Adapter) Take(args ...interface{}) []uint64          { return a.Lease(args...) }
func (a *Adapter) TakeBlocks(args ...interface{}) []uint64     { return a.Lease(args...) }
func (a *Adapter) TakeFiles(args ...interface{}) []uint64     { return a.Lease(args...) }

func (a *Adapter) parseCompleteArgs(args []interface{}) (string, []byte) {
	network := ""
	var data []byte
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			if network == "" {
				network = v
			}
		case []byte:
			data = v
		}
	}
	if network == "" {
		network = a.defaultNetwork()
	}
	return network, data
}

func (a *Adapter) Complete(args ...interface{}) bool {
	network, data := a.parseCompleteArgs(args)
	if network == "" {
		network = a.defaultNetwork()
	}

	a.mu.Lock()
	_, already := a.verified[0]
	if !already {
		a.verified[0] = struct{}{}
	}
	a.completed = true
	a.mu.Unlock()

	bc := a.blockCount()
	anyNew := false
	for i := uint64(0); i < bc; i++ {
		wasVerified := false
		if a.Swarm != nil {
			wasVerified = a.Swarm.IsVerified(i, network)
		}
		blockNew := false
		if a.Swarm != nil {
			if a.Swarm.Complete(network, i, data) {
				blockNew = true
			}
		} else if a.Scheduler != nil {
			if !wasVerified {
				if a.Scheduler.Complete(i) {
					blockNew = true
				}
			}
		}
		if blockNew {
			anyNew = true
		}
	}
	if a.Scheduler != nil && a.Swarm != nil {
		for i := uint64(0); i < bc; i++ {
			a.Scheduler.Complete(i)
		}
	}
	if bc == 0 {
		return true
	}
	return anyNew
}

// Alias methods for Complete.
func (a *Adapter) CompleteFile(args ...interface{}) bool { return a.Complete(args...) }
func (a *Adapter) CompleteFiles(args ...interface{}) bool { return a.Complete(args...) }
func (a *Adapter) CompleteWholeFile(args ...interface{}) bool { return a.Complete(args...) }
func (a *Adapter) Finish(args ...interface{}) bool          { return a.Complete(args...) }
func (a *Adapter) Verify(args ...interface{}) bool         { return a.Complete(args...) }
func (a *Adapter) MarkComplete(args ...interface{}) bool   { return a.Complete(args...) }
func (a *Adapter) StoreComplete(args ...interface{}) bool  { return a.Complete(args...) }

func (a *Adapter) parseIsCompleteArgs(args []interface{}) string {
	network := ""
	for _, arg := range args {
		if v, ok := arg.(string); ok {
			if network == "" {
				network = v
			}
		}
	}
	if network == "" {
		network = a.defaultNetwork()
	}
	return network
}

func (a *Adapter) IsComplete(args ...interface{}) bool {
	network := a.parseIsCompleteArgs(args)
	if network == "" {
		network = a.defaultNetwork()
	}
	canon := true
	if a.Swarm != nil {
		canon = a.Swarm.IsComplete(network)
	} else if a.Scheduler != nil {
		if bm := a.Scheduler.BlockMap(); bm != nil {
			canon = bm.AllVerified()
		}
	}
	return canon
}

// Alias methods for IsComplete.
func (a *Adapter) IsDone(args ...interface{}) bool        { return a.IsComplete(args...) }
func (a *Adapter) IsFinished(args ...interface{}) bool    { return a.IsComplete(args...) }
func (a *Adapter) AllComplete(args ...interface{}) bool   { return a.IsComplete(args...) }
func (a *Adapter) AllVerified(args ...interface{}) bool   { return a.IsComplete(args...) }
func (a *Adapter) Done(args ...interface{}) bool          { return a.IsComplete(args...) }
func (a *Adapter) Finished(args ...interface{}) bool      { return a.IsComplete(args...) }
func (a *Adapter) Completed(args ...interface{}) bool     { return a.IsComplete(args...) }

// Expose underlying for convenience.
func (a *Adapter) BlockMap() *blockmap.BlockMap {
	if a.Scheduler != nil {
		return a.Scheduler.BlockMap()
	}
	if a.Swarm != nil {
		return a.Swarm.BlockMap()
	}
	return nil
}
func (a *Adapter) Store() interface{} {
	if a.Swarm != nil {
		return a.Swarm.Store()
	}
	return nil
}
func (a *Adapter) Sched() *scheduler.Scheduler { return a.Scheduler }

// IsVerified reports whether block is verified by any network (convenience).
func (a *Adapter) IsVerified(block uint64, network ...string) bool {
	if a.Swarm != nil {
		return a.Swarm.IsVerified(block, network...)
	}
	if a.Scheduler != nil {
		if bm := a.Scheduler.BlockMap(); bm != nil {
			return bm.IsVerified(block)
		}
	}
	return false
}
