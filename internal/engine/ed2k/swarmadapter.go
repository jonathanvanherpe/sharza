// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This file adds a stdlib-only adapter that lets the eDonkey2000 engine
// participate in Sharza's cross-network swarm: it translates between
// eDonkey2000 part indices and canonical block indices using the existing
// RangeMap, tracks which parts have been verified, and exposes Lease/
// Complete/IsComplete hooks compatible with internal/swarm.Swarm and
// internal/scheduler.Scheduler. No networking, .part.met I/O, AICH or
// daemon/RPC/store/config wiring is performed here.
package ed2k

import (
	"sort"
	"sync"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
	"github.com/jonathanvanherpe/sharza/internal/scheduler"
	"github.com/jonathanvanherpe/sharza/internal/swarm"
)

// DefaultPartSize is the default eDonkey2000 part size: 9.5 MiB (9728000 bytes).
const DefaultPartSize = 9728000

// Aliases for DefaultPartSize.
const (
	DefaultED2KPartSize        = DefaultPartSize
	DefaultEd2kPartSize        = DefaultPartSize
	DefaultPartLen             = DefaultPartSize
	DefaultED2KPartLen         = DefaultPartSize
	ED2KDefaultPartSize        = DefaultPartSize
	Ed2kDefaultPartSize        = DefaultPartSize
	PartSizeDefault            = DefaultPartSize
	DefaultEDonkeyPartSize     = DefaultPartSize
	DefaultEDonkey2000PartSize = DefaultPartSize
)

// Adapter (also SwarmAdapter) wraps a *RangeMap together with a *swarm.Swarm
// and/or *scheduler.Scheduler and translates between eDonkey2000 parts and
// canonical blocks. It is safe for concurrent use.
type Adapter struct {
	// Embedded range map (also addressable as RangeMap).
	*RangeMap

	// Alias fields for the wrapped range map.
	RM   *RangeMap
	RMap *RangeMap
	Map  *RangeMap

	// Wrapped swarm components.
	Swarm     *swarm.Swarm
	Scheduler *scheduler.Scheduler

	// Default network name used when a caller omits one.
	Network string

	mu       sync.Mutex
	verified map[uint64]struct{}
}

// SwarmAdapter is an alias for Adapter.
type SwarmAdapter = Adapter

// ED2KAdapter is an alias for Adapter.
type ED2KAdapter = Adapter

// Ed2kAdapter is an alias for Adapter.
type Ed2kAdapter = Adapter

// ED2kAdapter is an alias for Adapter.
type ED2kAdapter = Adapter

// EDonkeyAdapter is an alias for Adapter.
type EDonkeyAdapter = Adapter

// EDonkey2000Adapter is an alias for Adapter.
type EDonkey2000Adapter = Adapter

// AdapterED2K is an alias for Adapter.
type AdapterED2K = Adapter

// AdapterEd2k is an alias for Adapter.
type AdapterEd2k = Adapter

// RangeAdapter is an alias for Adapter.
type RangeAdapter = Adapter

// PartAdapter is an alias for Adapter.
type PartAdapter = Adapter

// --- constructors ---

func NewAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }

func NewSwarmAdapter(args ...interface{}) *Adapter   { return newAdapter(args...) }
func NewED2KAdapter(args ...interface{}) *Adapter    { return newAdapter(args...) }
func NewEd2kAdapter(args ...interface{}) *Adapter    { return newAdapter(args...) }
func NewED2kAdapter(args ...interface{}) *Adapter    { return newAdapter(args...) }
func NewEDonkeyAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }
func NewEDonkey2000Adapter(args ...interface{}) *Adapter {
	return newAdapter(args...)
}
func NewRangeAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }
func NewPartAdapter(args ...interface{}) *Adapter  { return newAdapter(args...) }
func NewSwarmED2KAdapter(args ...interface{}) *Adapter {
	return newAdapter(args...)
}
func NewED2KSwarmAdapter(args ...interface{}) *Adapter {
	return newAdapter(args...)
}

func AdapterNew(args ...interface{}) *Adapter   { return newAdapter(args...) }
func SwarmAdapterNew(args ...interface{}) *Adapter { return newAdapter(args...) }
func ED2KAdapterNew(args ...interface{}) *Adapter  { return newAdapter(args...) }
func SwarmNewAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }

func newAdapter(args ...interface{}) *Adapter {
	a := &Adapter{Network: "ed2k", verified: make(map[uint64]struct{})}

	var rm *RangeMap
	var sw *swarm.Swarm
	var sc *scheduler.Scheduler
	var bm *blockmap.BlockMap

	hasSize := false
	var fileSize, partSize, blockSize uint64
	var netNames []string

	for _, arg := range args {
		switch v := arg.(type) {
		case *Adapter:
			if v != nil {
				if v.RangeMap != nil {
					rm = v.RangeMap
				}
				if v.RM != nil {
					rm = v.RM
				}
				if v.RMap != nil {
					rm = v.RMap
				}
				if v.Map != nil {
					rm = v.Map
				}
				if v.Swarm != nil {
					sw = v.Swarm
				}
				if v.Scheduler != nil {
					sc = v.Scheduler
				}
				if v.Network != "" {
					a.Network = v.Network
				}
				for _, n := range v.SwarmNetworks() {
					netNames = append(netNames, n)
				}
			}
		case *RangeMap:
			rm = v
		case RangeMap:
			vv := v
			rm = &vv
		case *swarm.Swarm:
			sw = v
		case *scheduler.Scheduler:
			sc = v
		case *blockmap.BlockMap:
			bm = v
		case uint64:
			if !hasSize {
				fileSize = v
				hasSize = true
			} else if partSize == 0 && fileSize != 0 {
				partSize = v
			} else {
				blockSize = v
			}
		case uint:
			n := uint64(v)
			if !hasSize {
				fileSize = n
				hasSize = true
			} else if partSize == 0 {
				partSize = n
			} else {
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
			} else if partSize == 0 {
				partSize = uint64(n)
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
			} else if partSize == 0 {
				partSize = uint64(n)
			} else {
				blockSize = uint64(n)
			}
		case string:
			netNames = append(netNames, v)
			if a.Network == "ed2k" && len(netNames) == 1 && v != "ed2k" && v != "ed2k2000" {
				// keep default network unless explicitly a network name? mirror bt: first string becomes network
			}
			if len(netNames) == 1 {
				a.Network = v
			}
		}
	}

	// Resolve range map.
	if rm == nil {
		if bm != nil {
			fs := bm.FileSize()
			bs := bm.BlockSize()
			if fileSize != 0 {
				fs = fileSize
			}
			if blockSize != 0 {
				bs = blockSize
			}
			if partSize == 0 {
				partSize = DefaultPartSize
			}
			if bs == 0 {
				bs = blockmap.DefaultBlockSize
			}
			rm = &RangeMap{FileSize: fs, PartSize: partSize, BlockSize: bs}
		} else {
			if fileSize == 0 && sw != nil {
				fileSize = sw.FileSize()
			}
			if blockSize == 0 && sw != nil {
				blockSize = sw.BlockSize()
			}
			if blockSize == 0 {
				blockSize = blockmap.DefaultBlockSize
			}
			if partSize == 0 {
				partSize = DefaultPartSize
			}
			if fileSize == 0 && sc != nil {
				if bmm := sc.BlockMap(); bmm != nil {
					fileSize = bmm.FileSize()
					if blockSize == 0 {
						blockSize = bmm.BlockSize()
					}
				}
			}
			rm = &RangeMap{FileSize: fileSize, PartSize: partSize, BlockSize: blockSize}
		}
	}
	if rm != nil {
		fs, ps, bs := rm.normalized()
		if fs == 0 && sw != nil {
			fs = sw.FileSize()
		}
		if bs == 0 {
			bs = blockmap.DefaultBlockSize
		}
		if ps == 0 {
			ps = DefaultPartSize
		}
		rm = &RangeMap{FileSize: fs, PartSize: ps, BlockSize: bs}
	}

	a.RangeMap = rm
	a.RM = rm
	a.RMap = rm
	a.Map = rm
	// Embed pointer
	a.RangeMap = rm // already
	// set embedded field
	// We need set embedded *RangeMap. Since Adapter has embedded *RangeMap, assign:
	a.RangeMap = rm
	// Actually embedded field name is RangeMap, same as field. Already set.

	// Resolve swarm/scheduler.
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
	if sc == nil && rm != nil {
		sc = scheduler.New(blockmap.New(rm.FileSize, rm.BlockSize))
	}
	if sw == nil {
		args := []interface{}{sc}
		for _, n := range netNames {
			args = append(args, n)
		}
		sw = swarm.New(args...)
	}
	if sw != nil {
		for _, n := range netNames {
			sw.AddNetwork(n)
		}
	}
	a.Swarm = sw
	a.Scheduler = sc
	if a.Network == "" {
		a.Network = "ed2k"
	}
	// Ensure embedded pointer is set (it is a.RangeMap)
	a.RangeMap = rm
	return a
}

// Note: embedded field assignment done via a.RangeMap above.

func defaultPartSize(blockSize uint64) uint64 {
	return DefaultPartSize
}

// SwarmNetworks returns tracked networks from the wrapped swarm.
func (a *Adapter) SwarmNetworks() []string {
	if a.Swarm != nil {
		return a.Swarm.Networks()
	}
	return nil
}

func (a *Adapter) rangeMap() *RangeMap {
	if a.RangeMap != nil {
		return a.RangeMap
	}
	if a.RM != nil {
		return a.RM
	}
	if a.RMap != nil {
		return a.RMap
	}
	if a.Map != nil {
		return a.Map
	}
	return nil
}

func (a *Adapter) defaultNetwork() string {
	if a.Network != "" {
		return a.Network
	}
	return "ed2k"
}

// --- translation helpers ---

func (a *Adapter) fileSize() uint64 {
	if rm := a.rangeMap(); rm != nil {
		fs, _, _ := rm.normalized()
		if fs != 0 {
			return fs
		}
	}
	if a.Swarm != nil {
		return a.Swarm.FileSize()
	}
	return 0
}
func (a *Adapter) partSize() uint64 {
	if rm := a.rangeMap(); rm != nil {
		_, ps, _ := rm.normalized()
		if ps != 0 {
			return ps
		}
	}
	return DefaultPartSize
}
func (a *Adapter) blockSize() uint64 {
	if rm := a.rangeMap(); rm != nil {
		_, _, bs := rm.normalized()
		if bs != 0 {
			return bs
		}
	}
	if a.Swarm != nil {
		return a.Swarm.BlockSize()
	}
	return blockmap.DefaultBlockSize
}

// CanonicalBlocksForPart returns canonical blocks overlapping part.
func (a *Adapter) CanonicalBlocksForPart(part uint64) []uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.CanonicalBlocksForPart(part)
	}
	return nil
}
// Alias: piece naming
func (a *Adapter) CanonicalBlocksForPiece(part uint64) []uint64 {
	return a.CanonicalBlocksForPart(part)
}

// Alias methods.
func (a *Adapter) MapPartToBlocks(part uint64) []uint64 { return a.CanonicalBlocksForPart(part) }
func (a *Adapter) BlocksForPart(part uint64) []uint64   { return a.CanonicalBlocksForPart(part) }
func (a *Adapter) PartToBlocks(part uint64) []uint64    { return a.CanonicalBlocksForPart(part) }
func (a *Adapter) MapPieceToBlocks(part uint64) []uint64 { return a.CanonicalBlocksForPart(part) }
func (a *Adapter) BlocksForPiece(part uint64) []uint64   { return a.CanonicalBlocksForPart(part) }
func (a *Adapter) PieceToBlocks(part uint64) []uint64    { return a.CanonicalBlocksForPart(part) }

func (a *Adapter) PartsForBlock(block uint64) []uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.PartsForBlock(block)
	}
	return nil
}
func (a *Adapter) MapBlockToParts(block uint64) []uint64 { return a.PartsForBlock(block) }
func (a *Adapter) BlockToParts(block uint64) []uint64    { return a.PartsForBlock(block) }
func (a *Adapter) PartsForCanonicalBlock(block uint64) []uint64 {
	return a.PartsForBlock(block)
}
// piece naming aliases
func (a *Adapter) PiecesForBlock(block uint64) []uint64 { return a.PartsForBlock(block) }
func (a *Adapter) MapBlockToPieces(block uint64) []uint64 { return a.PartsForBlock(block) }
func (a *Adapter) BlockToPieces(block uint64) []uint64    { return a.PartsForBlock(block) }
func (a *Adapter) PiecesForCanonicalBlock(block uint64) []uint64 {
	return a.PartsForBlock(block)
}

func (a *Adapter) PartCount() uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.PartCount()
	}
	return 0
}
// RangeMap has no PartCount method! Need compute. Oops.
func (a *Adapter) PieceCount() uint64 { return a.PartCount() }

func (a *Adapter) BlockCount() uint64 {
	if rm := a.rangeMap(); rm != nil {
		fs, _, bs := rm.normalized()
		_ = fs
		_ = bs
		// use Swarm if available
	}
	if a.Swarm != nil {
		return a.Swarm.BlockCount()
	}
	if rm := a.rangeMap(); rm != nil {
		// compute
		fs, _, bs := rm.normalized()
		if fs == 0 || bs == 0 {
			return 0
		}
		return (fs + bs - 1) / bs
	}
	return 0
}
func (a *Adapter) FileSize() uint64 { return a.fileSize() }
func (a *Adapter) PartSize() uint64 { return a.partSize() }
func (a *Adapter) PieceSize() uint64 { return a.partSize() }
func (a *Adapter) BlockSize() uint64 { return a.blockSize() }

// --- verified part tracking ---

func (a *Adapter) MarkPartVerified(part uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.verified[part] = struct{}{}
}
func (a *Adapter) MarkVerifiedPart(part uint64) { a.MarkPartVerified(part) }
func (a *Adapter) VerifyPart(part uint64)       { a.MarkPartVerified(part) }
func (a *Adapter) MarkPartComplete(part uint64) { a.MarkPartVerified(part) }

// piece naming
func (a *Adapter) MarkPieceVerified(part uint64) { a.MarkPartVerified(part) }
func (a *Adapter) MarkVerifiedPiece(part uint64) { a.MarkPartVerified(part) }
func (a *Adapter) VerifyPiece(part uint64)       { a.MarkPartVerified(part) }
func (a *Adapter) MarkPieceComplete(part uint64) { a.MarkPartVerified(part) }

func (a *Adapter) IsPartVerified(part uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.verified[part]
	return ok
}
func (a *Adapter) IsVerifiedPart(part uint64) bool { return a.IsPartVerified(part) }
func (a *Adapter) PartVerified(part uint64) bool   { return a.IsPartVerified(part) }

func (a *Adapter) IsPieceVerified(part uint64) bool { return a.IsPartVerified(part) }
func (a *Adapter) IsVerifiedPiece(part uint64) bool { return a.IsPartVerified(part) }
func (a *Adapter) PieceVerified(part uint64) bool   { return a.IsPartVerified(part) }

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

func (a *Adapter) VerifiedPieces() []uint64        { return a.VerifiedParts() }
func (a *Adapter) VerifiedPieceList() []uint64     { return a.VerifiedParts() }
func (a *Adapter) VerifiedPieceIndices() []uint64  { return a.VerifiedParts() }
func (a *Adapter) VerifiedPieceCount() uint64     { return a.VerifiedPartCount() }

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
	network, n := a.parseLeaseArgs(args)
	if network == "" {
		network = a.defaultNetwork()
	}
	var blocks []uint64
	if a.Swarm != nil {
		blocks = a.Swarm.Lease(network, n)
	} else if a.Scheduler != nil {
		blocks = a.Scheduler.Lease(network, n)
	}
	seen := make(map[uint64]struct{})
	out := make([]uint64, 0)
	for _, b := range blocks {
		for _, p := range a.PartsForBlock(b) {
			if _, ok := seen[p]; ok {
				continue
			}
			if a.IsPartVerified(p) {
				continue
			}
			seen[p] = struct{}{}
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	if out == nil {
		out = []uint64{}
	}
	return out
}

// Alias methods for Lease.
func (a *Adapter) LeaseParts(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) LeasePieces(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) LeaseBlocks(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) Acquire(args ...interface{}) []uint64     { return a.Lease(args...) }
func (a *Adapter) AcquireParts(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) AcquirePieces(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) AcquireBlocks(args ...interface{}) []uint64  { return a.Lease(args...) }
func (a *Adapter) GetParts(args ...interface{}) []uint64      { return a.Lease(args...) }
func (a *Adapter) GetPieces(args ...interface{}) []uint64     { return a.Lease(args...) }
func (a *Adapter) GetBlocks(args ...interface{}) []uint64     { return a.Lease(args...) }
func (a *Adapter) Take(args ...interface{}) []uint64           { return a.Lease(args...) }
func (a *Adapter) TakeParts(args ...interface{}) []uint64      { return a.Lease(args...) }
func (a *Adapter) TakePieces(args ...interface{}) []uint64     { return a.Lease(args...) }

func (a *Adapter) parseCompleteArgs(args []interface{}) (string, uint64, []byte, bool) {
	network := ""
	var part uint64
	var data []byte
	hasPart := false
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			if network == "" {
				network = v
			}
		case []byte:
			data = v
		case uint64:
			if !hasPart {
				part = v
				hasPart = true
			}
		case uint:
			if !hasPart {
				part = uint64(v)
				hasPart = true
			}
		case int:
			if !hasPart {
				if v < 0 {
					v = 0
				}
				part = uint64(v)
				hasPart = true
			}
		case int64:
			if !hasPart {
				if v < 0 {
					v = 0
				}
				part = uint64(v)
				hasPart = true
			}
		}
	}
	if network == "" {
		network = a.defaultNetwork()
	}
	if !hasPart {
		return network, 0, data, false
	}
	return network, part, data, true
}

func (a *Adapter) Complete(args ...interface{}) bool {
	network, part, data, ok := a.parseCompleteArgs(args)
	if !ok {
		return false
	}
	a.mu.Lock()
	_, already := a.verified[part]
	if !already {
		a.verified[part] = struct{}{}
	}
	a.mu.Unlock()

	blocks := a.CanonicalBlocksForPart(part)
	anyNew := !already
	for _, b := range blocks {
		blockNew := false
		if a.Swarm != nil {
			if a.Swarm.Complete(network, b, data) {
				blockNew = true
			}
		} else if a.Scheduler != nil {
			if a.Scheduler.Complete(b) {
				blockNew = true
			}
		}
		if blockNew {
			anyNew = true
		}
	}
	if a.Scheduler != nil && a.Swarm != nil {
		for _, b := range blocks {
			a.Scheduler.Complete(b)
		}
	}
	return anyNew
}

// Alias methods for Complete.
func (a *Adapter) CompletePart(args ...interface{}) bool { return a.Complete(args...) }
func (a *Adapter) CompleteParts(args ...interface{}) bool { return a.Complete(args...) }
func (a *Adapter) CompletePiece(args ...interface{}) bool { return a.Complete(args...) }
func (a *Adapter) CompletePieces(args ...interface{}) bool { return a.Complete(args...) }
func (a *Adapter) Finish(args ...interface{}) bool         { return a.Complete(args...) }
func (a *Adapter) Verify(args ...interface{}) bool        { return a.Complete(args...) }
func (a *Adapter) MarkComplete(args ...interface{}) bool  { return a.Complete(args...) }
func (a *Adapter) StoreComplete(args ...interface{}) bool { return a.Complete(args...) }

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
	// all parts verified?
	pc := a.PartCount()
	allParts := true
	a.mu.Lock()
	for i := uint64(0); i < pc; i++ {
		if _, ok := a.verified[i]; !ok {
			allParts = false
			break
		}
	}
	a.mu.Unlock()
	if pc == 0 {
		allParts = true
	}
	// canonical
	canon := true
	if a.Swarm != nil {
		canon = a.Swarm.IsComplete(network)
	} else if a.Scheduler != nil {
		if bm := a.Scheduler.BlockMap(); bm != nil {
			canon = bm.AllVerified()
		}
	}
	return allParts && canon
}

// Alias methods for IsComplete.
func (a *Adapter) IsDone(args ...interface{}) bool      { return a.IsComplete(args...) }
func (a *Adapter) IsFinished(args ...interface{}) bool  { return a.IsComplete(args...) }
func (a *Adapter) AllComplete(args ...interface{}) bool { return a.IsComplete(args...) }
func (a *Adapter) AllVerified(args ...interface{}) bool  { return a.IsComplete(args...) }
func (a *Adapter) Done(args ...interface{}) bool         { return a.IsComplete(args...) }
func (a *Adapter) Finished(args ...interface{}) bool    { return a.IsComplete(args...) }
func (a *Adapter) Completed(args ...interface{}) bool   { return a.IsComplete(args...) }

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

// RangeMap has normalized() but no PartCount/BlockCount/PieceCount methods.
// Add helper methods on RangeMap? The bt RangeMap has PieceCount/BlockCount.
// ed2k RangeMap lacks them. Add methods to RangeMap via extension? Can't add
// to existing type in another file? We can add methods in this file.
func (rm *RangeMap) PartCount() uint64 {
	if rm == nil {
		return 0
	}
	fs, ps, _ := rm.normalized()
	if fs == 0 || ps == 0 {
		return 0
	}
	return (fs + ps - 1) / ps
}
func (rm *RangeMap) PieceCount() uint64 { return rm.PartCount() }
func (rm *RangeMap) BlockCount() uint64 {
	if rm == nil {
		return 0
	}
	fs, _, bs := rm.normalized()
	if fs == 0 || bs == 0 {
		return 0
	}
	return (fs + bs - 1) / bs
}

// CanonicalBlocksForPart already defined in rangemap.go.

// Embedded field is *RangeMap; ensure methods promoted. Already.

var _ = defaultPartSize