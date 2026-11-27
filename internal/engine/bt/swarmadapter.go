// SPDX-License-Identifier: GPL-3.0-or-later

// Package bt implements the BitTorrent protocol engine.
//
// This file adds a stdlib-only adapter that lets the BitTorrent engine
// participate in Sharza's cross-network swarm: it translates between
// BitTorrent piece indices and canonical block indices using the existing
// RangeMap, tracks which pieces have been verified, and exposes Lease/
// Complete/IsComplete hooks compatible with internal/swarm.Swarm and
// internal/scheduler.Scheduler. No networking, metainfo I/O or client
// changes are performed here.
package bt

import (
	"sort"
	"sync"

	"github.com/jonathanvanherpe/sharza/internal/blockmap"
	"github.com/jonathanvanherpe/sharza/internal/scheduler"
	"github.com/jonathanvanherpe/sharza/internal/swarm"
)

// Adapter (also SwarmAdapter) wraps a *RangeMap together with a *swarm.Swarm
// and/or *scheduler.Scheduler and translates between BitTorrent pieces and
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

// BTAdapter is an alias for Adapter.
type BTAdapter = Adapter

// BtAdapter is an alias for Adapter.
type BtAdapter = Adapter

// AdapterBT is an alias for Adapter.
type AdapterBT = Adapter

// RangeAdapter is an alias for Adapter.
type RangeAdapter = Adapter

// PieceAdapter is an alias for Adapter.
type PieceAdapter = Adapter

// NewAdapter builds an Adapter from a flexible set of arguments, mirroring
// swarm.New: *RangeMap, *swarm.Swarm, *scheduler.Scheduler, *blockmap.BlockMap,
// file/piece/block sizes as integers, and network names as strings.
func NewAdapter(args ...interface{}) *Adapter {
	return newAdapter(args...)
}

// Alias constructors.
func NewSwarmAdapter(args ...interface{}) *Adapter   { return newAdapter(args...) }
func NewBTAdapter(args ...interface{}) *Adapter      { return newAdapter(args...) }
func NewBtAdapter(args ...interface{}) *Adapter      { return newAdapter(args...) }
func NewBT(args ...interface{}) *Adapter             { return newAdapter(args...) }
func NewBt(args ...interface{}) *Adapter             { return newAdapter(args...) }
func NewRangeAdapter(args ...interface{}) *Adapter   { return newAdapter(args...) }
func NewPieceAdapter(args ...interface{}) *Adapter   { return newAdapter(args...) }
func NewSwarmBTAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }

func AdapterNew(args ...interface{}) *Adapter   { return newAdapter(args...) }
func SwarmAdapterNew(args ...interface{}) *Adapter { return newAdapter(args...) }
func BTAdapterNew(args ...interface{}) *Adapter    { return newAdapter(args...) }
func SwarmNewAdapter(args ...interface{}) *Adapter { return newAdapter(args...) }

func newAdapter(args ...interface{}) *Adapter {
	a := &Adapter{Network: "bt", verified: make(map[uint64]struct{})}

	var rm *RangeMap
	var sw *swarm.Swarm
	var sc *scheduler.Scheduler
	var bm *blockmap.BlockMap

	hasSize := false
	var fileSize, pieceSize, blockSize uint64
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
			} else if pieceSize == 0 && fileSize != 0 {
				pieceSize = v
			} else {
				blockSize = v
			}
		case uint:
			n := uint64(v)
			if !hasSize {
				fileSize = n
				hasSize = true
			} else if pieceSize == 0 {
				pieceSize = n
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
			} else if pieceSize == 0 {
				pieceSize = uint64(n)
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
			} else if pieceSize == 0 {
				pieceSize = uint64(n)
			} else {
				blockSize = uint64(n)
			}
		case string:
			netNames = append(netNames, v)
			if a.Network == "bt" && len(netNames) == 1 {
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
			if pieceSize == 0 {
				pieceSize = defaultPieceSize(bs)
			}
			if bs == 0 {
				bs = blockmap.DefaultBlockSize
			}
			rm = &RangeMap{FileSize: fs, PieceSize: pieceSize, BlockSize: bs}
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
			if pieceSize == 0 {
				pieceSize = defaultPieceSize(blockSize)
			}
			if fileSize == 0 && sc != nil {
				if bmm := sc.BlockMap(); bmm != nil {
					fileSize = bmm.FileSize()
					if blockSize == 0 {
						blockSize = bmm.BlockSize()
					}
				}
			}
			rm = &RangeMap{FileSize: fileSize, PieceSize: pieceSize, BlockSize: blockSize}
		}
	}
	if rm != nil {
		// resolve zero values
		fs, ps, bs := rm.normalized()
		if fs == 0 && sw != nil {
			fs = sw.FileSize()
		}
		if bs == 0 {
			bs = blockmap.DefaultBlockSize
		}
		if ps == 0 {
			ps = defaultPieceSize(bs)
		}
		rm = &RangeMap{FileSize: fs, PieceSize: ps, BlockSize: bs}
	}

	a.RangeMap = rm
	a.RM = rm
	a.RMap = rm
	a.Map = rm

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
		a.Network = "bt"
	}
	return a
}

func defaultPieceSize(blockSize uint64) uint64 {
	if blockSize == 0 {
		blockSize = blockmap.DefaultBlockSize
	}
	// common BitTorrent default piece size
	return uint64(1 << 18)
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
	return "bt"
}

// --- translation helpers ---

func (a *Adapter) fileSize() uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.FileSize
	}
	if a.Swarm != nil {
		return a.Swarm.FileSize()
	}
	return 0
}

func (a *Adapter) pieceSize() uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.PieceSize
	}
	return 0
}

func (a *Adapter) blockSize() uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.BlockSize
	}
	if a.Swarm != nil {
		return a.Swarm.BlockSize()
	}
	return blockmap.DefaultBlockSize
}

// CanonicalBlocksForPiece returns canonical blocks overlapping piece.
func (a *Adapter) CanonicalBlocksForPiece(piece uint64) []uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.CanonicalBlocksForPiece(piece)
	}
	return nil
}

// Alias methods.
func (a *Adapter) MapPieceToBlocks(piece uint64) []uint64 { return a.CanonicalBlocksForPiece(piece) }
func (a *Adapter) BlocksForPiece(piece uint64) []uint64   { return a.CanonicalBlocksForPiece(piece) }
func (a *Adapter) PieceToBlocks(piece uint64) []uint64    { return a.CanonicalBlocksForPiece(piece) }
func (a *Adapter) PiecesForBlock(block uint64) []uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.PiecesForBlock(block)
	}
	return nil
}
func (a *Adapter) MapBlockToPieces(block uint64) []uint64 { return a.PiecesForBlock(block) }
func (a *Adapter) BlockToPieces(block uint64) []uint64    { return a.PiecesForBlock(block) }
func (a *Adapter) BlocksToPieces(block uint64) []uint64    { return a.PiecesForBlock(block) }
func (a *Adapter) PiecesForCanonicalBlock(block uint64) []uint64 {
	return a.PiecesForBlock(block)
}

func (a *Adapter) PieceCount() uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.PieceCount()
	}
	return 0
}
func (a *Adapter) BlockCount() uint64 {
	if rm := a.rangeMap(); rm != nil {
		return rm.BlockCount()
	}
	if a.Swarm != nil {
		return a.Swarm.BlockCount()
	}
	return 0
}
func (a *Adapter) FileSize() uint64 { return a.fileSize() }
func (a *Adapter) PieceSize() uint64 { return a.pieceSize() }
func (a *Adapter) BlockSize() uint64 { return a.blockSize() }

// --- verified piece tracking ---

func (a *Adapter) MarkPieceVerified(piece uint64) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.verified[piece] = struct{}{}
}
func (a *Adapter) MarkVerifiedPiece(piece uint64) { a.MarkPieceVerified(piece) }
func (a *Adapter) VerifyPiece(piece uint64)       { a.MarkPieceVerified(piece) }
func (a *Adapter) MarkPieceComplete(piece uint64) { a.MarkPieceVerified(piece) }

func (a *Adapter) IsPieceVerified(piece uint64) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.verified[piece]
	return ok
}
func (a *Adapter) IsVerifiedPiece(piece uint64) bool { return a.IsPieceVerified(piece) }
func (a *Adapter) PieceVerified(piece uint64) bool    { return a.IsPieceVerified(piece) }

func (a *Adapter) VerifiedPieces() []uint64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]uint64, 0, len(a.verified))
	for p := range a.verified {
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func (a *Adapter) VerifiedPieceList() []uint64 { return a.VerifiedPieces() }
func (a *Adapter) VerifiedPieceIndices() []uint64 { return a.VerifiedPieces() }
func (a *Adapter) VerifiedPieceCount() uint64 {
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
	network, n := a.parseLeaseArgs(args)
	if network == "" {
		network = a.defaultNetwork()
	}
	// Lease canonical blocks from wrapped components.
	var blocks []uint64
	if a.Swarm != nil {
		blocks = a.Swarm.Lease(network, n)
	} else if a.Scheduler != nil {
		blocks = a.Scheduler.Lease(network, n)
	}
	// Map to pieces.
	seen := make(map[uint64]struct{})
	out := make([]uint64, 0)
	for _, b := range blocks {
		for _, p := range a.PiecesForBlock(b) {
			if _, ok := seen[p]; ok {
				continue
			}
			if a.IsPieceVerified(p) {
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
func (a *Adapter) LeasePieces(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) LeaseBlocks(args ...interface{}) []uint64  { return a.Lease(args...) }
func (a *Adapter) Acquire(args ...interface{}) []uint64      { return a.Lease(args...) }
func (a *Adapter) AcquirePieces(args ...interface{}) []uint64 { return a.Lease(args...) }
func (a *Adapter) AcquireBlocks(args ...interface{}) []uint64  { return a.Lease(args...) }
func (a *Adapter) GetPieces(args ...interface{}) []uint64      { return a.Lease(args...) }
func (a *Adapter) Take(args ...interface{}) []uint64           { return a.Lease(args...) }
func (a *Adapter) TakePieces(args ...interface{}) []uint64     { return a.Lease(args...) }

func (a *Adapter) parseCompleteArgs(args []interface{}) (string, uint64, []byte, bool) {
	network := ""
	var piece uint64
	var data []byte
	hasPiece := false
	for _, arg := range args {
		switch v := arg.(type) {
		case string:
			if network == "" {
				network = v
			}
		case []byte:
			data = v
		case uint64:
			if !hasPiece {
				piece = v
				hasPiece = true
			}
		case uint:
			if !hasPiece {
				piece = uint64(v)
				hasPiece = true
			}
		case int:
			if !hasPiece {
				if v < 0 {
					v = 0
				}
				piece = uint64(v)
				hasPiece = true
			}
		case int64:
			if !hasPiece {
				if v < 0 {
					v = 0
				}
				piece = uint64(v)
				hasPiece = true
			}
		}
	}
	if network == "" {
		network = a.defaultNetwork()
	}
	if !hasPiece {
		return network, 0, data, false
	}
	return network, piece, data, true
}

func (a *Adapter) Complete(args ...interface{}) bool {
	network, piece, data, ok := a.parseCompleteArgs(args)
	if !ok {
		return false
	}
	// Track piece verification (new?).
	a.mu.Lock()
	_, already := a.verified[piece]
	if !already {
		a.verified[piece] = struct{}{}
	}
	a.mu.Unlock()

	blocks := a.CanonicalBlocksForPiece(piece)
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
	// Ensure scheduler marks blocks verified even when swarm present.
	if a.Scheduler != nil && a.Swarm != nil {
		for _, b := range blocks {
			a.Scheduler.Complete(b)
		}
	}
	return anyNew
}

// Alias methods for Complete.
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
	// all pieces verified?
	pc := a.PieceCount()
	allPieces := true
	a.mu.Lock()
	for i := uint64(0); i < pc; i++ {
		if _, ok := a.verified[i]; !ok {
			allPieces = false
			break
		}
	}
	a.mu.Unlock()
	if pc == 0 {
		allPieces = true
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
	return allPieces && canon
}

// Alias methods for IsComplete.
func (a *Adapter) IsDone(args ...interface{}) bool        { return a.IsComplete(args...) }
func (a *Adapter) IsFinished(args ...interface{}) bool    { return a.IsComplete(args...) }
func (a *Adapter) AllComplete(args ...interface{}) bool   { return a.IsComplete(args...) }
func (a *Adapter) AllVerified(args ...interface{}) bool    { return a.IsComplete(args...) }
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
