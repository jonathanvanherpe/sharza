// SPDX-License-Identifier: GPL-3.0-or-later

// Package ed2k implements the eDonkey2000 (and Kad) wire protocol.
//
// This slice adds ed2k part verification against a PartMet record. Given a
// PartMet (per-part MD4s, file size, file hash, optional AICH root) and the
// downloaded bytes, VerifyPartMet checks the byte count, each complete
// eDonkey part's MD4, the whole-file MD4 and (optionally) the AICH root.
// No networking, file I/O, AICH wiring into the download path, queue handling,
// obfuscation, server-side accept or daemon/RPC/store/config changes are
// performed here. This is a pure hashing helper.
package ed2k

import (
	"golang.org/x/crypto/md4"
)

// PartVerifyResult is the outcome of verifying downloaded bytes against a
// PartMet record. All alias fields carry the same value, mirroring the
// alias-tolerant style of PartMet and the other helpers in this package.
type PartVerifyResult struct {
	// Overall outcome.
	Verified         bool
	OK               bool
	Success          bool
	Valid            bool
	Complete         bool
	Passed           bool
	Match            bool
	Matches          bool
	IsVerified       bool
	VerifiedOK       bool
	AllVerified      bool
	AllPartsVerified bool
	PartsVerifiedAll bool
	WholeVerified    bool
	FileVerified     bool
	Result           bool
	Value            bool

	// Size checks.
	SizeMatch        bool
	SizeOK           bool
	SizeValid        bool
	SizeMatches      bool
	FileSizeMatch    bool
	LengthMatch      bool
	TotalSizeMatch   bool
	DataSizeMatch    bool
	LengthOK         bool
	SizeCorrect      bool

	// File (whole-file) MD4 checks.
	FileHashMatch     bool
	HashMatch         bool
	MD4Match          bool
	RootHashMatch     bool
	FileHashOK        bool
	HashOK            bool
	MD4OK             bool
	FileHashValid     bool
	HashValid         bool
	WholeFileHashMatch bool
	FullFileHashMatch bool
	WholeHashMatch    bool

	// Per-part verification.
	PartsVerified   []bool
	PartVerified    []bool
	VerifiedParts   []bool
	PartsOK         []bool
	PartsValid      []bool
	PartsMatch      []bool
	Parts           []bool
	PartResults     []bool
	PartMatches     []bool
	VerifiedPartsFlags []bool

	// Counts.
	PartCount         int
	NumParts          int
	TotalParts        int
	PartsN            int
	NParts            int
	ExpectedParts     int
	NumExpectedParts  int
	VerifiedPartCount int
	NumVerified       int
	VerifiedPartsCount int
	MatchedParts      int
	PartsMatched      int
	NumMatched        int
	VerifiedCount     int

	// Indices of verified parts.
	VerifiedPartIndices   []uint64
	VerifiedPartsList     []uint64
	VerifiedPartNumbers   []uint64
	VerifiedPartsIndices  []uint64
	MatchedPartIndices    []uint64
	MatchedPartsList      []uint64

	// Indices of parts that did not verify.
	CorruptParts          []uint64
	BadParts              []uint64
	FailedParts           []uint64
	MismatchedParts       []uint64
	UnverifiedParts       []uint64
	CorruptPartIndices    []uint64
	BadPartIndices        []uint64
	FailedPartIndices     []uint64
	MismatchedPartIndices []uint64
	UnverifiedPartIndices []uint64

	// AICH.
	AICHVerified    bool
	AICHMatch       bool
	AICHOK          bool
	AICHValid       bool
	AICHRootMatch   bool
	HasAICH         bool
	AICHChecked     bool
	AICHSupplied    bool
	TrustedRootSupplied bool
	HasTrustedRoot  bool
	AICHBlockCount  int

	// Resolved sizes.
	FileSize   uint64
	PartSize   uint64
	DataSize   int
	DataLen    int
	NumBytes   int

	// Hashes.
	ComputedFileHash  [16]byte
	ActualFileHash    [16]byte
	CalculatedFileHash [16]byte
	ComputedHash      [16]byte
	FileHashComputed  [16]byte
	ComputedMD4       [16]byte
	WholeFileHash     [16]byte
	ComputedWholeFileHash [16]byte
	MD4               [16]byte

	ExpectedFileHash  [16]byte
	PartMetFileHash   [16]byte
	RootHash          [16]byte
	ExpectedHash      [16]byte
	FileHash          [16]byte

	ComputedAICHRoot   [16]byte
	ActualAICHRoot     [16]byte
	CalculatedAICHRoot [16]byte
	AICHRootComputed   [16]byte
	TrustedAICHRoot    [16]byte
	ExpectedAICHRoot   [16]byte
	SuppliedAICHRoot   [16]byte
	AICHRoot           [16]byte

	AICHBlockSize uint64
}

// Type aliases for the result, mirroring the alias-heavy style of this package.
type (
	PartVerifyOutcome         = PartVerifyResult
	PartVerificationResult    = PartVerifyResult
	PartMetVerifyResult       = PartVerifyResult
	PartVerifyStatus          = PartVerifyResult
	PartVerifyReport          = PartVerifyResult
	PartCheckResult           = PartVerifyResult
	PartMetVerifyOutcome      = PartVerifyResult
	PartVerificationOutcome   = PartVerifyResult
	PartVerifyAnswer          = PartVerifyResult
	PartVerifyResponse        = PartVerifyResult
)

// VerifyPartMet checks downloaded bytes against a PartMet record.
//
// It resolves PartMet alias fields, checks len(data) against PartMet.FileSize,
// computes the MD4 of each complete eDonkey part and compares it to
// PartMet.PartHashes[i], records which parts verified, reports overall
// verified only when all parts are present and matching and the whole-file
// MD4 matches PartMet.FileHash, and optionally checks the AICH root when a
// trusted root is supplied via the trailing variadic arguments.
func VerifyPartMet(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	if data == nil {
		data = []byte{}
	}

	size, fileHash, partSize, partHashes, _ := pm.normalized()

	// Parse optional trailing arguments: trusted AICH root and/or block size.
	trustedRoot := [16]byte{}
	hasRoot := false
	blockSize := uint64(AICHBlockSize)
	for _, a := range args {
		switch v := a.(type) {
		case [16]byte:
			trustedRoot = v
			hasRoot = true
		case *[16]byte:
			if v != nil {
				trustedRoot = *v
				hasRoot = true
			}
		case []byte:
			if len(v) == 16 {
				copy(trustedRoot[:], v)
				hasRoot = true
			}
		case uint64:
			if v != 0 {
				blockSize = v
			}
		case uint:
			if v != 0 {
				blockSize = uint64(v)
			}
		case int:
			if v > 0 {
				blockSize = uint64(v)
			}
		case int64:
			if v > 0 {
				blockSize = uint64(v)
			}
		case uint32:
			if v != 0 {
				blockSize = uint64(v)
			}
		case int32:
			if v > 0 {
				blockSize = uint64(v)
			}
		}
	}
	if blockSize == 0 {
		blockSize = AICHBlockSize
	}

	sizeMatch := uint64(len(data)) == size

	// Expected part count from file size + part size.
	expectedParts := uint64(0)
	if size > 0 && partSize > 0 {
		expectedParts = (size + partSize - 1) / partSize
	}

	n := expectedParts
	if uint64(len(partHashes)) > n {
		n = uint64(len(partHashes))
	}

	partsVerified := make([]bool, n)
	verifiedIndices := make([]uint64, 0)
	corruptIndices := make([]uint64, 0)
	verifiedCount := 0
	for i := uint64(0); i < n; i++ {
		ok := false
		if i < expectedParts && int(i) < len(partHashes) {
			start, end, rangeOK := partByteRange(i, partSize, size)
			if rangeOK && uint64(end) <= uint64(len(data)) {
				computed := md4Sum(data[start:end])
				if computed == partHashes[i] {
					ok = true
				}
			}
		}
		partsVerified[i] = ok
		if ok {
			verifiedCount++
			verifiedIndices = append(verifiedIndices, i)
		} else {
			corruptIndices = append(corruptIndices, i)
		}
	}

	computedFileHash := md4Sum(data)
	fileHashMatch := computedFileHash == fileHash

	allPartsOK := (int(expectedParts) == len(partHashes)) && (verifiedCount == int(expectedParts))

	computedAICH := [16]byte{}
	aichMatch := true
	if hasRoot {
		computedAICH = AICHRoot(data, blockSize)
		aichMatch = computedAICH == trustedRoot
	}

	overall := sizeMatch && allPartsOK && fileHashMatch && (!hasRoot || aichMatch)

	// Build int slices too (as uint64 already).

	res := PartVerifyResult{
		// overall
		Verified:         overall,
		OK:               overall,
		Success:          overall,
		Valid:            overall,
		Complete:         overall,
		Passed:           overall,
		Match:            overall,
		Matches:          overall,
		IsVerified:       overall,
		VerifiedOK:       overall,
		AllVerified:      overall,
		AllPartsVerified: allPartsOK,
		PartsVerifiedAll: allPartsOK,
		WholeVerified:    fileHashMatch,
		FileVerified:     fileHashMatch,
		Result:           overall,
		Value:            overall,

		// size
		SizeMatch:     sizeMatch,
		SizeOK:        sizeMatch,
		SizeValid:     sizeMatch,
		SizeMatches:   sizeMatch,
		FileSizeMatch: sizeMatch,
		LengthMatch:   sizeMatch,
		TotalSizeMatch: sizeMatch,
		DataSizeMatch: sizeMatch,
		LengthOK:      sizeMatch,
		SizeCorrect:   sizeMatch,

		// file hash
		FileHashMatch:      fileHashMatch,
		HashMatch:         fileHashMatch,
		MD4Match:          fileHashMatch,
		RootHashMatch:     fileHashMatch,
		FileHashOK:        fileHashMatch,
		HashOK:            fileHashMatch,
		MD4OK:             fileHashMatch,
		FileHashValid:     fileHashMatch,
		HashValid:         fileHashMatch,
		WholeFileHashMatch: fileHashMatch,
		FullFileHashMatch: fileHashMatch,
		WholeHashMatch:    fileHashMatch,

		// per-part
		PartsVerified:        partsVerified,
		PartVerified:         append([]bool(nil), partsVerified...),
		VerifiedParts:        append([]bool(nil), partsVerified...),
		VerifiedPartsFlags:   append([]bool(nil), partsVerified...),
		PartsOK:              append([]bool(nil), partsVerified...),
		PartsValid:           append([]bool(nil), partsVerified...),
		PartsMatch:           append([]bool(nil), partsVerified...),
		Parts:                append([]bool(nil), partsVerified...),
		PartResults:          append([]bool(nil), partsVerified...),
		PartMatches:          append([]bool(nil), partsVerified...),

		// counts
		PartCount:          int(n),
		NumParts:           int(n),
		TotalParts:         int(n),
		PartsN:             int(n),
		NParts:             int(n),
		ExpectedParts:      int(expectedParts),
		NumExpectedParts:   int(expectedParts),
		VerifiedPartCount:  verifiedCount,
		NumVerified:        verifiedCount,
		VerifiedPartsCount: verifiedCount,
		MatchedParts:       verifiedCount,
		PartsMatched:       verifiedCount,
		NumMatched:         verifiedCount,
		VerifiedCount:      verifiedCount,

		// verified indices
		VerifiedPartIndices:  verifiedIndices,
		VerifiedPartsList:    append([]uint64(nil), verifiedIndices...),
		VerifiedPartNumbers:  append([]uint64(nil), verifiedIndices...),
		VerifiedPartsIndices: append([]uint64(nil), verifiedIndices...),
		MatchedPartIndices:   append([]uint64(nil), verifiedIndices...),
		MatchedPartsList:     append([]uint64(nil), verifiedIndices...),

		// corrupt indices
		CorruptParts:          corruptIndices,
		BadParts:              append([]uint64(nil), corruptIndices...),
		FailedParts:           append([]uint64(nil), corruptIndices...),
		MismatchedParts:       append([]uint64(nil), corruptIndices...),
		UnverifiedParts:       append([]uint64(nil), corruptIndices...),
		CorruptPartIndices:    append([]uint64(nil), corruptIndices...),
		BadPartIndices:        append([]uint64(nil), corruptIndices...),
		FailedPartIndices:     append([]uint64(nil), corruptIndices...),
		MismatchedPartIndices: append([]uint64(nil), corruptIndices...),
		UnverifiedPartIndices: append([]uint64(nil), corruptIndices...),

		// aich
		AICHVerified:        hasRoot && aichMatch,
		AICHMatch:           aichMatch,
		AICHOK:              aichMatch,
		AICHValid:           aichMatch,
		AICHRootMatch:       aichMatch,
		HasAICH:             hasRoot,
		AICHChecked:         hasRoot,
		AICHSupplied:        hasRoot,
		TrustedRootSupplied: hasRoot,
		HasTrustedRoot:      hasRoot,
		AICHBlockCount:      AICHLeafCount(len(data), blockSize),

		// sizes
		FileSize: size,
		PartSize: partSize,
		DataSize: len(data),
		DataLen:  len(data),
		NumBytes: len(data),

		// hashes
		ComputedFileHash:       computedFileHash,
		ActualFileHash:        computedFileHash,
		CalculatedFileHash:    computedFileHash,
		ComputedHash:          computedFileHash,
		FileHashComputed:      computedFileHash,
		ComputedMD4:           computedFileHash,
		WholeFileHash:         computedFileHash,
		ComputedWholeFileHash: computedFileHash,
		MD4:                  computedFileHash,

		ExpectedFileHash: fileHash,
		PartMetFileHash:  fileHash,
		RootHash:         fileHash,
		ExpectedHash:     fileHash,
		FileHash:         fileHash,

		ComputedAICHRoot:   computedAICH,
		ActualAICHRoot:     computedAICH,
		CalculatedAICHRoot: computedAICH,
		AICHRootComputed:   computedAICH,
		TrustedAICHRoot:    trustedRoot,
		ExpectedAICHRoot:   trustedRoot,
		SuppliedAICHRoot:   trustedRoot,
		AICHRoot:           trustedRoot,

		AICHBlockSize: blockSize,
	}

	// Ensure non-nil slices for empty case.
	if res.PartsVerified == nil {
		res.PartsVerified = []bool{}
	}
	if res.VerifiedParts == nil {
		res.VerifiedParts = []bool{}
	}
	if res.VerifiedPartsFlags == nil {
		res.VerifiedPartsFlags = []bool{}
	}
	if res.VerifiedPartIndices == nil {
		res.VerifiedPartIndices = []uint64{}
	}
	if res.CorruptParts == nil {
		res.CorruptParts = []uint64{}
	}

	// Keep alias slices in sync (already copies). Done.

	return res, nil
}

// verifyPartMet is an unexported alias, mirroring aich.go.
func verifyPartMet(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

// --- Method forms ---

func (pm PartMet) Verify(data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func (pm PartMet) VerifyPartMet(data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func (pm PartMet) VerifyPart(data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func (pm PartMet) Check(data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func (pm PartMet) Validate(data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

// --- Package-level aliases / alternate spellings ---

func VerifyPart(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func VerifyParts(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func VerifyPartHashes(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func VerifyPartMetRecord(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func VerifyPartMetData(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func VerifyPartData(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func VerifyPartsData(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func VerifyMetPart(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func CheckPartMet(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func ValidatePartMet(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func ValidatePart(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func PartVerify(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func PartMetVerify(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func PartVerifyMet(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func PartVerifyPartMet(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func Verify(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

// lowercase aliases
func verifyPart(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func verifyParts(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func verifyPartHashes(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func partVerify(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

func partMetVerify(pm PartMet, data []byte, args ...any) (PartVerifyResult, error) {
	return VerifyPartMet(pm, data, args...)
}

// AICH-specific convenience wrappers.
func VerifyPartMetAICH(pm PartMet, data []byte, root [16]byte, blockSize ...uint64) (PartVerifyResult, error) {
	bs := uint64(0)
	if len(blockSize) > 0 {
		bs = blockSize[0]
	}
	if bs == 0 {
		return VerifyPartMet(pm, data, root)
	}
	return VerifyPartMet(pm, data, root, bs)
}

func VerifyPartAICH(pm PartMet, data []byte, root [16]byte, blockSize ...uint64) (PartVerifyResult, error) {
	return VerifyPartMetAICH(pm, data, root, blockSize...)
}

func VerifyWithAICH(pm PartMet, data []byte, root [16]byte, blockSize ...uint64) (PartVerifyResult, error) {
	return VerifyPartMetAICH(pm, data, root, blockSize...)
}

// Ensure md4 import usage.
var _ = md4.New