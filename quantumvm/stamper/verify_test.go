// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package stamper

import (
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/log"
)

// testBlock builds a block whose header fields are all distinct, so a stamp that
// copies the wrong one is visible rather than accidentally equal.
func testBlock(height uint64) *types.Block {
	return types.NewBlockWithHeader(&types.Header{
		Number:      new(big.Int).SetUint64(height),
		Root:        common.BytesToHash([]byte{byte(height), 0xa1}),
		ReceiptHash: common.BytesToHash([]byte{byte(height), 0xa2}),
		GasUsed:     21000 + height,
		Time:        1700000000 + height,
	})
}

// newStamper returns an enabled stamper in the given mode with its worker
// goroutines running, as NewQuantumStamper leaves it.
func newStamper(t *testing.T, mode QuantumStampMode) *QuantumStamper {
	t.Helper()
	qs, err := NewQuantumStamper(log.NewNoOpLogger(), mode, 16)
	require.NoError(t, err)
	qs.Enable()
	t.Cleanup(func() { qs.Close() })
	return qs
}

// TestStampRoundTripEveryMode is the property the stamper exists for: a stamp
// this node produced, this node accepts. It runs every mode initializeSigners
// admits, because a verifier that only handles one of them is a verifier that
// rejects blocks its own signer stamped.
func TestStampRoundTripEveryMode(t *testing.T) {
	for name, mode := range map[string]QuantumStampMode{
		"MLDSA44": StampModeMLDSA44,
		"MLDSA65": StampModeMLDSA65,
		"MLDSA87": StampModeMLDSA87,
		"SLHDSA":  StampModeSLHDSA,
		"Hybrid":  StampModeHybrid,
	} {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			qs := newStamper(t, mode)
			block := testBlock(7)

			stamp, err := qs.StampBlock(block)
			require.NoError(err)
			require.Equal(mode, stamp.Mode)
			require.Equal(block.Hash(), stamp.CChainHash)
			require.Equal(block.Root(), stamp.StateRoot)

			require.True(qs.VerifyStamp(stamp, block), "stamper rejected its own stamp")
		})
	}
}

// TestVerifyRejectsAnotherBlock covers the correspondence half of verification:
// the signature is genuine and over data the signer really produced, but the
// stamp describes a different block than the one being replayed.
func TestVerifyRejectsAnotherBlock(t *testing.T) {
	require := require.New(t)
	qs := newStamper(t, StampModeMLDSA65)

	stamp, err := qs.StampBlock(testBlock(7))
	require.NoError(err)

	require.False(qs.VerifyStamp(stamp, testBlock(8)))
}

// TestVerifyRejectsEditedField walks the fields stampMatchesBlock compares. Each
// edit keeps the signature intact and changes only what the stamp claims, so a
// verifier that skipped the comparison would accept all five.
func TestVerifyRejectsEditedField(t *testing.T) {
	block := testBlock(7)
	for name, edit := range map[string]func(*QuantumStamp){
		"height":       func(s *QuantumStamp) { s.CChainHeight++ },
		"blockHash":    func(s *QuantumStamp) { s.CChainHash = common.BytesToHash([]byte{0xff}) },
		"stateRoot":    func(s *QuantumStamp) { s.StateRoot = common.BytesToHash([]byte{0xfe}) },
		"receiptsRoot": func(s *QuantumStamp) { s.ReceiptsRoot = common.BytesToHash([]byte{0xfd}) },
		"gasUsed":      func(s *QuantumStamp) { s.GasUsed++ },
	} {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			qs := newStamper(t, StampModeMLDSA65)

			stamp, err := qs.StampBlock(block)
			require.NoError(err)
			require.True(qs.VerifyStamp(stamp, block), "unedited stamp must verify first")

			edit(stamp)
			require.False(qs.VerifyStamp(stamp, block))
		})
	}
}

// TestVerifyRejectsBrokenSignature covers the signature half: the stamp still
// describes the right block, so it passes stampMatchesBlock and the decision
// falls entirely to verifyMLDSA and verifySLHDSA.
func TestVerifyRejectsBrokenSignature(t *testing.T) {
	for name, tc := range map[string]struct {
		mode   QuantumStampMode
		break_ func(*QuantumStamp)
	}{
		"mldsaFlipped":  {StampModeMLDSA65, func(s *QuantumStamp) { s.MLDSASignature[0] ^= 0x01 }},
		"mldsaEmpty":    {StampModeMLDSA65, func(s *QuantumStamp) { s.MLDSASignature = nil }},
		"mldsaNoKey":    {StampModeMLDSA65, func(s *QuantumStamp) { s.PublicKeyML = nil }},
		"mldsaShortKey": {StampModeMLDSA65, func(s *QuantumStamp) { s.PublicKeyML = s.PublicKeyML[:8] }},
		"slhdsaFlipped": {StampModeSLHDSA, func(s *QuantumStamp) { s.SLHDSASignature[0] ^= 0x01 }},
		"slhdsaEmpty":   {StampModeSLHDSA, func(s *QuantumStamp) { s.SLHDSASignature = nil }},
		"slhdsaNoKey":   {StampModeSLHDSA, func(s *QuantumStamp) { s.PublicKeySLH = nil }},
		// Hybrid must fail if EITHER leg fails, so break only the hash-based one.
		"hybridSLHOnly": {StampModeHybrid, func(s *QuantumStamp) { s.SLHDSASignature[0] ^= 0x01 }},
		"hybridMLOnly":  {StampModeHybrid, func(s *QuantumStamp) { s.MLDSASignature[0] ^= 0x01 }},
	} {
		t.Run(name, func(t *testing.T) {
			require := require.New(t)
			qs := newStamper(t, tc.mode)
			block := testBlock(7)

			stamp, err := qs.StampBlock(block)
			require.NoError(err)
			require.True(qs.VerifyStamp(stamp, block), "unbroken stamp must verify first")

			tc.break_(stamp)
			require.False(qs.VerifyStamp(stamp, block))
		})
	}
}

// TestVerifyRejectsUnknownMode covers the default arm of verifyStampSync. An
// unrecognised mode names no signature to check, so the only safe answer is no.
func TestVerifyRejectsUnknownMode(t *testing.T) {
	require := require.New(t)
	qs := newStamper(t, StampModeMLDSA65)
	block := testBlock(7)

	stamp, err := qs.StampBlock(block)
	require.NoError(err)

	stamp.Mode = QuantumStampMode(200)
	require.False(qs.VerifyStamp(stamp, block))
}

// TestDisabledStamperStampsAndVerifiesNothing pins the enable flag on both
// sides. A verifier that ignored it would accept stamps on a node that has
// deliberately turned quantum stamping off.
func TestDisabledStamperStampsAndVerifiesNothing(t *testing.T) {
	require := require.New(t)
	qs := newStamper(t, StampModeMLDSA65)
	block := testBlock(7)

	stamp, err := qs.StampBlock(block)
	require.NoError(err)

	qs.Disable()
	_, err = qs.StampBlock(testBlock(9))
	require.ErrorIs(err, ErrStampingDisabled)
	require.False(qs.VerifyStamp(stamp, block))
}

// TestSignatureDataCommitsToEachSignedField is the injectivity check behind
// every rejection above: two stamps differing in one signed field must produce
// different signing bytes, or a signature over one authenticates the other.
func TestSignatureDataCommitsToEachSignedField(t *testing.T) {
	qs := &QuantumStamper{}
	base := func() *QuantumStamp {
		return &QuantumStamp{
			CChainHeight: 7,
			CChainHash:   common.BytesToHash([]byte{0x01}),
			QChainHeight: 8,
			QChainHash:   common.BytesToHash([]byte{0x02}),
			StateRoot:    common.BytesToHash([]byte{0x03}),
			ReceiptsRoot: common.BytesToHash([]byte{0x04}),
			GasUsed:      21000,
			Nonce:        []byte{0x05},
		}
	}
	reference := qs.prepareSignatureData(base())

	for name, edit := range map[string]func(*QuantumStamp){
		"cchainHeight": func(s *QuantumStamp) { s.CChainHeight++ },
		"cchainHash":   func(s *QuantumStamp) { s.CChainHash = common.BytesToHash([]byte{0xf1}) },
		"qchainHeight": func(s *QuantumStamp) { s.QChainHeight++ },
		"qchainHash":   func(s *QuantumStamp) { s.QChainHash = common.BytesToHash([]byte{0xf2}) },
		"stateRoot":    func(s *QuantumStamp) { s.StateRoot = common.BytesToHash([]byte{0xf3}) },
		"receiptsRoot": func(s *QuantumStamp) { s.ReceiptsRoot = common.BytesToHash([]byte{0xf4}) },
		"gasUsed":      func(s *QuantumStamp) { s.GasUsed++ },
		"nonce":        func(s *QuantumStamp) { s.Nonce = []byte{0xf5} },
	} {
		t.Run(name, func(t *testing.T) {
			edited := base()
			edit(edited)
			require.NotEqual(t, reference, qs.prepareSignatureData(edited))
		})
	}
}

// TestQChainHashCommitsToBlockIdentity covers generateQChainHash. The hash is
// what prepareSignatureData carries as QChainHash, so two different C-Chain
// blocks sharing one Q-Chain hash would share signable bytes.
func TestQChainHashCommitsToBlockIdentity(t *testing.T) {
	qs := &QuantumStamper{}
	base := &QuantumStamp{
		CChainHeight: 7,
		CChainHash:   common.BytesToHash([]byte{0x01}),
		QChainHeight: 8,
		StateRoot:    common.BytesToHash([]byte{0x03}),
		ReceiptsRoot: common.BytesToHash([]byte{0x04}),
		Nonce:        []byte{0x05},
	}
	reference := qs.generateQChainHash(base)
	require.NotEqual(t, common.Hash{}, reference)

	other := *base
	other.CChainHash = common.BytesToHash([]byte{0xff})
	require.NotEqual(t, reference, qs.generateQChainHash(&other))
}

// TestStampBlockCachesByBlockHash covers the cache arm of StampBlock: a second
// request for the same block must return the stamp already made, not a second
// signature over a fresh timestamp and nonce.
func TestStampBlockCachesByBlockHash(t *testing.T) {
	require := require.New(t)
	qs := newStamper(t, StampModeMLDSA65)
	block := testBlock(7)

	first, err := qs.StampBlock(block)
	require.NoError(err)
	second, err := qs.StampBlock(block)
	require.NoError(err)
	require.Same(first, second)

	cached, ok := qs.GetStampForBlock(block.Hash())
	require.True(ok)
	require.Same(first, cached)
}

// TestVerifyStampBatchDecidesEachEntrySeparately covers the batch entry point.
// One good and one edited stamp in a single call must come back true and false,
// not one verdict applied to both.
func TestVerifyStampBatchDecidesEachEntrySeparately(t *testing.T) {
	require := require.New(t)
	qs := newStamper(t, StampModeMLDSA65)

	good := testBlock(7)
	bad := testBlock(8)
	goodStamp, err := qs.StampBlock(good)
	require.NoError(err)
	badStamp, err := qs.StampBlock(bad)
	require.NoError(err)
	badStamp.GasUsed++

	require.Equal([]bool{true, false}, qs.VerifyStampBatch(
		[]*QuantumStamp{goodStamp, badStamp},
		[]*types.Block{good, bad},
	))

	require.Nil(qs.VerifyStampBatch(nil, nil))
	require.Nil(qs.VerifyStampBatch([]*QuantumStamp{goodStamp}, nil))
}

// planned collects the plan's three lists into one index-to-decider map, and
// fails if any index is claimed twice or left unclaimed.
func planned(t *testing.T, plan batchPlan, n int) map[int]string {
	t.Helper()
	owner := map[int]string{}
	for name, list := range map[string][]int{
		"batched":    plan.batched,
		"sequential": plan.sequential,
		"refused":    plan.refused,
	} {
		for _, i := range list {
			require.NotContains(t, owner, i, "index %d claimed by two deciders", i)
			owner[i] = name
		}
	}
	require.Len(t, owner, n, "every entry needs exactly one decider")
	return owner
}

// TestPlanBatchGivesEveryEntryOneDecider is the invariant the accelerated path
// rests on. An entry the accelerator cannot lay out has to be sent somewhere,
// because the results slice starts out all-false: an unassigned entry is a
// silent rejection, and the caller cannot tell it apart from a real one.
func TestPlanBatchGivesEveryEntryOneDecider(t *testing.T) {
	mldsaStamper := newStamper(t, StampModeMLDSA65)
	slhStamper := newStamper(t, StampModeSLHDSA)
	wideStamper := newStamper(t, StampModeMLDSA87)

	block := func(h uint64) *types.Block { return testBlock(h) }
	stampOf := func(qs *QuantumStamper, b *types.Block) *QuantumStamp {
		s, err := qs.StampBlock(b)
		require.NoError(t, err)
		return s
	}

	b0, b1, b2, b3, b4 := block(1), block(2), block(3), block(4), block(5)
	mismatched := stampOf(mldsaStamper, b3)
	mismatched.GasUsed++
	unsigned := stampOf(mldsaStamper, b4)
	unsigned.MLDSASignature = nil

	stamps := []*QuantumStamp{
		stampOf(mldsaStamper, b0), // batched: the first ML-DSA set seen
		stampOf(slhStamper, b1),   // sequential: carries no ML-DSA leg at all
		stampOf(wideStamper, b2),  // sequential: a different parameter set
		mismatched,                // refused: describes another block
		unsigned,                  // refused: nothing to check
	}
	blocks := []*types.Block{b0, b1, b2, b3, b4}

	owner := planned(t, planBatch(stamps, blocks), len(stamps))
	require.Equal(t, "batched", owner[0])
	require.Equal(t, "sequential", owner[1])
	require.Equal(t, "sequential", owner[2])
	require.Equal(t, "refused", owner[3])
	require.Equal(t, "refused", owner[4])
	require.Equal(t, mldsa.MLDSA65, planBatch(stamps, blocks).mode)
}

// TestPlanBatchBatchesOneParameterSet pins the stride rule. The accelerator
// writes each key at a fixed offset, so admitting a 2592-byte ML-DSA-87 key to
// a batch laid out for 1952-byte ML-DSA-65 keys overwrites the next entry's key
// with the tail of this one.
func TestPlanBatchBatchesOneParameterSet(t *testing.T) {
	require := require.New(t)

	var stamps []*QuantumStamp
	var blocks []*types.Block
	for i, mode := range []QuantumStampMode{
		StampModeMLDSA44, StampModeMLDSA44, StampModeMLDSA65, StampModeMLDSA87,
	} {
		qs := newStamper(t, mode)
		b := testBlock(uint64(i + 1))
		s, err := qs.StampBlock(b)
		require.NoError(err)
		stamps = append(stamps, s)
		blocks = append(blocks, b)
	}

	plan := planBatch(stamps, blocks)
	planned(t, plan, len(stamps))
	require.Equal(mldsa.MLDSA44, plan.mode)
	require.Equal([]int{0, 1}, plan.batched)
	require.Equal([]int{2, 3}, plan.sequential)

	for _, i := range plan.batched {
		key, ok := stamps[i].Mode.mldsaMode()
		require.True(ok)
		require.Equal(plan.mode, key, "a batched entry must match the batch stride")
		require.Len(stamps[i].PublicKeyML, mldsa.GetPublicKeySize(plan.mode))
	}
}

// TestPlanBatchRefusesOnlyWhatSequentialRefuses is the agreement property: an
// entry the plan decides false without looking at a signature must be one the
// sequential verifier would also reject. The accelerated path may be faster; it
// may not be stricter.
func TestPlanBatchRefusesOnlyWhatSequentialRefuses(t *testing.T) {
	require := require.New(t)
	qs := newStamper(t, StampModeMLDSA65)

	var stamps []*QuantumStamp
	var blocks []*types.Block
	add := func(b *types.Block, edit func(*QuantumStamp)) {
		s, err := qs.StampBlock(b)
		require.NoError(err)
		if edit != nil {
			edit(s)
		}
		stamps = append(stamps, s)
		blocks = append(blocks, b)
	}
	add(testBlock(1), nil)
	add(testBlock(2), func(s *QuantumStamp) { s.StateRoot = common.BytesToHash([]byte{0xee}) })
	add(testBlock(3), func(s *QuantumStamp) { s.PublicKeyML = nil })
	add(testBlock(4), func(s *QuantumStamp) { s.CChainHeight = 999 })

	plan := planBatch(stamps, blocks)
	planned(t, plan, len(stamps))
	require.NotEmpty(plan.refused)
	for _, i := range plan.refused {
		require.False(qs.verifyStampSync(stamps[i], blocks[i]),
			"plan refused entry %d that the sequential verifier accepts", i)
	}
	for _, i := range plan.batched {
		require.True(qs.verifyStampSync(stamps[i], blocks[i]),
			"plan batched entry %d that the sequential verifier rejects", i)
	}
}
