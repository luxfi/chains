// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"sync"
	"testing"

	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// engine returns a real Quasar with one block awaiting signatures.
func engine(t *testing.T, threshold int) (*Quasar, ids.ID) {
	t.Helper()
	q, err := NewQuasar(QuasarConfig{
		ValidatorID: "validator-self",
		Threshold:   threshold,
		TotalNodes:  3,
		Logger:      log.NewNoOpLogger(),
	})
	require.NoError(t, err)

	blockID := ids.GenerateTestID()
	q.pendingBlocks[blockID] = &PendingBlock{
		BlockID:          blockID,
		BlockHash:        blockID[:],
		Height:           1,
		BLSSignatures:    make([]*quasar.BLSSignature, 0),
		CoronaSignatures: make([]*quasar.CoronaSignature, 0),
	}
	return q, blockID
}

// TestThresholdIsDerivedFromTheCommitteeItGuards.
//
// The default threshold was computed from TotalNodes before TotalNodes had been
// defaulted, so a config that named neither got a threshold of one — and then a
// committee of three. One validator would have finalized a block alone, on a
// network built to need three.
func TestThresholdIsDerivedFromTheCommitteeItGuards(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{Logger: log.NewNoOpLogger()})
	require.NoError(t, err)
	require.Equal(t, 3, q.totalNodes)
	require.Equal(t, 3, q.GetThreshold(),
		"a validator could finalize alone on the three-node network this same config assumes")

	// An explicit threshold is honoured, and an explicit committee is what the
	// default is taken from.
	q, err = NewQuasar(QuasarConfig{Threshold: 2, TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)
	require.Equal(t, 2, q.GetThreshold())

	q, err = NewQuasar(QuasarConfig{TotalNodes: 10, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)
	require.Equal(t, 7, q.GetThreshold(), "⌊2n/3⌋+1 of ten")

	// A nil logger is not a reason to crash on the first Debug call.
	q, err = NewQuasar(QuasarConfig{TotalNodes: 3})
	require.NoError(t, err)
	require.NotPanics(t, func() { _ = q.AddValidator("v1", 1) })
}

// TestOneValidatorCannotReachCoronaThreshold proves the post-quantum finality
// leg counts distinct validators.
//
// TryFinalize finalizes the Corona leg on count alone and verifies none of
// those signatures — unlike the BLS leg, which aggregates and verifies. A
// validator resending its signature would drive the count to the threshold on
// its own and satisfy the post-quantum half of quantum finality alone.
func TestOneValidatorCannotReachCoronaThreshold(t *testing.T) {
	q, blockID := engine(t, 3)

	sig := &quasar.CoronaSignature{Signature: []byte{1}, ValidatorID: "validator-1", Round: 1}
	require.NoError(t, q.AddCoronaSignature(blockID, sig))
	require.ErrorIs(t, q.AddCoronaSignature(blockID, sig), errDuplicateSigner)
	require.ErrorIs(t, q.AddCoronaSignature(blockID, sig), errDuplicateSigner)

	// Different bytes under the same name is still one vote.
	require.ErrorIs(t, q.AddCoronaSignature(blockID, &quasar.CoronaSignature{
		Signature: []byte{9}, ValidatorID: "validator-1", Round: 2,
	}), errDuplicateSigner)

	pending := q.pendingBlocks[blockID]
	require.Len(t, pending.CoronaSignatures, 1)
	require.Less(t, len(pending.CoronaSignatures), q.threshold)

	_, finalized, err := q.TryFinalize(context.Background(), blockID)
	require.NoError(t, err)
	require.False(t, finalized)
	require.False(t, pending.CoronaFinalized, "the Corona leg was finalized by one validator")
}

// TestOneValidatorCannotReachBLSThreshold is the same rule on the classical leg.
func TestOneValidatorCannotReachBLSThreshold(t *testing.T) {
	q, blockID := engine(t, 3)

	sig := &quasar.BLSSignature{Signature: []byte{1}, ValidatorID: "validator-1"}
	require.NoError(t, q.AddBLSSignature(blockID, sig))
	require.ErrorIs(t, q.AddBLSSignature(blockID, sig), errDuplicateSigner)

	require.Len(t, q.pendingBlocks[blockID].BLSSignatures, 1)
	require.False(t, q.IsFinalized(blockID))
}

// TestDistinctValidatorsReachTheCoronaThreshold is the other half: three
// different validators do reach a threshold of three, and the leg finalizes.
func TestDistinctValidatorsReachTheCoronaThreshold(t *testing.T) {
	q, blockID := engine(t, 3)

	for _, id := range []string{"validator-1", "validator-2", "validator-3"} {
		require.NoError(t, q.AddCoronaSignature(blockID, &quasar.CoronaSignature{
			Signature: []byte{1}, ValidatorID: id, Round: 1,
		}))
	}
	require.Len(t, q.pendingBlocks[blockID].CoronaSignatures, 3)

	_, finalized, err := q.TryFinalize(context.Background(), blockID)
	require.NoError(t, err)
	require.True(t, q.pendingBlocks[blockID].CoronaFinalized,
		"three distinct validators did not carry the Corona leg")
	// Quantum finality needs BOTH legs, and the BLS aggregate over these
	// placeholder signatures does not verify, so the block is not final.
	require.False(t, finalized, "one leg alone must not be quantum finality")
	require.False(t, q.IsFinalized(blockID))
}

// TestSignaturesForAnUnknownBlockAreRefused: an id nobody proposed is not a
// place to accumulate signatures a peer chose the id of.
func TestSignaturesForAnUnknownBlockAreRefused(t *testing.T) {
	q, _ := engine(t, 3)
	stranger := ids.GenerateTestID()

	require.Error(t, q.AddBLSSignature(stranger, &quasar.BLSSignature{ValidatorID: "v1"}))
	require.Error(t, q.AddCoronaSignature(stranger, &quasar.CoronaSignature{ValidatorID: "v1"}))
	_, _, err := q.TryFinalize(context.Background(), stranger)
	require.Error(t, err)
}

// TestCleanupReleasesWhatWillNeverFinalize.
//
// minHeight is the caller's finalized frontier, so nothing below it can gather
// another signature. Releasing only the FINALIZED entries kept exactly the ones
// that accumulate — every proposal that lost, timed out or failed to sign — and
// the two maps grew for the life of the process.
func TestCleanupReleasesWhatWillNeverFinalize(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	for h := uint64(1); h <= 100; h++ {
		id := ids.GenerateTestID()
		q.pendingBlocks[id] = &PendingBlock{BlockID: id, Height: h, Finalized: h%10 == 0}
		if h%10 == 0 {
			q.finalizedBlocks[id] = true
		}
	}
	require.Len(t, q.pendingBlocks, 100)

	q.Cleanup(90)

	require.Len(t, q.pendingBlocks, 11,
		"blocks below the finalized frontier were kept because they never finalized — which is why they pile up")
	for _, pending := range q.pendingBlocks {
		require.GreaterOrEqual(t, pending.Height, uint64(90))
	}
}

// TestSignBlockLeavesNothingBehindWhenItFails: the tracking entry is created
// before signing, so a signing failure must take it away again.
func TestSignBlockLeavesNothingBehindWhenItFails(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	// A cancelled context is the cheapest way to make the signing lanes fail.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	blockID := ids.GenerateTestID()
	if _, err := q.SignBlock(ctx, blockID, blockID[:], 1); err != nil {
		require.NotContains(t, q.pendingBlocks, blockID,
			"a block that failed to sign is tracked forever: it can never finalize, so Cleanup never sees it")
	}
}

// TestSignBlockDoesNotRaceIncomingSignatures. Signing appends to the same slice
// AddBLSSignature appends to, and the log line afterwards read its length.
// Under -race that read is a data race against every arriving peer signature.
func TestSignBlockDoesNotRaceIncomingSignatures(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	blockID := ids.GenerateTestID()
	hash := make([]byte, 64)

	var wg sync.WaitGroup
	wg.Add(1)
	go func() { defer wg.Done(); _, _ = q.SignBlock(context.Background(), blockID, hash, 1) }()

	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			_ = q.AddBLSSignature(blockID, &quasar.BLSSignature{
				Signature: []byte{byte(i)}, ValidatorID: string(rune('a' + i)),
			})
			_ = q.IsFinalized(blockID)
			q.Cleanup(0)
		}(i)
	}
	wg.Wait()
}

// TestSignBlockAcceptsAnyMessageLength. The Corona lane derives its PRF key
// from the message; taking a 32-byte prefix instead crashed the process on
// anything shorter, and StampBlock hands it whatever the bridge supplies.
func TestSignBlockAcceptsAnyMessageLength(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	for _, n := range []int{0, 1, 31, 32, 64} {
		blockID := ids.GenerateTestID()
		require.NotPanics(t, func() {
			_, _ = q.SignBlock(context.Background(), blockID, make([]byte, n), 1)
		}, "a %d-byte message crashed the signer", n)
	}
}

// TestValidatorsJoinTheCommittee: the active count is what the threshold is
// measured against, so joining has to move it.
func TestValidatorsJoinTheCommittee(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	before := q.GetActiveValidators()
	require.NoError(t, q.AddValidator("validator-1", 100))
	require.Equal(t, before+1, q.GetActiveValidators())

	require.NotNil(t, q.GetQuasar())
}

// TestTheCoreRefusesAThresholdOfOne. Quantum finality is a quorum's statement;
// a "threshold" one validator meets alone is a single point of compromise, and
// the consensus core will not build one.
func TestTheCoreRefusesAThresholdOfOne(t *testing.T) {
	_, err := NewQuasar(QuasarConfig{
		ValidatorID: "self", Threshold: 1, TotalNodes: 1, Logger: log.NewNoOpLogger(),
	})
	require.Error(t, err, "a one-of-one quorum was accepted")
}

// committee returns an engine at threshold 2 whose core knows both validators
// for BLS, and the block they are all signing.
func committee(t *testing.T, self string) (*Quasar, ids.ID, []byte) {
	t.Helper()
	q, err := NewQuasar(QuasarConfig{
		ValidatorID: self, Threshold: 2, TotalNodes: 2, Logger: log.NewNoOpLogger(),
	})
	require.NoError(t, err)
	require.NoError(t, q.AddValidator("validator-a", 100))
	require.NoError(t, q.AddValidator("validator-b", 100))

	blockID := ids.GenerateTestID()
	hash := make([]byte, 64)
	copy(hash, blockID[:])
	q.pendingBlocks[blockID] = &PendingBlock{BlockID: blockID, BlockHash: hash, Height: 1}
	return q, blockID, hash
}

// TestQuantumFinalityNeedsBothLegs is the happy path, with real BLS signatures
// from two validators the core knows.
//
// The classical leg aggregates and VERIFIES; the post-quantum leg is counted.
// Neither alone is quantum finality — the whole point of running two is that a
// break in one is not a break in the chain.
func TestQuantumFinalityNeedsBothLegs(t *testing.T) {
	q, blockID, hash := committee(t, "validator-a")
	core := q.GetQuasar()
	ctx := context.Background()

	// Two peers' BLS signatures, as they arrive over the wire.
	for _, name := range []string{"validator-a", "validator-b"} {
		sig, err := core.SignMessageWithContext(ctx, name, hash)
		require.NoError(t, err, "a validator the core knows could not sign")
		require.NoError(t, q.AddBLSSignature(blockID, &quasar.BLSSignature{
			Signature:   sig.BLS,
			ValidatorID: sig.ValidatorID,
			SignerIndex: sig.SignerIndex,
			IsThreshold: sig.IsThreshold,
		}))
	}

	pending := q.pendingBlocks[blockID]
	_, finalized, err := q.TryFinalize(ctx, blockID)
	require.NoError(t, err)
	require.True(t, pending.BLSFinalized, "two real signatures did not carry the classical leg")
	require.False(t, finalized, "the classical leg alone was taken for quantum finality")
	require.False(t, q.IsFinalized(blockID))

	// Now the post-quantum leg, from the same two validators.
	for _, name := range []string{"validator-a", "validator-b"} {
		require.NoError(t, q.AddCoronaSignature(blockID, &quasar.CoronaSignature{
			Signature: []byte{1}, ValidatorID: name, Round: 1,
		}))
	}

	agg, finalized, err := q.TryFinalize(ctx, blockID)
	require.NoError(t, err)
	require.True(t, finalized, "both legs reached their threshold and the block did not finalize")
	require.NotNil(t, agg)
	require.True(t, q.IsFinalized(blockID))

	// Cleanup below the finalized frontier releases it from both maps.
	q.Cleanup(2)
	require.NotContains(t, q.pendingBlocks, blockID)
	require.False(t, q.IsFinalized(blockID))
}

// TestSignBlockReportsAMissingCoronaShare.
//
// A validator joins through AddValidator, which gives it a BLS key and no
// Corona share — the shares must come from a dealerless DKG, and until one
// lands there is nothing to sign the post-quantum leg with. What matters is
// that SignBlock SAYS so: a node that reported success here would be claiming
// a post-quantum signature it never made.
func TestSignBlockReportsAMissingCoronaShare(t *testing.T) {
	q, _, hash := committee(t, "validator-a")

	blockID := ids.GenerateTestID()
	_, err := q.SignBlock(context.Background(), blockID, hash, 1)
	require.ErrorContains(t, err, "Corona sign failed",
		"the post-quantum leg reported success without a share to sign with")
	require.NotContains(t, q.pendingBlocks, blockID, "the failed block is tracked forever")
}

// TestAggregationOverSignaturesThatAreNotSignatures fails closed. The BLS leg
// aggregates and VERIFIES, so bytes that never came from a signer must not
// carry the classical half of finality.
func TestAggregationOverSignaturesThatAreNotSignatures(t *testing.T) {
	q, blockID := engine(t, 3)

	for _, id := range []string{"validator-1", "validator-2", "validator-3"} {
		require.NoError(t, q.AddBLSSignature(blockID, &quasar.BLSSignature{
			Signature: []byte("not a signature"), ValidatorID: id,
		}))
	}
	require.Len(t, q.pendingBlocks[blockID].BLSSignatures, 3)

	_, finalized, _ := q.TryFinalize(context.Background(), blockID)
	require.False(t, finalized, "three forged signatures reached the threshold and finalized")
	require.False(t, q.pendingBlocks[blockID].BLSFinalized)
	require.False(t, q.IsFinalized(blockID))
}

// TestAddValidatorRefusesADuplicate: the active count is what the threshold is
// measured against, so one validator joining twice would count twice.
func TestAddValidatorRefusesADuplicate(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", TotalNodes: 3, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	require.NoError(t, q.AddValidator("validator-1", 100))
	after := q.GetActiveValidators()
	if err := q.AddValidator("validator-1", 100); err != nil {
		require.Equal(t, after, q.GetActiveValidators())
		return
	}
	require.Equal(t, after, q.GetActiveValidators(),
		"one validator joining twice moved the count the threshold is measured against")
}
