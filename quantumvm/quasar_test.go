// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"sync"
	"testing"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/stretchr/testify/require"
)

// committee returns a bridge whose core knows every member, plus the block they
// are all signing. Only a registered validator's signature can verify, so the
// roster is what decides whose statement counts.
func committee(t *testing.T, self string, peers ...string) (*Quasar, ids.ID, []byte) {
	t.Helper()
	q, err := NewQuasar(QuasarConfig{
		ValidatorID: self,
		Committee:   1 + len(peers),
		Logger:      log.NewNoOpLogger(),
	})
	require.NoError(t, err)
	for _, peer := range peers {
		require.NoError(t, q.AddValidator(peer, 100))
	}

	blockID := ids.GenerateTestID()
	hash := make([]byte, 64)
	copy(hash, blockID[:])
	q.pendingBlocks[blockID] = &PendingBlock{BlockID: blockID, BlockHash: hash, Height: 1}
	return q, blockID, hash
}

// signAs produces a real signature from a committee member over a message.
func signAs(t *testing.T, q *Quasar, validatorID string, message []byte) *quasar.QuasarSig {
	t.Helper()
	sig, err := q.GetQuasar().SignMessageWithContext(context.Background(), validatorID, message)
	require.NoError(t, err, "a validator the core knows could not sign")
	return sig
}

// TestThresholdFollowsTheCommittee.
//
// The threshold is derived, never configured, so the two cannot disagree — and
// the derivation has to land in the range that is actually a quorum. ⌊2n/3⌋+1
// equals n for every n below four, which is unanimity: zero Byzantine
// tolerance, one absent validator is a halt, and the consensus core refuses it
// outright ("threshold must be less than validator count"). So a committee that
// small is refused where it is named, rather than producing a bridge that
// cannot rotate a key.
func TestThresholdFollowsTheCommittee(t *testing.T) {
	for _, n := range []int{1, 2, 3} {
		_, err := NewQuasar(QuasarConfig{ValidatorID: "self", Committee: n, Logger: log.NewNoOpLogger()})
		require.Error(t, err, "a committee of %d tolerates no fault and was accepted", n)
	}

	for _, tc := range []struct{ committee, threshold int }{
		{4, 3}, {5, 4}, {7, 5}, {10, 7}, {100, 67},
	} {
		q, err := NewQuasar(QuasarConfig{
			ValidatorID: "self", Committee: tc.committee, Logger: log.NewNoOpLogger(),
		})
		require.NoError(t, err)
		require.Equal(t, tc.threshold, q.GetThreshold(), "⌊2n/3⌋+1 of %d", tc.committee)
		require.Equal(t, tc.committee, q.Committee())
		require.Less(t, q.GetThreshold(), q.Committee(), "a quorum of everyone is not a quorum")
		require.GreaterOrEqual(t, q.GetThreshold(), 2)
	}

	// An unset committee settles on the smallest that survives a fault.
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self"})
	require.NoError(t, err)
	require.Equal(t, config.CommitteeMin, q.Committee())
	require.Equal(t, config.Quorum(config.CommitteeMin), q.GetThreshold())

	// A nil logger is not a reason to crash on the first Debug call.
	require.NotPanics(t, func() { _ = q.AddValidator("v1", 1) })
}

// TestABridgeWithNoIdentityIsRefused: a signer with no name cannot be one of a
// number of distinct signers.
func TestABridgeWithNoIdentityIsRefused(t *testing.T) {
	_, err := NewQuasar(QuasarConfig{Committee: 4, Logger: log.NewNoOpLogger()})
	require.ErrorIs(t, err, errNoValidatorID)
}

// TestTheBridgeSignsForItself.
//
// The node was never registered with its own consensus core, so signing
// answered "validator not found" on every call — and everything downstream
// followed: the failure path deleted the pending entry, so a peer's signature
// arriving afterwards found no block to attach to, so the quorum was never
// reached and finality was unreachable. One missing registration; the whole
// bridge dead, and quiet about it.
func TestTheBridgeSignsForItself(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", Committee: 4, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	blockID := ids.GenerateTestID()
	sig, err := q.SignBlock(context.Background(), blockID, blockID[:], 1)
	require.NoError(t, err, "the node cannot sign for its own identity")
	require.Equal(t, "self", sig.ValidatorID)

	pending := q.pendingBlocks[blockID]
	require.NotNil(t, pending, "a signed block is not being tracked, so no peer signature can join it")
	require.Len(t, pending.Signatures, 1)

	// Signing it again is the same statement, not a second signer.
	again, err := q.SignBlock(context.Background(), blockID, blockID[:], 1)
	require.NoError(t, err)
	require.Equal(t, sig, again)
	require.Len(t, q.pendingBlocks[blockID].Signatures, 1)

	// And a peer's signature now finds the block and joins it.
	require.NoError(t, q.AddValidator("peer", 1))
	require.NoError(t, q.AddSignature(blockID, signAs(t, q, "peer", pending.BlockHash)))
	require.Len(t, q.pendingBlocks[blockID].Signatures, 2)
}

// TestOnlyAVerifiedSignatureCounts.
//
// The quorum was a count of STRINGS: a caller supplied a ValidatorID and it was
// counted, unverified, against the threshold. So three fabricated ids finalized
// a block; five spellings of one name — case, a trailing space, an embedded NUL,
// the fullwidth forms — counted as five distinct signers of one signature; and a
// signature made for block A was accepted onto block B, because nothing bound a
// signature to its message.
//
// Verification fixes all three at once, because the name is looked up in the
// committee and the signature is checked against THAT key over THIS block.
func TestOnlyAVerifiedSignatureCounts(t *testing.T) {
	q, blockID, hash := committee(t, "validator-a", "validator-b", "validator-c", "validator-d")

	// Names nobody holds a key for.
	for _, name := range []string{"ghost-1", "ghost-2", "ghost-3"} {
		require.ErrorIs(t, q.AddSignature(blockID, &quasar.QuasarSig{
			BLS: []byte("not a signature"), ValidatorID: name,
		}), errUnverifiedSigner, "a fabricated validator %q was counted", name)
	}
	require.Empty(t, q.pendingBlocks[blockID].Signatures)

	// One real signature, re-labelled every way a string can be respelled.
	real := signAs(t, q, "validator-a", hash)
	require.NoError(t, q.AddSignature(blockID, real))
	for _, respelling := range []string{
		"validator-a ", " validator-a", "Validator-A", "VALIDATOR-A",
		"validator-a\x00", "ｖａｌｉｄａｔｏｒ－ａ", "validator-a\n", "validator‑a",
	} {
		require.ErrorIs(t, q.AddSignature(blockID, &quasar.QuasarSig{
			BLS: real.BLS, MLDSA: real.MLDSA, ValidatorID: respelling,
			IsThreshold: real.IsThreshold, SignerIndex: real.SignerIndex,
		}), errUnverifiedSigner, "%q counted as a second signer of one signature", respelling)
	}

	// The same name twice is one signer, however the bytes differ.
	require.ErrorIs(t, q.AddSignature(blockID, real), errDuplicateSigner)
	require.ErrorIs(t, q.AddSignature(blockID, signAs(t, q, "validator-a", hash)), errDuplicateSigner)
	require.Len(t, q.pendingBlocks[blockID].Signatures, 1)

	// A signature for another block does not count for this one.
	other := ids.GenerateTestID()
	require.ErrorIs(t, q.AddSignature(blockID, signAs(t, q, "validator-b", other[:])),
		errUnverifiedSigner, "a signature made for another block was accepted onto this one")

	// Nor does no signature at all.
	require.ErrorIs(t, q.AddSignature(blockID, nil), errUnverifiedSigner)
	require.Len(t, q.pendingBlocks[blockID].Signatures, 1)
}

// TestFinalityNeedsAnAggregateThatVerifies.
//
// Reaching the count is necessary and not sufficient. The signatures are
// aggregated and the aggregate is checked against the committee's keys, so a
// block finalizes on cryptography rather than on arithmetic.
func TestFinalityNeedsAnAggregateThatVerifies(t *testing.T) {
	ctx := context.Background()
	q, blockID, hash := committee(t, "validator-a", "validator-b", "validator-c", "validator-d")
	require.Equal(t, 3, q.GetThreshold())

	// Below the threshold nothing finalizes and nothing errors: it is simply
	// not time yet.
	for _, name := range []string{"validator-a", "validator-b"} {
		require.NoError(t, q.AddSignature(blockID, signAs(t, q, name, hash)))
	}
	agg, finalized, err := q.TryFinalize(ctx, blockID)
	require.NoError(t, err)
	require.False(t, finalized, "two of three finalized a block")
	require.Nil(t, agg)
	require.False(t, q.IsFinalized(blockID))

	// The third carries it.
	require.NoError(t, q.AddSignature(blockID, signAs(t, q, "validator-c", hash)))
	agg, finalized, err = q.TryFinalize(ctx, blockID)
	require.NoError(t, err)
	require.True(t, finalized, "a verified quorum did not finalize the block")
	require.NotNil(t, agg)
	require.True(t, q.IsFinalized(blockID))
	require.True(t, q.VerifyAggregate(ctx, hash, agg))
	require.False(t, q.VerifyAggregate(ctx, []byte("another block"), agg),
		"the aggregate verified against a message it does not sign")

	// Cleanup below the finalized frontier releases it from both maps.
	q.Cleanup(2)
	require.NotContains(t, q.pendingBlocks, blockID)
	require.False(t, q.IsFinalized(blockID))
}

// TestSignaturesThatAreNotSignaturesFinalizeNothing. The set is verified on the
// way in, so bytes that never came from a signer never reach the threshold.
func TestSignaturesThatAreNotSignaturesFinalizeNothing(t *testing.T) {
	q, blockID, _ := committee(t, "validator-a", "validator-b", "validator-c", "validator-d")

	for _, name := range []string{"validator-b", "validator-c", "validator-d"} {
		require.ErrorIs(t, q.AddSignature(blockID, &quasar.QuasarSig{
			BLS: []byte("not a signature"), ValidatorID: name,
		}), errUnverifiedSigner)
	}
	require.Empty(t, q.pendingBlocks[blockID].Signatures)

	_, finalized, err := q.TryFinalize(context.Background(), blockID)
	require.NoError(t, err)
	require.False(t, finalized, "three forged signatures reached the threshold and finalized")
	require.False(t, q.IsFinalized(blockID))
}

// TestSignaturesForAnUnknownBlockAreRefused: an id nobody proposed is not a
// place to accumulate signatures a peer chose the id of.
func TestSignaturesForAnUnknownBlockAreRefused(t *testing.T) {
	q, _, _ := committee(t, "validator-a", "validator-b", "validator-c", "validator-d")
	stranger := ids.GenerateTestID()

	require.ErrorIs(t, q.AddSignature(stranger, &quasar.QuasarSig{ValidatorID: "validator-b"}), errUnknownBlock)
	_, _, err := q.TryFinalize(context.Background(), stranger)
	require.ErrorIs(t, err, errUnknownBlock)
}

// TestCleanupReleasesWhatWillNeverFinalize.
//
// minHeight is the caller's finalized frontier, so nothing below it can gather
// another signature. Releasing only the FINALIZED entries kept exactly the ones
// that accumulate — every proposal that lost, timed out or failed to sign — and
// the two maps grew for the life of the process.
func TestCleanupReleasesWhatWillNeverFinalize(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", Committee: 4, Logger: log.NewNoOpLogger()})
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
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", Committee: 4, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	// A cancelled context is the cheapest way to make signing fail.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	blockID := ids.GenerateTestID()
	_, err = q.SignBlock(ctx, blockID, blockID[:], 1)
	require.Error(t, err)
	require.NotContains(t, q.pendingBlocks, blockID,
		"a block that failed to sign is tracked forever: it can never finalize, so Cleanup never sees it")
}

// TestSignBlockDoesNotRaceIncomingSignatures. Signing appends to the same slice
// AddSignature appends to, and the log line afterwards read its length. Under
// -race that read is a data race against every arriving peer signature.
func TestSignBlockDoesNotRaceIncomingSignatures(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", Committee: 20, Logger: log.NewNoOpLogger()})
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
			_ = q.AddSignature(blockID, &quasar.QuasarSig{
				BLS: []byte{byte(i)}, ValidatorID: string(rune('a' + i)),
			})
			_ = q.IsFinalized(blockID)
			q.Cleanup(0)
			_ = q.GetActiveValidators()
		}(i)
	}
	wg.Wait()
}

// TestSignBlockAcceptsAnyMessageLength. The signer takes whatever the finality
// bridge supplies, which is not always block-hash shaped.
func TestSignBlockAcceptsAnyMessageLength(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", Committee: 4, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)

	for _, n := range []int{0, 1, 31, 32, 64} {
		blockID := ids.GenerateTestID()
		require.NotPanics(t, func() {
			_, _ = q.SignBlock(context.Background(), blockID, make([]byte, n), 1)
		}, "a %d-byte message crashed the signer", n)
	}
}

// TestTheCommitteeIsASetOfADeclaredSize.
//
// Registering an id twice hands the core a FRESH key for it, which silently
// invalidates every signature that validator already contributed; registering
// more members than the committee declares makes the threshold a quorum of a
// committee that no longer exists.
func TestTheCommitteeIsASetOfADeclaredSize(t *testing.T) {
	q, err := NewQuasar(QuasarConfig{ValidatorID: "self", Committee: 4, Logger: log.NewNoOpLogger()})
	require.NoError(t, err)
	require.Equal(t, 1, q.GetActiveValidators(), "the node is a member of its own committee")

	require.NoError(t, q.AddValidator("validator-1", 100))
	require.Equal(t, 2, q.GetActiveValidators())

	require.ErrorIs(t, q.AddValidator("validator-1", 100), errAlreadyRegistered)
	require.ErrorIs(t, q.AddValidator("self", 1), errAlreadyRegistered)
	require.Equal(t, 2, q.GetActiveValidators(),
		"one validator joining twice moved the count the threshold is measured against")

	require.NoError(t, q.AddValidator("validator-2", 100))
	require.NoError(t, q.AddValidator("validator-3", 100))
	require.ErrorIs(t, q.AddValidator("validator-4", 100), errCommitteeFull)
	require.ErrorIs(t, q.AddValidator("", 100), errNoValidatorID)
	require.Equal(t, 4, q.GetActiveValidators())

	require.NotNil(t, q.GetQuasar())
}

// TestARegisteredKeyIsWhatVerifies: the bridge's own verification helpers agree
// with what AddSignature admits, so nothing can be verified one way in one place
// and another way in another.
func TestARegisteredKeyIsWhatVerifies(t *testing.T) {
	q, _, hash := committee(t, "validator-a", "validator-b", "validator-c", "validator-d")

	sig := signAs(t, q, "validator-b", hash)
	require.True(t, q.VerifySignature(hash, sig))
	require.False(t, q.VerifySignature([]byte("another message"), sig))
	require.False(t, q.VerifySignature(hash, nil))
	require.False(t, q.VerifyAggregate(context.Background(), hash, nil))

	relabelled := *sig
	relabelled.ValidatorID = "validator-c"
	require.False(t, q.VerifySignature(hash, &relabelled),
		"a signature relabelled to another committee member verified")
}
