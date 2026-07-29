// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// pendingQuasar returns a Quasar with one pending block awaiting signatures.
func pendingQuasar(threshold int) (*Quasar, ids.ID) {
	blockID := ids.GenerateTestID()
	q := &Quasar{
		threshold: threshold,
		log:       log.NewNoOpLogger(),
		pendingBlocks: map[ids.ID]*PendingBlock{
			blockID: {
				BlockID:          blockID,
				BlockHash:        blockID[:],
				Height:           1,
				BLSSignatures:    make([]*quasar.BLSSignature, 0),
				CoronaSignatures: make([]*quasar.CoronaSignature, 0),
			},
		},
		finalizedBlocks: make(map[ids.ID]bool),
	}
	return q, blockID
}

// TestOneValidatorCannotReachCoronaThreshold proves the post-quantum finality leg
// counts distinct validators.
//
// TryFinalize finalizes the Corona leg on len(CoronaSignatures) >= threshold and
// verifies none of those signatures (unlike the BLS leg, which aggregates and
// verifies). A validator resending its signature therefore drove the count to the
// threshold on its own and satisfied the post-quantum half of quantum finality
// alone.
func TestOneValidatorCannotReachCoronaThreshold(t *testing.T) {
	require := require.New(t)
	q, blockID := pendingQuasar(3)

	sig := &quasar.CoronaSignature{Signature: []byte{1}, ValidatorID: "validator-1", SignerIndex: 0, Round: 1}
	require.NoError(q.AddCoronaSignature(blockID, sig))
	require.ErrorIs(q.AddCoronaSignature(blockID, sig), errDuplicateSigner)
	require.ErrorIs(q.AddCoronaSignature(blockID, sig), errDuplicateSigner)

	pending := q.pendingBlocks[blockID]
	require.Len(pending.CoronaSignatures, 1, "one validator contributes one signature")
	require.Less(len(pending.CoronaSignatures), q.threshold,
		"a single validator must stay below the threshold")

	// Even a signature with the same validator but different bytes is one vote.
	require.ErrorIs(q.AddCoronaSignature(blockID, &quasar.CoronaSignature{
		Signature: []byte{9}, ValidatorID: "validator-1", SignerIndex: 0, Round: 2,
	}), errDuplicateSigner)
	require.Len(pending.CoronaSignatures, 1)

	_, finalized, err := q.TryFinalize(context.Background(), blockID)
	require.Error(err, "quasar core is not initialized in this fixture")
	require.False(finalized)
	require.False(pending.CoronaFinalized, "the Corona leg must not be finalized by one validator")
}

// TestDistinctValidatorsReachCoronaThreshold is the other half: three different
// validators do reach a threshold of three.
func TestDistinctValidatorsReachCoronaThreshold(t *testing.T) {
	require := require.New(t)
	q, blockID := pendingQuasar(3)

	for _, id := range []string{"validator-1", "validator-2", "validator-3"} {
		require.NoError(q.AddCoronaSignature(blockID, &quasar.CoronaSignature{
			Signature: []byte{1}, ValidatorID: id, Round: 1,
		}))
	}
	require.Len(q.pendingBlocks[blockID].CoronaSignatures, 3)
}

// TestOneValidatorCannotReachBLSThreshold is the same rule on the classical leg,
// where a resent signature also inflated the count compared against the
// threshold.
func TestOneValidatorCannotReachBLSThreshold(t *testing.T) {
	require := require.New(t)
	q, blockID := pendingQuasar(3)

	sig := &quasar.BLSSignature{Signature: []byte{1}, ValidatorID: "validator-1"}
	require.NoError(q.AddBLSSignature(blockID, sig))
	require.ErrorIs(q.AddBLSSignature(blockID, sig), errDuplicateSigner)
	require.ErrorIs(q.AddBLSSignature(blockID, sig), errDuplicateSigner)

	require.Len(q.pendingBlocks[blockID].BLSSignatures, 1)
}
