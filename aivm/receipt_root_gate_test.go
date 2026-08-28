// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"context"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"
)

// TestVerifyRejectsBlockClaimingZeroReceiptRoot proves the receipt-root
// comparison has no exemption for the zero hash.
//
// verifyImported exists so every validator reaches byte-identical engine state
// from the same committed inputs. Exempting the zero hash made that guarantee
// opt-out: a proposer recorded intents, wrote a zero receipt_root, and followers
// applied the intents without ever checking their engine state agreed with the
// proposer's.
func TestVerifyRejectsBlockClaimingZeroReceiptRoot(t *testing.T) {
	require := require.New(t)
	v, reqr, _ := newAIVMForConsensus(t)
	e, st, lg := v.QuorumEngine()

	reward := uint256.NewInt(1_000_000_000_000_000_000)

	// Drive one task to settlement so the engine has folded a receipt and the
	// receipt_root is non-zero. Until something settles the root is legitimately
	// zero on both sides, which is why the exemption looked harmless.
	settled := mkIntent(e, reqr, testN, testThr, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, acceptAll, settled, 100)
	require.NoError(err)
	selected, _ := e.SelectOperators(st, taskID, modelSpec, testN)
	out := h(0x42)
	for _, op := range selected {
		require.NoError(e.CommitResponse(st, taskID, op, opCommit(taskID, op, out, h(0x01), h(0x02)), 101))
		require.NoError(e.RevealResponse(st, taskID, op, out, h(0x01), h(0x02), 131))
	}
	_, err = e.Settle(st, lg, taskID, 161)
	require.NoError(err)

	root := e.ReceiptRoot(st)
	require.NotEqual(common.Hash{}, root, "a settled receipt must move the root")

	// An honest proposer stamps the engine's own root and verifies.
	v.EnqueueCommittedIntent(mkIntent(e, reqr, testN, testThr, uint256.NewInt(2), reward))
	blk, err := v.BuildBlock(context.Background())
	require.NoError(err)
	honest := blk.(*Block)
	require.Len(honest.ImportedIntents, 1)
	require.Equal(root, honest.ReceiptRoot)
	require.NoError(honest.Verify(context.Background()))

	// The same block claiming a zero root must be refused, not waved through.
	tampered := *honest
	tampered.ReceiptRoot = common.Hash{}
	require.ErrorIs(tampered.Verify(context.Background()), ErrReceiptRootMismatch)
}
