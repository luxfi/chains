// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"testing"

	"github.com/stretchr/testify/require"

	nodefee "github.com/luxfi/node/vms/types/fee"
)

// TestGas_PerAlgorithmDistinct proves the audit fix: ML-KEM encapsulation,
// ML-DSA-65 sign-authorize, and BLS verify are priced DIFFERENTLY, not by one
// flat floor.
func TestGas_PerAlgorithmDistinct(t *testing.T) {
	feeFor := func(algo string) uint64 {
		f, err := FeeFor(&Transaction{Type: TxAuthorize, Algorithm: algo})
		require.NoError(t, err)
		return f
	}
	kem := feeFor("ml-kem-768")
	dsa := feeFor("ml-dsa-65")
	bls := feeFor("bls-threshold")

	require.NotEqual(t, kem, dsa, "ML-KEM and ML-DSA-65 must price differently")
	require.NotEqual(t, dsa, bls, "ML-DSA-65 and BLS must price differently")
	require.NotEqual(t, kem, bls, "ML-KEM and BLS must price differently")
	// Real-cost ordering: KEM encaps < BLS verify < ML-DSA-65 threshold sign.
	require.Less(t, kem, bls)
	require.Less(t, bls, dsa)
}

// TestGas_AllOperationsMeetFloor proves every scheduled operation settles at or
// above the node admission floor, so settlement and admission never drift.
func TestGas_AllOperationsMeetFloor(t *testing.T) {
	// Algorithm-priced operations across every supported algorithm.
	for _, op := range []uint8{TxRegisterKey, TxAuthorize} {
		for algo := range algoGas {
			f, err := FeeFor(&Transaction{Type: op, Algorithm: algo})
			require.NoError(t, err)
			require.GreaterOrEqualf(t, f, nodefee.MinTxFeeFloor,
				"op %d algo %s fee %d below floor %d", op, algo, f, nodefee.MinTxFeeFloor)
		}
	}
	// Policy-only operations (algorithm-independent).
	for _, op := range []uint8{TxSetPolicy, TxRevokeKey} {
		f, err := FeeFor(&Transaction{Type: op})
		require.NoError(t, err)
		require.GreaterOrEqual(t, f, nodefee.MinTxFeeFloor)
	}
	require.GreaterOrEqual(t, MinScheduledFee(), nodefee.MinTxFeeFloor,
		"the cheapest scheduled fee must satisfy the admission floor")
}

// TestGas_UnknownAlgorithmRejected proves an unrecognised algorithm is refused
// (fail closed), never priced at the bare base cost.
func TestGas_UnknownAlgorithmRejected(t *testing.T) {
	_, err := GasFor(&Transaction{Type: TxRegisterKey, Algorithm: "rsa-2048"})
	require.ErrorIs(t, err, ErrUnknownAlgorithm)

	_, err = GasFor(&Transaction{Type: TxAuthorize, Algorithm: ""})
	require.ErrorIs(t, err, ErrUnknownAlgorithm)

	require.False(t, SupportedAlgorithm("rsa-2048"))
	require.True(t, SupportedAlgorithm("ml-dsa-65"))
}

// TestGas_PolicyOpsAlgorithmIndependent proves policy operations ignore the
// algorithm field entirely.
func TestGas_PolicyOpsAlgorithmIndependent(t *testing.T) {
	a, err := FeeFor(&Transaction{Type: TxSetPolicy, Algorithm: "ml-dsa-87"})
	require.NoError(t, err)
	b, err := FeeFor(&Transaction{Type: TxSetPolicy, Algorithm: ""})
	require.NoError(t, err)
	require.Equal(t, a, b, "SetPolicy must be algorithm-independent")
}
