// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"testing"

	"github.com/stretchr/testify/require"

	nodefee "github.com/luxfi/node/vms/types/fee"
)

// TestGas_PerSchemeDistinct proves the cost model is real: a TFHE boolean, a
// BFV vector and a CKKS vector are priced differently, and doubling the ring
// dimension raises the price.
func TestGas_PerSchemeDistinct(t *testing.T) {
	feeFor := func(scheme string) uint64 {
		f, err := FeeFor(&Transaction{Type: TxRequestDecrypt, Scheme: scheme})
		require.NoError(t, err)
		return f
	}
	require.Less(t, feeFor("tfhe-n10"), feeFor("bfv-n13"), "small LWE ciphertexts are cheapest")
	require.Less(t, feeFor("bfv-n13"), feeFor("ckks-n13"), "at equal N, CKKS costs more than BFV")
	require.Less(t, feeFor("bfv-n13"), feeFor("bfv-n14"), "doubling the ring dimension must cost more")
	require.Less(t, feeFor("ckks-n14"), feeFor("ckks-n15"), "doubling the ring dimension must cost more")
	require.NotEqual(t, feeFor("bfv-n13"), feeFor("bgv-n13"), "distinct schemes must price distinctly")
}

// TestGas_AllOperationsMeetFloor proves every scheduled operation settles at or
// above the node admission floor, so settlement and admission never drift.
func TestGas_AllOperationsMeetFloor(t *testing.T) {
	for op := range opBaseGas {
		if usesScheme(op) {
			for scheme := range schemeGas {
				f, err := FeeFor(&Transaction{Type: op, Scheme: scheme})
				require.NoError(t, err)
				require.GreaterOrEqualf(t, f, nodefee.MinTxFeeFloor,
					"op %d scheme %s fee %d below floor %d", op, scheme, f, nodefee.MinTxFeeFloor)
			}
			continue
		}
		f, err := FeeFor(&Transaction{Type: op})
		require.NoError(t, err)
		require.GreaterOrEqualf(t, f, nodefee.MinTxFeeFloor,
			"op %d fee %d below floor %d", op, f, nodefee.MinTxFeeFloor)
	}
	require.GreaterOrEqual(t, MinScheduledFee(), nodefee.MinTxFeeFloor,
		"the cheapest scheduled fee must satisfy the admission floor")
}

// TestGas_UnknownSchemeRejected proves an unrecognised scheme is refused (fail
// closed), never priced at the bare base cost.
func TestGas_UnknownSchemeRejected(t *testing.T) {
	_, err := GasFor(&Transaction{Type: TxRegisterCiphertext, Scheme: "paillier"})
	require.ErrorIs(t, err, ErrUnknownScheme)

	_, err = GasFor(&Transaction{Type: TxRequestDecrypt, Scheme: ""})
	require.ErrorIs(t, err, ErrUnknownScheme)

	require.False(t, SupportedScheme("paillier"))
	require.True(t, SupportedScheme(testScheme))
}

// TestGas_UnknownOperationRejected proves an unpriced transaction type cannot
// slip through at zero cost.
func TestGas_UnknownOperationRejected(t *testing.T) {
	_, err := GasFor(&Transaction{Type: 200, Scheme: testScheme})
	require.Error(t, err)
}

// TestGas_RecordOpsAreSchemeIndependent proves the fixed-size record writes
// ignore the scheme field entirely.
func TestGas_RecordOpsAreSchemeIndependent(t *testing.T) {
	for _, op := range []uint8{TxGrantPermit, TxRevokePermit, TxFulfillDecrypt, TxAdvanceEpoch} {
		a, err := FeeFor(&Transaction{Type: op, Scheme: "ckks-n15"})
		require.NoError(t, err)
		b, err := FeeFor(&Transaction{Type: op})
		require.NoError(t, err)
		require.Equalf(t, a, b, "op %d must be scheme-independent", op)
	}
}

// TestGas_EveryOperationIsPriced proves the schedule covers every transaction
// type the package defines — a new operation cannot ship unpriced.
func TestGas_EveryOperationIsPriced(t *testing.T) {
	for _, op := range []uint8{
		TxRegisterCiphertext, TxGrantPermit, TxRevokePermit,
		TxRequestDecrypt, TxFulfillDecrypt, TxAdvanceEpoch,
	} {
		require.Containsf(t, opBaseGas, op, "transaction type %d has no base gas", op)
		require.Containsf(t, opNames, op, "transaction type %d has no public name", op)
	}
	require.Len(t, opBaseGas, len(opNames), "every priced operation must have exactly one name")
}
