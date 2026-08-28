// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
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

// TestGas_PayloadBytesArePriced is the regression test for unpriced bytes. The
// schedule had no length term, so a megabyte of commitments rode on chain — into
// the block AND into the key record, permanently — for the same flat fee as an
// empty payload. Price must be strictly increasing in payload length, at the
// declared rate, for every operation.
func TestGas_PayloadBytesArePriced(t *testing.T) {
	for _, op := range []uint8{TxRegisterKey, TxSetPolicy, TxAuthorize, TxRevokeKey} {
		algo := ""
		if usesAlgorithm(op) {
			algo = "ml-dsa-65"
		}
		empty, err := GasFor(&Transaction{Type: op, Algorithm: algo})
		require.NoError(t, err)
		small, err := GasFor(&Transaction{Type: op, Algorithm: algo, Payload: make([]byte, 100)})
		require.NoError(t, err)
		large, err := GasFor(&Transaction{Type: op, Algorithm: algo, Payload: make([]byte, 1_000_000)})
		require.NoError(t, err)

		require.Greaterf(t, small, empty, "op %d: 100 bytes must cost more than none", op)
		require.Greaterf(t, large, small, "op %d: a megabyte must cost more than 100 bytes", op)
		require.Equalf(t, empty+100*GasPerPayloadByte, small,
			"op %d: bytes must be priced at the declared rate", op)
		require.Equalf(t, empty+1_000_000*GasPerPayloadByte, large, "op %d", op)
	}
}

// TestGas_PayloadPricingReachesThePayer proves the byte term is not an isolated
// arithmetic fact: a payer submitting a larger payload is charged more real
// balance, and the surplus is burned.
func TestGas_PayloadPricingReachesThePayer(t *testing.T) {
	small, large := newTestKey(t), newTestKey(t)
	const fund = uint64(100_000_000_000)
	vm := newTestVM(t, map[string]uint64{small.hexAddr(): fund, large.hexAddr(): fund})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tiny := registerTx(t, small, "a", 100_000_000, 1)

	// The same operation carrying 64 KiB of PUBLIC commitments.
	bulk := make([][]byte, 64)
	for i := range bulk {
		bulk[i] = make([]byte, 1024)
	}
	payload := mustJSONRaw(RegisterKeyPayload{
		Name: "b", PublicKey: []byte("PUB"), Threshold: 1, TotalShares: 1, Commitments: bulk,
	})
	fat := &Transaction{
		Type: TxRegisterKey, Algorithm: "ml-dsa-65", Payer: large.addr,
		KeyID: deriveKeyID("b"), GasLimit: 100_000_000, Nonce: 1, Payload: payload,
	}
	large.sign(t, fat)

	acceptOne(t, vm, tiny)
	acceptOne(t, vm, fat)

	tinyBal, err := vm.Balance(small.addr)
	require.NoError(t, err)
	fatBal, err := vm.Balance(large.addr)
	require.NoError(t, err)
	require.Less(t, fatBal, tinyBal, "a bigger payload must cost the payer more")

	burned, err := vm.Burned()
	require.NoError(t, err)
	require.Equal(t, (fund-tinyBal)+(fund-fatBal), burned,
		"everything both payers lost was burned")
}
