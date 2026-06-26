// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"testing"

	"github.com/luxfi/chains/dexvm/txs"
	"github.com/luxfi/constants"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"
	"github.com/luxfi/warp"
)

// luxL2NetworkID is a sovereign L1/L2/L3 primary-network id that is NOT the Lux
// primary network (1). A chain on this id has its OWN native UTXO asset
// (UTXOAssetIDFor(luxL2NetworkID)), distinct from LUX — exactly the case the CTO
// directive targets: "any L2 or L3 building with native currency on top of LUX".
const luxL2NetworkID uint32 = 8675309

// newChainVMForNetwork returns a fully-initialized ChainVM pinned to networkID,
// so a test can assert the fee policy on an arbitrary network (the primary
// network or an L2/L3 with its own native token).
func newChainVMForNetwork(t *testing.T, networkID uint32) *ChainVM {
	t.Helper()
	logger := log.NewNoOpLogger()
	cvm := NewChainVM(logger)
	rt := &runtime.Runtime{
		ChainID:   ids.GenerateTestID(),
		NetworkID: networkID,
		Log:       logger,
	}
	if err := cvm.Initialize(context.Background(), vm.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vm.Message, 8),
		Sender:   warp.FakeSender{},
		Log:      logger,
	}); err != nil {
		t.Fatalf("init dexvm (network %d): %v", networkID, err)
	}
	return cvm
}

// TestFeeAsset_IsCanonicalLUX_NotLocalNative is the core property: the DEX fee
// asset is canonical LUX on EVERY network — the Lux primary network AND an L2/L3
// whose own native token differs from LUX. Before this change the fee was
// denominated in constants.UTXOAssetIDFor(localNetworkID) (the local native
// token); now it is always LUX, so DEX fees settle to the L0 token regardless of
// the chain's native currency.
func TestFeeAsset_IsCanonicalLUX_NotLocalNative(t *testing.T) {
	// Canonical LUX is the PRIMARY-network (id 1) UTXO asset.
	wantLUX := constants.UTXOAssetIDFor(constants.MainnetID)
	if LUXAssetID != wantLUX {
		t.Fatalf("LUXAssetID = %s, want UTXOAssetIDFor(1) = %s", LUXAssetID, wantLUX)
	}

	// (1) Lux primary network: fee asset is LUX (and here LUX == the local
	// native asset, since the local network IS the primary network).
	primary := newChainVMForNetwork(t, constants.MainnetID)
	if got := primary.FeePolicy().FeeAssetID(); got != LUXAssetID {
		t.Fatalf("primary-network fee asset = %s, want LUX %s", got, LUXAssetID)
	}

	// (2) L2/L3 network: its OWN native token differs from LUX, yet the fee
	// asset is STILL LUX. This is the whole point of the directive.
	localNative := constants.UTXOAssetIDFor(luxL2NetworkID)
	if localNative == LUXAssetID {
		t.Fatalf("test precondition broken: L2/L3 native %s must differ from LUX %s", localNative, LUXAssetID)
	}
	l2 := newChainVMForNetwork(t, luxL2NetworkID)
	if got := l2.FeePolicy().FeeAssetID(); got != LUXAssetID {
		t.Fatalf("L2/L3 fee asset = %s, want LUX %s (NOT local native %s)", got, LUXAssetID, localNative)
	}

	// The floor is unchanged and the policy still validates (non-zero floor).
	if got := l2.FeePolicy().MinTxFee(); got != fee.MinTxFeeFloor {
		t.Fatalf("L2/L3 MinTxFee = %d, want %d", got, fee.MinTxFeeFloor)
	}
	if err := fee.Validate(l2.FeePolicy()); err != nil {
		t.Fatalf("fee.Validate(L2/L3 policy) = %v, want nil", err)
	}
}

// TestFeeFloor_HoldsInLUX_OnL2 confirms the consensus fee-floor invariant still
// holds — in LUX terms — on an L2/L3 network. An under-floor fee is rejected with
// ErrInsufficientFee (in LUX, not the local native token), and a fee at the floor
// is admitted. The gate is not weakened by switching the denomination to LUX.
func TestFeeFloor_HoldsInLUX_OnL2(t *testing.T) {
	l2 := newChainVMForNetwork(t, luxL2NetworkID)

	// Under-floor: GasPrice*GasLimit < MinTxFeeFloor -> rejected in LUX terms.
	under := &txs.PlaceOrderTx{BaseTx: txs.BaseTx{
		TxType:   txs.TxPlaceOrder,
		From:     ids.GenerateTestShortID(),
		Nonce:    1,
		GasPrice: 1,
		GasLimit: 1, // fee = 1 nLUX << floor
	}, PoolID: [32]byte{1}, Side: 0, Price: 1, Size: 1}
	b, err := json.Marshal(under)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := l2.SubmitTx(b); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("SubmitTx(under-floor on L2) = %v, want ErrInsufficientFee", err)
	}

	// At the floor: admitted (fee == MinTxFeeFloor, denominated in LUX).
	atFloor := &txs.PlaceOrderTx{BaseTx: txs.BaseTx{
		TxType:   txs.TxPlaceOrder,
		From:     ids.GenerateTestShortID(),
		Nonce:    2,
		GasPrice: 1_000,
		GasLimit: 1_000, // fee = 1_000_000 nLUX == floor
	}, PoolID: [32]byte{1}, Side: 0, Price: 1, Size: 1}
	b2, err := json.Marshal(atFloor)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	if err := l2.SubmitTx(b2); err != nil {
		t.Fatalf("SubmitTx(at-floor on L2) = %v, want nil", err)
	}
}

// TestSwapNativeFeeToLUX_Deterministic exercises the swap-to-LUX settle path: a
// fee tendered in the local native asset is converted to LUX at a confirmed
// matcher fill price, and the LUX floor is enforced on the OUTPUT (LUX is the
// canonical sink). The conversion is deterministic — identical inputs always
// yield identical LUX — and an under-floor swap output is refused exactly like an
// under-floor LUX tender at the mempool gate.
func TestSwapNativeFeeToLUX_Deterministic(t *testing.T) {
	cvm := newChainVMForNetwork(t, luxL2NetworkID)

	// 1:1 parity — a native fee at the floor settles to exactly the floor in LUX.
	if got, err := swapNativeFeeToLUX(fee.MinTxFeeFloor, 1.0); err != nil || got != fee.MinTxFeeFloor {
		t.Fatalf("swapNativeFeeToLUX(floor, 1.0) = (%d, %v), want (%d, nil)", got, err, fee.MinTxFeeFloor)
	}

	// Determinism: the same native fee + fill price always yields the same LUX.
	const nativeFee = uint64(20_000_000)
	const price = 0.1 // LUX per native unit
	first, err := swapNativeFeeToLUX(nativeFee, price)
	if err != nil {
		t.Fatalf("swap: %v", err)
	}
	for i := 0; i < 1000; i++ {
		got, err := swapNativeFeeToLUX(nativeFee, price)
		if err != nil || got != first {
			t.Fatalf("non-deterministic swap on iter %d: got (%d,%v), want (%d,nil)", i, got, err, first)
		}
	}
	if first != 2_000_000 { // 20_000_000 * 0.1 = 2_000_000 LUX
		t.Fatalf("swap(20e6, 0.1) = %d, want 2_000_000", first)
	}

	// settleFeeInLUX enforces the LUX floor on the swapped output. 2_000_000 >= floor.
	if got, err := cvm.settleFeeInLUX(nativeFee, price); err != nil || got != 2_000_000 {
		t.Fatalf("settleFeeInLUX(20e6, 0.1) = (%d, %v), want (2_000_000, nil)", got, err)
	}

	// An under-floor swap output is refused (native fee too small for the price):
	// 1_000_000 native * 0.1 = 100_000 LUX < 1_000_000 floor.
	if _, err := cvm.settleFeeInLUX(1_000_000, 0.1); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("settleFeeInLUX(under-floor output) = %v, want ErrInsufficientFee", err)
	}

	// Proceeds round DOWN (never credit LUX the fill did not realize, floor-safe):
	// 3 native * 0.5 = 1.5 LUX -> 1 LUX.
	if got, err := swapNativeFeeToLUX(3, 0.5); err != nil || got != 1 {
		t.Fatalf("swapNativeFeeToLUX(3, 0.5) = (%d, %v), want (1, nil) [floor-safe round down]", got, err)
	}

	// Malformed fill prices are refused (no silent zero/garbage settlement).
	for _, bad := range []float64{0, -1, math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := swapNativeFeeToLUX(fee.MinTxFeeFloor, bad); err == nil {
			t.Fatalf("swapNativeFeeToLUX with invalid price %v = nil err, want refusal", bad)
		}
	}
}
