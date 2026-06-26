// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"encoding/json"
	"fmt"

	"github.com/luxfi/chains/dexvm/txs"
	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/node/vms/types/fee"
)

// LUXAssetID is the canonical L0 settlement asset: the brand-neutral LUX UTXO
// asset literal (constants.UTXO_ASSET_ID). It is NETWORK-INDEPENDENT by design —
// every chain that runs the D-Chain DEX, including an L2/L3 with its own native
// currency on top of LUX, denominates DEX fees in this ONE asset, so DEX fees
// always settle to LUX regardless of the local native token.
//
// The D-Chain is UTXO-based, so the canonical UTXO asset id is the correct
// reference (an EVM-context DEX would settle in the EVM-native LUX instead).
// This is deliberately the ONE canonical literal — NOT UTXOAssetIDFor(localID)
// (the local chain's own token) nor the per-network function pinned to mainnet.
var LUXAssetID ids.ID = constants.UTXO_ASSET_ID

// newFeePolicy returns the canonical D-Chain FeePolicy: a FlatPolicy at
// MinTxFeeFloor (1 mLUX = 1_000_000 nLUX) denominated in canonical LUX. D-Chain
// is user-tx-accepting so it MUST charge a non-zero floor — see
// vms/types/fee/policy.go.
//
// The fee asset is LUX for EVERY network (the L0 settlement token), never the
// local network's native UTXO asset: an L2/L3 building on LUX pays DEX fees that
// settle to LUX. The policy is therefore network-independent — it takes no
// networkID, which is exactly the property "LUX is the lowest-level currency"
// encodes.
func newFeePolicy() fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: LUXAssetID,
	}
}

// txFee returns the LUX-denominated fee a DEX BaseTx pays.
// In dexvm the per-tx burn is GasPrice * GasLimit; both fields live on
// BaseTx so every concrete Tx (PlaceOrderTx, SwapTx, ...) inherits them.
func txFee(base txs.BaseTx) uint64 {
	// Saturating multiply — overflow means "definitely above any floor".
	hi, lo := mul64Overflow(base.GasPrice, base.GasLimit)
	if hi != 0 {
		return ^uint64(0)
	}
	return lo
}

// mul64Overflow returns hi:lo = a*b. Hot-path constant-time integer mul,
// no allocations, no branches on values.
func mul64Overflow(a, b uint64) (hi, lo uint64) {
	const mask = uint64(0xffffffff)
	a0, a1 := a&mask, a>>32
	b0, b1 := b&mask, b>>32
	w0 := a0 * b0
	t := a1*b0 + (w0 >> 32)
	w1 := t & mask
	w2 := t >> 32
	w1 += a0 * b1
	hi = a1*b1 + w2 + (w1 >> 32)
	lo = a * b
	return
}

// gateUserTxBytes admits a raw user-tx blob iff it parses to a BaseTx
// whose declared fee satisfies the configured FeePolicy. Called from
// SubmitTx — the single user-mempool entry on D-Chain.
//
// Internal callers (consensus engine -> VM, replay path) bypass this
// gate by feeding pendingTxs directly; the gate only fires on the
// public bytes-in interface.
func (cvm *ChainVM) gateUserTxBytes(b []byte) error {
	if cvm.feePolicy == nil {
		return fmt.Errorf("dexvm: fee policy not initialized")
	}
	var base txs.BaseTx
	if err := json.Unmarshal(b, &base); err != nil {
		return fmt.Errorf("dexvm: tx decode: %w", err)
	}
	// Fees are denominated in canonical LUX, NOT the local network's native
	// asset — the floor is enforced in LUX so every chain settles DEX fees to
	// the L0 token. Deterministic: a pure integer + asset-id compare against a
	// compile-time constant, identical on every validator and on every network.
	return cvm.feePolicy.ValidateFee(txFee(base), LUXAssetID)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics and
// the boot-time Validate gate.
func (cvm *ChainVM) FeePolicy() fee.Policy { return cvm.feePolicy }

// swapNativeFeeToLUX converts a fee TENDERED in a non-LUX native asset into its
// canonical-LUX settlement amount, swapping native -> LUX at a CONFIRMED matcher
// fill price (the proxy's own swap path — eat-your-own-dogfood). luxPerNative is
// the Fill.Price of a confirmed native->LUX fill (LUX quote per native base); it
// is a consensus-agreed receipt, so every validator computes the identical LUX
// amount from identical inputs — deterministic settlement.
//
// The LUX output is the asset the fee sink RECEIVES, so it rounds DOWN via
// quantToCredit — the SAME asymmetric proceeds rounding settleFromFills uses for
// every credited leg (never credit a LUX unit the fill did not realize; the
// proxy never mints LUX). Rounding DOWN is also the floor-SAFE direction: a
// caller's floor check can never be passed by rounding error, only failed by it.
// A non-finite or non-positive price is a malformed fill and is refused.
func swapNativeFeeToLUX(nativeFee uint64, luxPerNative float64) (uint64, error) {
	if !isFinitePositive(luxPerNative) {
		return 0, fmt.Errorf("dexvm: fee swap: invalid LUX/native price %v", luxPerNative)
	}
	return quantToCredit(float64(nativeFee) * luxPerNative)
}

// settleFeeInLUX sources the D-Chain tx fee in canonical LUX from a fee tendered
// in the local native asset, by swapping native -> LUX through a CONFIRMED
// matcher fill (the DEX's own swap path). LUX is the canonical sink: the returned
// amount is the LUX the fee settles to, and it MUST clear the LUX floor
// (MinTxFeeFloor) or the fee is insufficient.
//
// This is the SETTLE-time counterpart of gateUserTxBytes: the gate enforces the
// floor in LUX on a LUX-denominated tender at mempool admission (deterministic,
// no price needed); settleFeeInLUX enforces the SAME floor in LUX on the swapped
// output for a native tender at block execution (deterministic against the
// confirmed fill). The floor therefore holds whether the fee is paid in LUX
// directly or swapped from a native token — it cannot be bypassed by tendering
// native.
func (cvm *ChainVM) settleFeeInLUX(nativeFee uint64, luxPerNative float64) (uint64, error) {
	if cvm.feePolicy == nil {
		return 0, fmt.Errorf("dexvm: fee policy not initialized")
	}
	luxOut, err := swapNativeFeeToLUX(nativeFee, luxPerNative)
	if err != nil {
		return 0, err
	}
	if err := cvm.feePolicy.ValidateFee(luxOut, LUXAssetID); err != nil {
		return 0, err
	}
	return luxOut, nil
}
