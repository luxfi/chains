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

// newFeePolicy returns the canonical D-Chain FeePolicy: a FlatPolicy at
// MinTxFeeFloor (1 mLUX = 1_000_000 nLUX) denominated in the network's
// primary UTXO asset. D-Chain is user-tx-accepting so it MUST charge a
// non-zero floor — see vms/types/fee/policy.go.
func newFeePolicy(networkID uint32) fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
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
	asset := constants.UTXOAssetIDFor(cvm.networkID)
	return cvm.feePolicy.ValidateFee(txFee(base), asset)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics and
// the boot-time Validate gate.
func (cvm *ChainVM) FeePolicy() fee.Policy { return cvm.feePolicy }

// ensure ids is used (imported for clarity; gate currently uses constants
// + fee directly).
var _ ids.ID
