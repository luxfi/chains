// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"fmt"

	"github.com/luxfi/constants"
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical Q-Chain FeePolicy. Q-Chain accepts
// user-submitted txs that exercise the quantum signing pipeline, so it
// MUST charge a non-zero floor; see vms/types/fee/policy.go.
func newFeePolicy(networkID uint32) fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
	}
}

// gateUserTx admits a tx iff its declared Fee satisfies the configured
// FeePolicy. Called from VM.IssueTx (the canonical user-mempool entry).
// Internal callers (consensus engine replay) reach txPool.AddTransaction
// directly and bypass the gate.
func (vm *VM) gateUserTx(tx Transaction) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("quantumvm: fee policy not initialized")
	}
	asset := constants.UTXOAssetIDFor(vm.NetworkID)
	return vm.feePolicy.ValidateFee(tx.Fee(), asset)
}

// IssueTx is the canonical user-tx admission point on Q-Chain. The
// FeePolicy gate refuses zero-fee txs before they touch the pool.
func (vm *VM) IssueTx(tx Transaction) error {
	if err := vm.gateUserTx(tx); err != nil {
		return err
	}
	return vm.txPool.AddTransaction(tx)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
