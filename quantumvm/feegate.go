// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical Q-Chain FeePolicy. Per LP-0130 §6,
// Q-Chain has NO user-payable blockspace: finality-cert inclusion is a
// validator obligation paid via P-Chain reward distribution, never a
// user fee. A fee market on Q would make finality hostage to blockspace
// pricing (the exact failure mode LP-0130 §6 eliminates), so the policy
// is the explicit committee-only sentinel.
func newFeePolicy(uint32) fee.Policy {
	return fee.NoUserTxPolicy{}
}

// gateUserTx refuses every user-submitted tx: Q-Chain state advances
// only through consensus-internal cert aggregation, which reaches
// txPool.AddTransaction directly and bypasses this gate.
func (vm *VM) gateUserTx(tx Transaction) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("quantumvm: fee policy not initialized")
	}
	return vm.feePolicy.ValidateFee(tx.Fee(), ids.Empty)
}

// IssueTx is the user-tx admission point on Q-Chain. Under
// NoUserTxPolicy it structurally refuses all user txs (LP-0130 §6).
func (vm *VM) IssueTx(tx Transaction) error {
	if err := vm.gateUserTx(tx); err != nil {
		return err
	}
	return vm.txPool.AddTransaction(tx)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
