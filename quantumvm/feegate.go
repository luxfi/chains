// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"fmt"

	"github.com/luxfi/ids"
	"github.com/luxfi/node/vms/types/fee"
)

// Per LP-0130 §6, Q-Chain has NO user-payable blockspace: finality-cert
// inclusion is a validator obligation paid via P-Chain reward distribution,
// never a user fee. A fee market on Q would make finality hostage to
// blockspace pricing (the exact failure mode LP-0130 §6 eliminates), so the
// policy is the explicit committee-only sentinel.

// IssueTx is the user-tx admission point on Q-Chain, and it admits nothing.
// Under NoUserTxPolicy every amount is refused (LP-0130 §6), so there is no
// path from here into the pool — Q-Chain state advances only through
// consensus-internal cert aggregation, which reaches txPool.AddTransaction
// directly and never passes this way.
func (vm *VM) IssueTx(tx Transaction) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("quantumvm: fee policy not initialized")
	}
	return vm.feePolicy.ValidateFee(tx.Fee(), ids.Empty)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
