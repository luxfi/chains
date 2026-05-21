// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"fmt"

	"github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/constants"
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical A-Chain FeePolicy. A-Chain accepts
// user-submitted inference tasks (HTTP /tasks -> VM.SubmitTask) so it
// MUST charge a non-zero floor; see vms/types/fee/policy.go.
func newFeePolicy(networkID uint32) fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
	}
}

// gateUserTask refuses tasks whose declared Fee does not satisfy the
// configured FeePolicy. Called from SubmitTask (and the HTTP entry
// /tasks) before the task is enqueued.
//
// The Task.Fee field is uint64-nLUX-denominated; the implicit asset is
// the chain's primary UTXO asset (LUX).
func (vm *VM) gateUserTask(task *aivm.Task) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("aivm: fee policy not initialized")
	}
	asset := constants.UTXOAssetIDFor(vm.networkID)
	return vm.feePolicy.ValidateFee(task.Fee, asset)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
