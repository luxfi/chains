// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"fmt"

	"github.com/luxfi/constants"
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical B-Chain FeePolicy. B-Chain accepts
// user-submitted bridge transfers (InitiateBridgeTransfer) that drive
// MPC signing capacity, so it MUST charge a non-zero floor; see
// vms/types/fee/policy.go.
func newFeePolicy(networkID uint32) fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
	}
}

// gateUserBridgeMessage refuses messages whose declared Fee does not
// satisfy the configured FeePolicy. Called from InitiateBridgeTransfer
// before any MPC signing capacity is consumed.
//
// Internal callers (consensus engine replay) bypass the gate by
// reaching pendingBridges/bridgeSigner directly.
func (vm *VM) gateUserBridgeMessage(message *BridgeMessage) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("bridgevm: fee policy not initialized")
	}
	asset := constants.UTXOAssetIDFor(vm.networkID)
	return vm.feePolicy.ValidateFee(message.Fee, asset)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
