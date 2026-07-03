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

// gateUserBridgeFee refuses a bridge transfer whose declared fee does not
// satisfy the configured FeePolicy (LP-0130 §8: B-Chain fees). Called on
// the user-tx entry before any M-Chain signing capacity is consumed.
func (vm *VM) gateUserBridgeFee(paid uint64) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("bridgevm: fee policy not initialized")
	}
	return vm.feePolicy.ValidateFee(paid, constants.UTXOAssetIDFor(vm.networkID))
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }

// mpcGroupPublicKey returns the serialized CGGMP21 custody group public key
// (established by M-Chain's dealerless keygen), or nil if keygen has not
// completed. B-Chain never holds a custody secret — only this public point.
func (vm *VM) mpcGroupPublicKey() []byte {
	if vm.mpcConfig == nil {
		return nil
	}
	pt := vm.mpcConfig.PublicPoint()
	if pt == nil {
		return nil
	}
	b, err := pt.MarshalBinary()
	if err != nil {
		return nil
	}
	return b
}
