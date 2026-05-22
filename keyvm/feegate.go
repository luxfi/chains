// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"fmt"

	"github.com/luxfi/constants"
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical K-Chain FeePolicy. K-Chain accepts
// user-submitted mutating RPCs (CreateKey, DeleteKey, Encrypt) that
// produce on-chain effects, so it MUST charge a non-zero floor; see
// vms/types/fee/policy.go.
func newFeePolicy(networkID uint32) fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
	}
}

// gateUserFee refuses paidFee < MinTxFeeFloor. Called from each
// mutating service RPC (CreateKey, DeleteKey, Encrypt) before the
// state-modifying VM method runs.
//
// Read-only RPCs (ListKeys, GetKey*) are not gated — they consume no
// chain state and produce no on-chain effects.
func (vm *VM) gateUserFee(paidFee uint64) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("keyvm: fee policy not initialized")
	}
	asset := constants.UTXOAssetIDFor(vm.networkID)
	return vm.feePolicy.ValidateFee(paidFee, asset)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
