// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"github.com/luxfi/constants"
	nodefee "github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the F-Chain ADMISSION policy: a non-zero floor so the
// chain Manager's boot-time fee.Validate never flags F as a zero-fee
// user-facing chain (see node/vms/types/fee/policy.go).
//
// This is ORTHOGONAL to SETTLEMENT. Admission (here) is a static declaration
// "this chain charges at least the floor"; settlement (github.com/luxfi/chains/
// fee, driven in block Accept) performs the actual per-operation debit + burn,
// priced by the per-scheme gas schedule (gas.go). The floor declared here is
// below MinScheduledFee(), so the two surfaces agree — proven in gas_test.go.
func newFeePolicy(networkID uint32) nodefee.Policy {
	return nodefee.FlatPolicy{
		Fee:     nodefee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
	}
}

// FeePolicy exposes the chain's declared admission policy for diagnostics and
// the boot-time Validate gate.
func (vm *VM) FeePolicy() nodefee.Policy { return vm.feePolicy }
