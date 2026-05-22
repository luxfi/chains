// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"fmt"

	"github.com/luxfi/constants"
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical I-Chain FeePolicy. I-Chain accepts
// user-submitted DID + credential RPCs that produce on-chain effects,
// so it MUST charge a non-zero floor; see vms/types/fee/policy.go.
func newFeePolicy(networkID uint32) fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
	}
}

// gateUserFee refuses paidFee below MinTxFeeFloor. Called from each
// mutating service RPC (CreateIdentity, IssueCredential,
// RevokeCredential, CreateProof, RegisterIssuer) before the
// state-modifying VM method runs.
//
// Read-only RPCs (GetIdentity, GetCredential, VerifyCredential,
// GetIssuer, ListIssuers, ResolveIdentity, Health) are not gated.
func (vm *VM) gateUserFee(paidFee uint64) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("identityvm: fee policy not initialized")
	}
	asset := constants.UTXOAssetIDFor(vm.networkID)
	return vm.feePolicy.ValidateFee(paidFee, asset)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
