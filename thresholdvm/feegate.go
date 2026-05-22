// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical M-Chain FeePolicy. M-Chain is a
// committee-driven service VM — keygen / signing requests come from
// validators via consensus, not a user mempool — so it declares the
// NoUserTxPolicy sentinel. See vms/types/fee/policy.go.
//
// Any tx that reaches the fee gate on a NoUserTx chain is a wiring
// bug; ValidateFee returns ErrChainAcceptsNoUserTxs.
func newFeePolicy() fee.Policy {
	return fee.NoUserTxPolicy{}
}

// gateUserTx refuses every caller — M-Chain accepts no user txs.
// Any service entry that exposes itself as user-callable MUST route
// through this gate so the refusal is explicit, not implicit.
func (vm *VM) gateUserTx() error {
	if vm.feePolicy == nil {
		return fee.ErrChainAcceptsNoUserTxs
	}
	// NoUserTxPolicy.ValidateFee ignores the args and always returns
	// ErrChainAcceptsNoUserTxs.
	return vm.feePolicy.ValidateFee(0, fee.NoUserTxPolicy{}.FeeAssetID())
}

// FeePolicy exposes the chain's declared fee policy for diagnostics
// and the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
