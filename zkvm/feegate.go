// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"fmt"

	"github.com/luxfi/constants"
	"github.com/luxfi/node/vms/types/fee"
)

// newFeePolicy returns the canonical Z-Chain FeePolicy. Z-Chain accepts
// user-submitted shielded txs (handleSendTransaction -> Mempool.Add)
// so it MUST charge a non-zero floor; see vms/types/fee/policy.go.
func newFeePolicy(networkID uint32) fee.Policy {
	return fee.FlatPolicy{
		Fee:     fee.MinTxFeeFloor,
		AssetID: constants.UTXOAssetIDFor(networkID),
	}
}

// gateUserTx admits a user-submitted Transaction iff its declared Fee
// satisfies the configured FeePolicy. Called from the HTTP entry
// (handleSendTransaction) before Mempool.AddTransaction so a zero-fee
// tx is rejected before mempool/heap pressure changes.
//
// The shielded-tx Fee field is uint64-nLUX-denominated; the implicit
// asset is the chain's primary UTXO asset (always LUX on Z-Chain).
//
// Internal callers (consensus engine replay) bypass the gate by
// reaching processGenesisTransactions / direct mempool calls.
func (vm *VM) gateUserTx(tx *Transaction) error {
	if vm.feePolicy == nil {
		return fmt.Errorf("zkvm: fee policy not initialized")
	}
	asset := constants.UTXOAssetIDFor(vm.networkID)
	return vm.feePolicy.ValidateFee(tx.Fee, asset)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics and
// the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
