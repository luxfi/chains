// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"github.com/luxfi/chains/fee"
)

// gateUserTx admits a user-submitted Transaction iff its declared Fee
// satisfies the chain's declared floor. Called from the HTTP entry
// (handleSendTransaction) before Mempool.AddTransaction, so a zero-fee tx is
// rejected before mempool or heap pressure changes.
//
// The shielded-tx Fee field is uint64-nLUX-denominated; the implicit asset is
// the chain's primary UTXO asset (always LUX on Z-Chain).
//
// Internal callers (consensus engine replay) bypass the gate by reaching
// processGenesisTransactions or direct mempool calls.
func (vm *VM) gateUserTx(tx *Transaction) error { return vm.fee.Admit(tx.Fee) }

// FeePolicy exposes the chain's declared fee policy for diagnostics and the
// boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.fee.Policy() }
