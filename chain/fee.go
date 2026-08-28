// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	nodefee "github.com/luxfi/node/vms/types/fee"
)

// Fee is what a chain charges to admit a user transaction, and the check that
// refuses one paying less.
//
// It is a DECLARATION at the boundary, orthogonal to settlement: this says
// what the chain costs to submit to, while the actual per-operation debit and
// burn happen inside consensus against the payer's on-chain balance
// (github.com/luxfi/chains/fee). A chain declares one of these at Initialize;
// the node's boot-time nodefee.Validate reads it.
//
// The zero Fee admits nothing, so a chain that forgets to declare one refuses
// every caller rather than admitting every caller.
type Fee struct {
	policy nodefee.Policy
	asset  ids.ID
}

// Floor is the canonical declaration for a chain that accepts user-submitted
// work: the network's UTXO asset at the minimum transaction fee. A chain with
// a user-facing entry MUST charge at least this, or nodefee.Validate flags it
// at boot as a zero-fee user-facing chain.
func Floor(networkID uint32) Fee {
	asset := constants.UTXOAssetIDFor(networkID)
	return Fee{
		policy: nodefee.FlatPolicy{Fee: nodefee.MinTxFeeFloor, AssetID: asset},
		asset:  asset,
	}
}

// Closed is the declaration for a chain that accepts no user transactions at
// all — one driven by validators through consensus, or one that only reads.
// Every caller is refused, so an entry that exposes itself as user-callable
// still refuses explicitly instead of by omission.
func Closed() Fee {
	return Fee{policy: nodefee.NoUserTxPolicy{}, asset: nodefee.NoUserTxPolicy{}.FeeAssetID()}
}

// Admit refuses a payment the declaration does not cover. Every user-facing
// entry that produces an on-chain effect passes through here before the effect
// is reachable.
func (f Fee) Admit(paid uint64) error {
	if f.policy == nil {
		return nodefee.ErrChainAcceptsNoUserTxs
	}
	return f.policy.ValidateFee(paid, f.asset)
}

// Policy is the declaration itself, for diagnostics and the boot-time gate.
func (f Fee) Policy() nodefee.Policy { return f.policy }
