// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"github.com/luxfi/chains/chain"
	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
)

// VMID identifies B-Chain: cross-chain settlement.
//
// It is an immutable one-way door — the node resolves a plugin binary by this
// id, so a chain created under one value can never be served by a binary
// answering to another. It is therefore taken from luxfi/constants and nowhere
// else; a private literal beside the shared one is two declarations of a value
// that must be one.
var VMID = constants.BridgeVMID

// The bytes, asserted at compile time so a change to either declaration is a
// build failure rather than a chain nothing can open.
var _ = map[bool]struct{}{VMID == ids.ID{'b', 'r', 'i', 'd', 'g', 'e', 'v', 'm'}: {}}

// Factory creates B-Chain VM instances.
type Factory = chain.Factory[VM]
