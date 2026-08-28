// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"github.com/luxfi/chains/chain"
	"github.com/luxfi/ids"
)

// VMID is the unique identifier for BridgeVM (B-Chain)
var VMID = ids.ID{'b', 'r', 'i', 'd', 'g', 'e', 'v', 'm'}

// Factory creates B-Chain VM instances.
type Factory = chain.Factory[VM]
