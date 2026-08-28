// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"github.com/luxfi/chains/chain"
	"github.com/luxfi/ids"
)

// VMID is the unique identifier for ZKVM (Z-Chain)
var VMID = ids.ID{'z', 'k', 'v', 'm'}

// Factory creates Z-Chain VM instances.
type Factory = chain.Factory[VM]
