// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"github.com/luxfi/chains/chain"
	"github.com/luxfi/ids"
)

// VMID is the unique identifier for IdentityVM (I-Chain)
var VMID = ids.ID{'i', 'd', 'e', 'n', 't', 'i', 't', 'y', 'v', 'm'}

// Factory creates new IdentityVM instances.
type Factory = chain.Factory[VM]
