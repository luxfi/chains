// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package thresholdvm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for the shared threshold substrate VM.
// Per LP-134 / LP-7050 there is NO T-Chain and NO teleportvm: teleport IS
// bridgevm (B-Chain, LP-6000). This VM is the shared library substrate that
// M-Chain (MPC — threshold signing / bridge custody, LP-7100) and F-Chain
// (FHE — confidential compute, LP-8200) run; it is not itself a chain.
var VMID = ids.ID{'t', 'h', 'r', 'e', 's', 'h', 'o', 'l', 'd', 'v', 'm', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// Factory creates new ThresholdVM instances
type Factory struct{}

// New returns a new instance of the ThresholdVM
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{
		protocolRegistry: NewProtocolRegistry(nil), // Will be initialized properly in Initialize
	}, nil
}
