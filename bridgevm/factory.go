// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for BridgeVM (B-Chain)
var VMID = ids.ID{'b', 'r', 'i', 'd', 'g', 'e', 'v', 'm', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}

// Factory creates new BridgeVM instances
type Factory struct{}

// New returns a new instance of the BridgeVM
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	return &VM{
		pendingBlocks:  make(map[ids.ID]*Block),
		pendingBridges: make(map[ids.ID]*BridgeRequest),
		chainClients:   make(map[string]ChainClient),
	}, nil
}
