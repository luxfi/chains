// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for RelayVM (R-Chain)
var VMID = ids.ID{'r', 'e', 'l', 'a', 'y', 'v', 'm'}

// Factory creates new RelayVM instances
type Factory struct{}

// New returns a new instance of the RelayVM
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	return &VM{
		channels:      make(map[ids.ID]*Channel),
		messages:      make(map[ids.ID]*Message),
		pendingMsgs:   make(map[ids.ID][]*Message),
		sequences:     make(map[ids.ID]uint64),
		pendingBlocks: make(map[ids.ID]*Block),
	}, nil
}
