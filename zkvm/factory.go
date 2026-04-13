// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for ZKVM (Z-Chain)
var VMID = ids.ID{'z', 'k', 'v', 'm'}

// Factory implements vms.Factory interface for creating Z-Chain VM instances
type Factory struct{}

// New implements vms.Factory
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
