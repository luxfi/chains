// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for AIVM (A-Chain)
var VMID = ids.ID{'a', 'i', 'v', 'm'}

// Factory implements vms.Factory interface for creating AIVM instances
type Factory struct{}

// New creates a new AIVM instance
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
