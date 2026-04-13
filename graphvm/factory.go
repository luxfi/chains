// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for GraphVM (G-Chain)
var VMID = ids.ID{'g', 'r', 'a', 'p', 'h', 'v', 'm'}

// Factory creates new instances of the Graph VM
type Factory struct{}

// New returns a new instance of the Graph VM
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
