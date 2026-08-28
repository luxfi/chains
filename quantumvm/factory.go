// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for QuantumVM (Q-Chain)
var VMID = ids.ID{'q', 'u', 'a', 'n', 't', 'u', 'm', 'v', 'm'}

// Factory implements vms.Factory interface for creating QVM instances
type Factory struct {
	config.Config
}

// New creates a new QVM instance. The config is normalised and checked once,
// in Initialize, so a VM built here and a VM built by hand start from the same
// rules.
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	return &VM{Config: f.Config, log: logger}, nil
}
