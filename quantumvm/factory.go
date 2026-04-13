// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
	"github.com/luxfi/chains/quantumvm/config"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for QuantumVM (Q-Chain)
var VMID = ids.ID{'q', 'u', 'a', 'n', 't', 'u', 'm', 'v', 'm'}

// Factory implements vms.Factory interface for creating QVM instances
type Factory struct {
	config.Config
}

// New creates a new QVM instance
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	// Validate configuration
	if err := f.Config.Validate(); err != nil {
		return nil, err
	}

	// Create and return new QVM instance
	vm := &VM{
		Config: f.Config,
		log:    logger,
	}

	return vm, nil
}
