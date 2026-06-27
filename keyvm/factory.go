// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"github.com/luxfi/chains/keyvm/config"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the K-Chain VM identifier (matches constants.KeyVMID).
var VMID = ids.ID{'k', 'e', 'y', 'v', 'm'}

// Factory builds K-Chain VM instances. Unlike the prior design it allocates no
// GPU/accel session: an auth-only VM performs no key generation or batch
// cryptography on its hot path, so there is nothing to accelerate and one fewer
// failure mode / native dependency.
type Factory struct {
	config.Config
}

// New constructs a VM. It is dependency-free (like the Q/Z core factories), so
// it can be registered either as a plugin (cmd/plugin) or, once the hardened
// chains module is the one the node pins, in-process.
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	if f.Config.ListenPort == 0 {
		f.Config = config.DefaultConfig()
	}
	if err := f.Config.Validate(); err != nil {
		return nil, err
	}
	return &VM{Config: f.Config, log: logger}, nil
}

// NewFactory builds a factory with the given configuration.
func NewFactory(cfg config.Config) *Factory { return &Factory{Config: cfg} }

// NewDefaultFactory builds a factory with default configuration.
func NewDefaultFactory() *Factory { return &Factory{Config: config.DefaultConfig()} }
