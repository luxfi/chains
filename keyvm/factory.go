// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
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
	Config
}

// New constructs a VM. It is dependency-free (like the Q/Z core factories), so
// it can be registered either as a plugin (cmd/plugin) or, once the hardened
// chains module is the one the node pins, in-process.
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	return &VM{networkID: f.NetworkID, log: logger}, nil
}

// NewFactory builds a factory with the given configuration.
func NewFactory(cfg Config) *Factory { return &Factory{Config: cfg} }
