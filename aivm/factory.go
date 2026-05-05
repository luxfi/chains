// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"github.com/luxfi/accel"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for AIVM (A-Chain)
var VMID = ids.ID{'a', 'i', 'v', 'm'}

// Factory implements vms.Factory interface for creating AIVM instances
type Factory struct{}

// New creates a new AIVM instance.
// Allocates a per-VM GPU session at PriorityNormal for future batch
// attestation verification and tensor proof checks.
func (f *Factory) New(log.Logger) (interface{}, error) {
	sess, err := accel.NewVMSession("aivm", accel.WithPriority(accel.PriorityNormal))
	if err != nil {
		return nil, err
	}
	return &VM{accel: sess}, nil
}
