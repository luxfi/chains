// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID is the unique identifier for IdentityVM (I-Chain)
var VMID = ids.ID{'i', 'd', 'e', 'n', 't', 'i', 't', 'y', 'v', 'm'}

// Factory creates new IdentityVM instances
type Factory struct{}

// New returns a new instance of the IdentityVM
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	return &VM{
		identities:    make(map[ids.ID]*Identity),
		credentials:   make(map[ids.ID]*Credential),
		issuers:       make(map[ids.ID]*Issuer),
		revocations:   make(map[ids.ID]*RevocationEntry),
		pendingCreds:  make([]*Credential, 0),
		pendingBlocks: make(map[ids.ID]*Block),
	}, nil
}
