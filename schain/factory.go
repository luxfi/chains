// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package schain

import (
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var (
	// VMID is the unique identifier for the S-Chain storage VM. Derived from the
	// ASCII bytes of "schain", left-aligned and zero-padded to 32 bytes — the same
	// byte pattern dexvm uses (dexvm/factory.go:31, ids.ID{'d','e','x','v','m'}).
	VMID = ids.ID{'s', 'c', 'h', 'a', 'i', 'n'}

	_ vms.Factory = (*Factory)(nil)
)

// Factory creates new S-Chain VM instances for the chains manager.
type Factory struct{}

// New implements vms.Factory. It returns a ChainVM (which implements
// chain.ChainVM) for the chains manager to drive. Unlike dexvm, the storage VM
// allocates no GPU session — there is no latency-critical compute on its hot
// path; manifest commits are pure database writes.
func (f *Factory) New(logger log.Logger) (interface{}, error) {
	return NewChainVM(logger), nil
}
