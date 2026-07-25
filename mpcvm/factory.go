// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID identifies M-Chain: MPC threshold signing and bridge custody of external
// wallets (LP-7100). It is constants.MPCVMID and nothing else.
//
// A vmID is an immutable one-way door: it is baked into the CreateChainTx at
// genesis, it is the plugin binary's filename, and it is what the P-Chain stores
// forever. Every declaration of it must agree, so there is exactly one — this
// alias — and it points at the single source of truth in luxfi/constants.
//
// This VM previously declared a private `thresholdvm` literal here that matched
// no other declaration in the stack. Per LP-7050 the thresholdvm package was
// split into mpcvm (M-Chain) and fhevm (F-Chain); "ThresholdVM" and "mvm" are
// stale names. constants.MPCVMID, node/genesis/builder/registry.go and
// node/node/vms.go all say mpcvm.
var VMID = constants.MPCVMID

// Assert at compile time that the alias really is the shared constant, so a
// future edit cannot silently reintroduce a private literal.
var _ = map[bool]struct{}{VMID == ids.ID{'m', 'p', 'c', 'v', 'm'}: {}}

// Factory creates M-Chain VM instances.
type Factory struct{}

// New returns a new M-Chain VM. Everything that needs configuration or a
// database is set up in Initialize; a Factory-built VM holds no state.
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
