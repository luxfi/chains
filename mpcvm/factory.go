// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"github.com/luxfi/constants"
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

// The value is held by TestVMID_Bytes and TestVMID_IsCanonicalAndStable, which
// compare it to the literal bytes and to the CB58 the plugin binary is named
// after.
//
// It used to also carry `var _ = map[bool]struct{}{VMID == ids.ID{...}: {}}`,
// labelled a compile-time assertion. It is not one: a map literal with a
// single non-constant key compiles whatever the key evaluates to — only a
// DUPLICATE constant key is a compile error. So it held for every possible
// value of VMID, including a wrong one, while reading as proof. A check that
// cannot fail is worse than no check, because it stops anyone writing the one
// that can.
// Factory creates M-Chain VM instances.
type Factory struct{}

// New returns a new M-Chain VM. Everything that needs configuration or a
// database is set up in Initialize; a Factory-built VM holds no state.
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
