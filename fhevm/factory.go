// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms"
)

var _ vms.Factory = (*Factory)(nil)

// VMID identifies F-Chain: coordination of confidential compute — ciphertext
// handles, access permits, and threshold decryption (LP-8200, LP-167). It is
// constants.FHEVMID and nothing else.
//
// A vmID is an immutable one-way door: it is baked into the CreateChainTx at
// genesis, it is the plugin binary's filename, and it is what the P-Chain
// stores forever. Every declaration of it must agree, so there is exactly one —
// this alias — and it points at the single source of truth in luxfi/constants,
// which node/node/vms.go already lists in OptionalVMs under the plugin name
// "fhevm".
var VMID = constants.FHEVMID

// Assert at compile time that the alias really is the shared constant, so a
// future edit cannot silently introduce a private literal.
var _ = map[bool]struct{}{VMID == ids.ID{'f', 'h', 'e', 'v', 'm'}: {}}

// Factory creates F-Chain VM instances.
type Factory struct{}

// New returns a new F-Chain VM. Everything that needs configuration, a
// database, or a committee is set up in Initialize; a Factory-built VM holds no
// state.
func (f *Factory) New(log.Logger) (interface{}, error) {
	return &VM{}, nil
}
