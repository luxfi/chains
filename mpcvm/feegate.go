// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"github.com/luxfi/chains/fee"
)

// Fee is what M-Chain charges to admit a user transaction, which is nothing,
// because it admits none: it is a committee-driven service VM, and keygen and
// signing requests reach it from validators through consensus rather than from
// a mempool. Initialize pins the closed sentinel and the node's boot-time
// nodefee.Validate reads it back through here.
//
// There was also a gateUserTx() wrapper, described as the gate every
// user-callable entry MUST route through. Nothing routed through it, because
// M-Chain has no user-callable entry — a refusal nobody can reach is a
// statement, and this is where the statement belongs.
func (vm *VM) Fee() fee.Policy { return vm.fee.Policy() }

// AdmitUserTx is the refusal itself, so "M-Chain takes no user transactions"
// is a value that can be exercised rather than a comment.
func (vm *VM) AdmitUserTx(paid uint64) error { return vm.fee.Admit(paid) }
