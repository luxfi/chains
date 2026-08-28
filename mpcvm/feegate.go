// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"github.com/luxfi/node/vms/types/fee"
)

// gateUserTx refuses every caller — M-Chain accepts no user txs. It is a
// committee-driven service VM: keygen and signing requests come from validators
// through consensus, not a user mempool. Any service entry that exposes itself
// as user-callable MUST route through this gate, so the refusal is explicit
// rather than a path nobody happened to write.
func (vm *VM) gateUserTx() error { return vm.fee.Admit(0) }

// FeePolicy exposes the chain's declared fee policy for diagnostics and the
// boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.fee.Policy() }
