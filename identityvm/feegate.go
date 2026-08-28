// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"github.com/luxfi/node/vms/types/fee"
)

// gateUserFee refuses paidFee below the chain's declared floor. Called from
// each mutating service RPC (CreateIdentity, IssueCredential,
// RevokeCredential, CreateProof, RegisterIssuer) before the state-modifying VM
// method runs.
//
// Read-only RPCs (GetIdentity, GetCredential, VerifyCredential, GetIssuer,
// ListIssuers, ResolveIdentity, Health) are not gated.
func (vm *VM) gateUserFee(paidFee uint64) error { return vm.fee.Admit(paidFee) }

// FeePolicy exposes the chain's declared fee policy for diagnostics and the
// boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.fee.Policy() }
