// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package graphvm

import "github.com/luxfi/node/vms/types/fee"

// newFeePolicy returns the canonical G-Chain FeePolicy.
//
// G-Chain is read-only — the GraphQL executor explicitly rejects
// `mutation` operations (see graphql.go: "mutations not allowed:
// G-chain is read-only"). There is no user-submitted-tx mempool, so
// the only sound policy is NoUserTxPolicy{}: any path that ever tried
// to admit a user-tx is a bug.
//
// Per node/CLAUDE.md FeePolicy section: service-only chains use
// NoUserTxPolicy. Read-only chains are a subset of service-only.
func newFeePolicy() fee.Policy {
	return fee.NoUserTxPolicy{}
}

// FeePolicy exposes the chain's declared fee policy for diagnostics and
// the boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.feePolicy }
