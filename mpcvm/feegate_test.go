// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"errors"
	"testing"

	"github.com/luxfi/chains/fee"
)

// M-Chain declares the closed policy: it is a committee-driven service VM and
// there is no mempool to admit anything into. The node's boot-time
// nodefee.Validate reads this declaration, and it passes for the sentinel with
// no minimum fee — which for any OTHER policy would be flagged as a zero-fee
// user-facing chain.
func TestMChainDeclaresItTakesNoUserTransactions(t *testing.T) {
	vm := newVM(t)

	policy := vm.Fee()
	if policy == nil {
		t.Fatal("Fee() = nil; a chain that declares no policy is a chain with no declared cost")
	}
	if _, ok := policy.(fee.NoUserTxPolicy); !ok {
		t.Fatalf("Fee() = %T, want NoUserTxPolicy", policy)
	}
	if err := fee.Validate(policy); err != nil {
		t.Fatalf("the node's boot gate rejects M-Chain's own declaration: %v", err)
	}
}

// Refusal does not depend on how much is offered. A policy that admitted a
// large enough payment would make "M-Chain has no user entry" a matter of
// price.
func TestNoPaymentBuysAdmission(t *testing.T) {
	vm := newVM(t)

	for _, paid := range []uint64{0, 1, 1_000_000, 1 << 62} {
		if err := vm.AdmitUserTx(paid); !errors.Is(err, fee.ErrChainAcceptsNoUserTxs) {
			t.Errorf("AdmitUserTx(%d) = %v, want ErrChainAcceptsNoUserTxs", paid, err)
		}
	}
}

// A VM that never ran Initialize holds the zero Fee, and the zero Fee admits
// nothing. That is the direction the default must fail in: a chain that forgot
// to declare a policy refuses every caller rather than admitting every caller.
func TestAnUndeclaredPolicyRefusesEveryone(t *testing.T) {
	var vm VM
	if err := vm.AdmitUserTx(0); !errors.Is(err, fee.ErrChainAcceptsNoUserTxs) {
		t.Fatalf("the zero Fee admitted a caller: %v", err)
	}
	if vm.Fee() != nil {
		t.Fatalf("the zero Fee reports a policy: %v", vm.Fee())
	}
}
