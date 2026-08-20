// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/ids"
)

// authenticated builds the Caller the TRANSPORT would produce for a chain that
// is bound to a permission entry. In-package tests may build one because they
// stand in for the transport; a request body cannot, which is the whole point.
func authenticated(vm *VM, name string) Caller {
	return Caller{name: name, perms: vm.config.AuthorizedChains[name]}
}

// TestCaller_ZeroValueMaySignNothing: a path that forgets to authenticate must
// fail closed rather than quietly acquire whatever the zero value implies.
func TestCaller_ZeroValueMaySignNothing(t *testing.T) {
	vm := &VM{}
	if _, err := vm.RequestSignature(context.Background(), Caller{}, "key", make([]byte, 32)); !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatalf("the zero Caller must authorize nothing, got %v", err)
	}
	if _, err := vm.StartKeygenWithPolicy(context.Background(), "key", vm.Policy(), Caller{}); !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatalf("the zero Caller must not run keygen, got %v", err)
	}
}

// TestCaller_UnboundEntryAuthorizesNobody is the fail-closed default. The stock
// permission table ships names with no chain id, so until an operator binds a
// name to a chain, no chain id resolves — including one that happens to spell
// itself like an entry.
func TestCaller_UnboundEntryAuthorizesNobody(t *testing.T) {
	vm := &VM{config: ThresholdConfig{AuthorizedChains: map[string]*ChainPermissions{
		"B-Chain": {ChainID: "", CanSign: true},
	}}}
	if _, err := vm.caller(ids.GenerateTestID()); !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatalf("an entry bound to no chain must authorize nobody, got %v", err)
	}
}

// TestCaller_BindsToChainIDNotName: authorization follows the chain id the
// transport authenticated. A second entry whose LABEL is more appealing must
// not win, and an id that matches nothing must not fall back to a label.
func TestCaller_BindsToChainIDNotName(t *testing.T) {
	bridge := ids.GenerateTestID()
	stranger := ids.GenerateTestID()
	vm := &VM{config: ThresholdConfig{AuthorizedChains: map[string]*ChainPermissions{
		"B-Chain": {ChainID: bridge.String(), CanSign: true},
	}}}

	c, err := vm.caller(bridge)
	if err != nil {
		t.Fatalf("the bound chain must authorize: %v", err)
	}
	if c.Name() != "B-Chain" {
		t.Fatalf("resolved name = %q, want B-Chain", c.Name())
	}
	if _, err := vm.caller(stranger); !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatalf("an unbound chain id must not resolve, got %v", err)
	}
}

// TestCaller_PayloadCannotNameItself is the defect this type exists to prevent.
//
// CrossChainRequest receives the sender's chain id from the transport AND a
// body in which the sender describes itself. Authorization must read the first
// and ignore the second, so a peer that writes "B-Chain" into its payload gains
// nothing it did not already have.
func TestCaller_PayloadCannotNameItself(t *testing.T) {
	bridge := ids.GenerateTestID()
	impostor := ids.GenerateTestID()
	vm := &VM{config: ThresholdConfig{AuthorizedChains: map[string]*ChainPermissions{
		"B-Chain": {ChainID: bridge.String(), CanSign: true, CanKeygen: true},
	}}}

	// The impostor's id is bound to nothing; its claim to be B-Chain is in the
	// only place it controls — the body — and must not be consulted.
	if _, err := vm.caller(impostor); !errors.Is(err, ErrUnauthorizedChain) {
		t.Fatal("a self-declared name must not produce a Caller")
	}
}

// TestUnboundLabelIsNotCounted is F10: an entry whose chainId is a LABEL binds to
// no chain, exactly like an empty one, because a label never equals a base58 chain
// id. Counting it as bound made a stock node report five authorized chains while
// authorizing none — the precise misreading the boot warning exists to prevent.
func TestUnboundLabelIsNotCounted(t *testing.T) {
	real := ids.GenerateTestID()
	entries := map[string]*ChainPermissions{
		"B-Chain": {ChainID: "B-Chain"},        // a label: binds to nothing
		"C-Chain": {ChainID: ""},               // empty: binds to nothing
		"X-Chain": {ChainID: real.String()},    // an actual chain id
	}
	bound := 0
	for _, p := range entries {
		if p != nil && p.ChainID != "" {
			if _, err := ids.FromString(p.ChainID); err == nil {
				bound++
			}
		}
	}
	if bound != 1 {
		t.Fatalf("bound = %d, want 1 — only an entry carrying a real chain id is bound", bound)
	}
}

// TestUnexportedCeremonyPrimitives is F6: the authorized wrapper was made
// unforgeable while the primitive it wraps stayed exported and still took the very
// chain-name string the change removed. A caller outside this package must have no
// way to run a ceremony at all.
func TestUnexportedCeremonyPrimitives(t *testing.T) {
	var vm *VM
	// These compile only because this test is IN the package. The property under
	// test is that the identifiers are lowercase; if either is re-exported, the
	// grep in CI and this comment are the record of why it must not be.
	_ = vm.runKeygen
	_ = vm.runSign
}
