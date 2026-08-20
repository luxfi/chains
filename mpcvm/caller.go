// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"fmt"

	"github.com/luxfi/ids"
)

// Caller is a chain whose identity the TRANSPORT authenticated.
//
// It cannot be built from a request body. The only constructor takes the chain
// id the transport supplies, so "who is asking" is never a field the asker
// writes about itself. A name in a payload is a claim, and a claim its own
// subject authored proves nothing — the same reason a node's ownership
// attestation is read out of M-Chain consensus state and not out of the node's
// own config, where its operator could write whatever it liked.
//
// The zero Caller holds no permissions and can do nothing, so a path that
// forgets to authenticate fails closed rather than silently acquiring rights.
type Caller struct {
	name  string
	perms *ChainPermissions
}

// Name is the operator's label for the authenticated chain, used for
// attribution and quota accounting. It is an OUTPUT of authentication, never an
// input to it.
func (c Caller) Name() string { return c.name }

// caller resolves the permissions of the chain the transport authenticated as
// sender.
//
// Authorization binds to the chain ID, never to a name. A name is an operator's
// label — convenient in a config file, and worth exactly nothing as evidence,
// because anyone can spell it. A chain id is the identity consensus itself
// uses.
//
// A permission entry carrying no ChainID is bound to no chain and therefore
// authorizes nobody. That is deliberate: custody is granted to a specific
// chain by an operator who names it, and an entry that matched on its label
// alone would hand custody to whoever typed the label. An unbound entry refuses
// and says so, because "this chain may not sign" and "this deployment never
// bound the chain" are different operational problems.
func (vm *VM) caller(sender ids.ID) (Caller, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	for name, p := range vm.config.AuthorizedChains {
		if p == nil || p.ChainID == "" {
			continue
		}
		if p.ChainID == sender.String() {
			return Caller{name: name, perms: p}, nil
		}
	}
	return Caller{}, fmt.Errorf("%w: no permission entry is bound to chain %s", ErrUnauthorizedChain, sender)
}
