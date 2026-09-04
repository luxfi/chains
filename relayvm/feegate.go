// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

// FeePolicy lives at the canonical impl in luxfi/relay/vm. This package
// is a thin re-export shim (see relayvm.go header); the gate is wired
// there and re-exported via the type alias `VM = relayvm.VM`, so any
// caller that constructs a VM through this shim transitively gets the
// NoUserTxPolicy{} declared in ~/work/lux/relay/vm/feegate.go.
//
// The policy value this shim hands back is the one luxfi/relay constructs, and
// luxfi/relay v1.1.1 still builds it from the node's fee package. So the test
// beside this file asserts against that package and not against
// github.com/luxfi/chains/fee: the two declare the same shape under the same
// name, but they are different types, and a test may only claim the type the
// value actually has. R-Chain reaches a node-free closure when luxfi/relay
// programs against the chains fee surface; nothing in this repo can move it.
//
// See:
//   - relayvm.go: re-export shim
//   - luxfi/relay/vm: canonical NoUserTxPolicy
