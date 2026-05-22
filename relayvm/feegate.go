// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package relayvm

// FeePolicy lives at the canonical impl in luxfi/relay/vm. This package
// is a thin re-export shim (see relayvm.go header); the gate is wired
// there and re-exported via the type alias `VM = relayvm.VM`, so any
// caller that constructs a VM through this shim transitively gets the
// NoUserTxPolicy{} declared in ~/work/lux/relay/vm/feegate.go.
//
// See:
//   - relayvm.go: re-export shim
//   - ~/work/lux/relay/vm/feegate.go: canonical NoUserTxPolicy
//   - ~/work/lux/node/CLAUDE.md FeePolicy section
