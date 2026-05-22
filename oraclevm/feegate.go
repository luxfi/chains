// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package oraclevm

// FeePolicy lives at the canonical impl in luxfi/oracle/vm. This package
// is a thin re-export shim (see oraclevm.go header); the gate is wired
// there and re-exported via the type alias `VM = oraclevm.VM`, so any
// caller that constructs a VM through this shim transitively gets the
// NoUserTxPolicy{} declared in ~/work/lux/oracle/vm/feegate.go.
//
// See:
//   - oraclevm.go: re-export shim
//   - ~/work/lux/oracle/vm/feegate.go: canonical NoUserTxPolicy
//   - ~/work/lux/node/CLAUDE.md FeePolicy section
