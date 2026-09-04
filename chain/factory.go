// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"github.com/luxfi/log"
	"github.com/luxfi/vm/manager"
)

// Factory builds one chain's VM. The zero VM is the whole of it: a VM gets its
// database, its configuration and its caches in Initialize, and nothing else
// may hand it state — a factory that half-populates a VM leaves two places
// that decide what a fresh VM holds, and they drift.
type Factory[T any] struct{}

var _ manager.Factory = Factory[struct{}]{}

// New returns a VM with nothing set. Initialize does the rest.
func (Factory[T]) New(log.Logger) (interface{}, error) { return new(T), nil }
