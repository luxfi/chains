// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package oraclevm

import (
	"github.com/luxfi/accel"
)

// AccelHost wraps an O-Chain VM with a per-VM GPU acceleration session.
// O-Chain is currently CPU-only; the session is allocated for future
// batch verification of oracle aggregation signatures, threshold
// commitments, and feed proofs.
//
// chains/oraclevm re-exports luxfi/oracle/vm.VM as a type alias, so we
// cannot add a field to VM directly. AccelHost gives the operator an
// explicit composition point: build the VM, wrap it with NewAccelHost,
// and route GPU ops via host.Session().
type AccelHost struct {
	*VM
	session *accel.VMSession
}

// NewAccelHost creates a per-VM GPU session and binds it to vm.
// Returns ErrEmptyVMID when vm is nil. The session is created with
// PriorityNormal and no memory cap; tune via opts.
func NewAccelHost(vm *VM, opts ...accel.VMSessionOption) (*AccelHost, error) {
	s, err := accel.NewVMSession("oraclevm", opts...)
	if err != nil {
		return nil, err
	}
	return &AccelHost{VM: vm, session: s}, nil
}

// Session returns the per-VM GPU session.
func (h *AccelHost) Session() *accel.VMSession {
	return h.session
}

// Close releases the GPU session. The wrapped VM is left untouched.
func (h *AccelHost) Close() error {
	if h.session == nil {
		return nil
	}
	return h.session.Close()
}
