// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package oraclevm

import (
	"errors"
	"testing"

	"github.com/luxfi/accel"
	"github.com/luxfi/log"
)

// A host built around nothing defers its failure to whichever method the
// operator calls first, arbitrarily far from the mistake. NewAccelHost refuses
// at the point the mistake is made.
func TestNoVMIsRefusedAtConstruction(t *testing.T) {
	h, err := NewAccelHost(nil)
	if !errors.Is(err, ErrNilVM) {
		t.Fatalf("NewAccelHost(nil) error = %v, want ErrNilVM", err)
	}
	if h != nil {
		t.Fatalf("NewAccelHost(nil) returned a host (%p) alongside its refusal", h)
	}
}

// The host wraps the VM it was given and holds a session for it. The embedded
// *VM is the promoted field every method of the VM reaches through, so a host
// that dropped it would answer for a different VM than the operator built.
func TestTheHostHoldsTheVMItWasGiven(t *testing.T) {
	vm := newVM(t)

	h, err := NewAccelHost(vm)
	if err != nil {
		t.Fatalf("NewAccelHost: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	if h.VM != vm {
		t.Fatalf("host wraps %p, want the VM it was given, %p", h.VM, vm)
	}
	if h.Session() == nil {
		t.Fatal("Session() = nil; the host exists to carry one")
	}
	// The session is named for the chain, so per-VM GPU accounting attributes
	// its work to O-Chain and not to whichever VM allocated first.
	if got := h.Session().ID(); got != "oraclevm" {
		t.Errorf("session id = %q, want %q", got, "oraclevm")
	}
}

// Options reach the session. Without this, NewAccelHost's variadic parameter
// could be dropped on the floor and every caller would silently get the
// documented default instead of what it asked for.
func TestOptionsReachTheSession(t *testing.T) {
	h, err := NewAccelHost(newVM(t), accel.WithPriority(accel.PriorityHigh))
	if err != nil {
		t.Fatalf("NewAccelHost: %v", err)
	}
	t.Cleanup(func() { _ = h.Close() })

	if got := h.Session().Priority(); got != accel.PriorityHigh {
		t.Errorf("session priority = %v, want %v", got, accel.PriorityHigh)
	}

	// And the documented default when nothing is asked for.
	d, err := NewAccelHost(newVM(t))
	if err != nil {
		t.Fatalf("NewAccelHost: %v", err)
	}
	t.Cleanup(func() { _ = d.Close() })

	if got := d.Session().Priority(); got != accel.PriorityNormal {
		t.Errorf("default session priority = %v, want %v", got, accel.PriorityNormal)
	}
}

// Close releases the session and leaves the VM alone: the host owns the GPU
// session, not the chain.
func TestCloseReleasesTheSessionAndNotTheVM(t *testing.T) {
	vm := newVM(t)

	h, err := NewAccelHost(vm)
	if err != nil {
		t.Fatalf("NewAccelHost: %v", err)
	}
	if err := h.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !h.Session().IsClosed() {
		t.Fatal("Close returned nil but the session is still open")
	}
	if h.VM != vm {
		t.Fatal("Close dropped the wrapped VM")
	}
}

// A host with no session — the zero value, reachable through composite literal
// construction — closes without dereferencing it. Nothing to release is not an
// error.
func TestClosingAHostWithNoSessionIsNotAnError(t *testing.T) {
	var h AccelHost
	if err := h.Close(); err != nil {
		t.Fatalf("Close() on a host with no session = %v, want nil", err)
	}
	if h.Session() != nil {
		t.Fatal("Session() on a host with no session returned one")
	}
}

// newVM builds an O-Chain VM through the Factory the node uses.
func newVM(t *testing.T) *VM {
	t.Helper()

	raw, err := (&Factory{}).New(log.Root())
	if err != nil {
		t.Fatalf("Factory.New: %v", err)
	}
	return raw.(*VM)
}
