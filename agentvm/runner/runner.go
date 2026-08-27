// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package runner executes workloads and attests to how they ran. Those are two
// jobs and this package keeps them apart.
//
// A Runner executes. It returns what came out, what it cost, and what the run
// observed of its own environment. It does not sign anything and it does not
// decide what its output proves.
//
// An Attestor vouches. It turns a run's observations into Evidence for specific
// properties, and it is a different authority from the runner on purpose: the
// thing that ran the code should not be the sole author of the statement that it
// ran as claimed. A hardware quote comes from the platform, not from the process
// that asked for it, which is why the confidential attestor holds a device rather
// than a runner.
//
// Selection is the chain's own predicate, applied locally: a runner serves a
// demand when the properties its mechanism grants contain the ones demanded. A
// runner that cannot is not chosen — there is nothing to fall back to, because
// nothing here is ordered. If runsc is not installed the gVisor runner is not
// constructed, so it never enters a match; it never quietly becomes runc.
package runner

import (
	"context"
	"errors"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
)

var (
	// ErrNoMechanism means no available runner grants what the demand asks. It
	// is the only outcome of an unmet demand: there is no weaker runner to try.
	ErrNoMechanism = errors.New("agentvm/runner: no available mechanism grants the demanded properties")
	// ErrUnavailable is returned by a constructor when the mechanism it drives is
	// not present or not usable on this host.
	ErrUnavailable = errors.New("agentvm/runner: mechanism unavailable on this host")
	// ErrFailed means the workload ran and did not complete.
	ErrFailed = errors.New("agentvm/runner: workload did not complete")
	// ErrOutput means the run produced no usable output.
	ErrOutput = errors.New("agentvm/runner: run produced no output")
)

// Result is what a run produced and what it observed about itself.
type Result struct {
	// Output is the bytes the workload wrote.
	Output []byte
	// Exit is the workload's exit status.
	Exit uint32
	// Consumed is what the run actually used.
	Consumed agentvm.Resource
	// Observed is the identity of whatever answered the run's syscalls, read
	// from inside the run. It is the one fact about its own isolation that a run
	// can report and a configuration cannot fake.
	Observed agentvm.Witness
	// Filter is the digest of the syscall filter the run was given.
	Filter common.Hash
	// Kernel and Root are the measurements of the guest kernel and root
	// filesystem the run booted, when it booted its own.
	Kernel common.Hash
	Root   common.Hash
}

// Runner executes a workload under one isolation mechanism, in one place.
type Runner interface {
	// Mechanism is what this runner is. Unordered; it is read against the one
	// grants table, never compared to another mechanism.
	Mechanism() agentvm.Mechanism
	// Placement is where this runner runs things.
	Placement() agentvm.Placement
	// Run executes the workload over the input bytes and returns what happened.
	Run(ctx context.Context, w agentvm.Workload, input []byte) (Result, error)
}

// Attestor turns a run into evidence for the properties it can vouch for.
type Attestor interface {
	// Grants is the set of properties this attestor can produce evidence for.
	Grants() agentvm.Properties
	// Attest builds the evidence for a completed run. claim is the run's own
	// statement about itself, fixed before any evidence exists, so a hardware
	// quote can be requested against it.
	Attest(ctx context.Context, claim common.Hash, out agentvm.Handle, r Result, in agentvm.Evidence) (agentvm.Evidence, error)
}

// Set is the runners available on this host, in the order they were offered.
type Set struct {
	runners []Runner
}

// New collects the runners available here. Constructors return ErrUnavailable
// for a mechanism this host cannot drive, and such a runner is simply absent from
// the set rather than present and lying about what it is.
func New(rs ...Runner) *Set {
	out := make([]Runner, 0, len(rs))
	for _, r := range rs {
		if r != nil {
			out = append(out, r)
		}
	}
	return &Set{runners: out}
}

// Mechanisms is what this host can run — what an operator advertises.
func (s *Set) Mechanisms() agentvm.Mechanisms {
	ms := make([]agentvm.Mechanism, 0, len(s.runners))
	for _, r := range s.runners {
		ms = append(ms, r.Mechanism())
	}
	return agentvm.Offer(ms...)
}

// For returns the runner that serves this workload, by the chain's own
// predicate: the properties its mechanism grants must contain every execution
// property the workload demands, and its placement must be one the workload
// admits. Storage properties are not a runner's to grant and are not consulted
// here.
//
// The first runner that serves is returned, so a host offering several gets a
// stable answer. When none serves, that is the answer — no runner is returned
// with a note that it is close.
func (s *Set) For(w agentvm.Workload) (Runner, error) {
	demand := w.Demand &^ agentvm.Storage
	for _, r := range s.runners {
		if !w.Placement.Admits(r.Placement()) {
			continue
		}
		if r.Mechanism().Satisfies(demand) {
			return r, nil
		}
	}
	return nil, ErrNoMechanism
}
