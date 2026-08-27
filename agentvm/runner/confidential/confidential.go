// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package confidential obtains a hardware attestation quote for a run.
//
// It is an Attestor and not a Runner, and the split is the point. A quote is
// produced by the platform, over a value the caller hands it, and the process
// that asked for the quote has no way to influence what the hardware puts in
// it. A component that both ran the code and authored the statement about how
// it ran would be its own witness.
//
// What this package does is small on purpose: ask the device for a quote over
// the run's claim, check that the quote came back bound to that claim, and put
// it in the evidence. It does not verify the signature. Verification needs the
// set of attesting keys the chain has admitted, which lives in engine state and
// is read on the verifying side (see agentvm.Quote.Verify); an operator holding
// its own copy of that check could only ever refuse quotes the chain would
// accept, or accept quotes the chain would refuse.
package confidential

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

var (
	// ErrDevice means no attestation device was supplied.
	ErrDevice = errors.New("agentvm/runner/confidential: no attestation device")
	// ErrBinding means the device returned a quote produced for something
	// other than the run being attested.
	ErrBinding = errors.New("agentvm/runner/confidential: quote is not bound to this run")
)

// Device is a source of hardware attestation quotes. Quote takes the value the
// report must be bound to and returns a report the hardware produced over it.
type Device interface {
	// Kind is the report layout this device produces.
	Kind() agentvm.QuoteKind
	// Quote asks the hardware for a report bound to this value.
	Quote(binding common.Hash) (agentvm.Quote, error)
}

// Attestor fills a run's evidence with a hardware quote.
type Attestor struct {
	dev Device
}

var _ runner.Attestor = (*Attestor)(nil)

// New builds an attestor over a device. There is no default device: an
// attestor without one could only produce evidence that proves nothing, so it
// is refused here rather than at the first run.
func New(dev Device) (*Attestor, error) {
	if dev == nil {
		return nil, ErrDevice
	}
	return &Attestor{dev: dev}, nil
}

// Grants is what a hardware quote establishes: the memory was encrypted against
// the host, and the statement is signed by hardware rather than by an operator.
func (a *Attestor) Grants() agentvm.Properties {
	return agentvm.Require(agentvm.MemoryEncrypted, agentvm.AttestHardware)
}

// Attest asks the device for a quote over the run's claim and returns the
// evidence carrying it.
//
// The quote is checked against the claim before it is accepted. A device that
// answers with a report bound to a different value has attested to a different
// run, and putting that in the evidence would produce a claim the chain refuses
// at verification with no way to tell why. It is read the same way the chain
// reads it, out of the report bytes at the vendor's own offset, so the check
// here and the check on chain are the same question asked of the same bytes.
func (a *Attestor) Attest(ctx context.Context, claim common.Hash, out agentvm.Handle, r runner.Result, in agentvm.Evidence) (agentvm.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return in, err
	}
	if a.dev == nil {
		return in, ErrDevice
	}
	q, err := a.dev.Quote(claim)
	if err != nil {
		return in, err
	}
	if got := q.Binding(); got != claim {
		return in, fmt.Errorf("%w: report binds %s, run claims %s", ErrBinding, got, claim)
	}
	in.Quote = q
	return in, nil
}
