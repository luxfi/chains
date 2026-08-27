// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package attest turns a run's observations into signed evidence.
//
// It proves one property, attest.software, and what that property is worth is
// stated plainly in agentvm/evidence.go: below hardware attestation no
// signature proves isolation to a remote party. What a signature does is make
// the statement attributable. An operator that says its run was mediated by a
// sentry has said so under a key that recovers to a bonded identity, and when
// two independently selected operators disagree the chain knows exactly whose
// bond to take.
//
// The signature is therefore the last thing that happens. It covers every other
// evidence field through Evidence.Attestation, so a field written afterwards is
// a field the signature does not cover, and the chain would recover a different
// address than the one that signed.
package attest

import (
	"context"
	"errors"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

var (
	// ErrKey means the attestor holds no signing key.
	ErrKey = errors.New("agentvm/runner/attest: no signing key")
	// ErrPlacement means the attestor was given a placement this build does
	// not know.
	ErrPlacement = errors.New("agentvm/runner/attest: unknown placement")
)

// Attestor signs a run's observations under an operator's key.
type Attestor struct {
	key   agentvm.Signer
	place agentvm.Placement
}

var _ runner.Attestor = (*Attestor)(nil)

// New builds an attestor over an operator's key, for runs that happened in one
// place. Placement is the attestor's rather than the run's because it is a fact
// about the operator: a runner reports what answered its syscalls, and where
// the machine was is something only the operator can say.
func New(key agentvm.Signer, placement agentvm.Placement) *Attestor {
	return &Attestor{key: key, place: placement}
}

// Grants is the one property a signature establishes: the statement is
// attributable to whoever holds the key.
func (a *Attestor) Grants() agentvm.Properties {
	return agentvm.Require(agentvm.AttestSoftware)
}

// Attest copies what the run observed into the evidence and signs the result.
//
// The witness, the filter digest and the two boot measurements come from the
// run and are not the attestor's to choose; the placement is the operator's own
// statement. Signing is last because Evidence.Attestation covers all of them.
func (a *Attestor) Attest(ctx context.Context, claim common.Hash, out agentvm.Handle, r runner.Result, in agentvm.Evidence) (agentvm.Evidence, error) {
	if err := ctx.Err(); err != nil {
		return in, err
	}
	if a.key == nil {
		return in, ErrKey
	}
	if !a.place.Known() {
		return in, ErrPlacement
	}
	in.Witness = r.Observed
	in.Filter = r.Filter
	in.Kernel = r.Kernel
	in.Root = r.Root
	in.Placement = a.place
	if err := in.Sign(claim, out, a.key); err != nil {
		return in, err
	}
	return in, nil
}
