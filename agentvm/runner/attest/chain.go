// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package attest

// chain.go composes attestors. A confidential run needs two statements: the
// hardware's, which is a quote, and the operator's, which is a signature over
// everything including that quote. They come from different authorities, so
// they are different attestors, and composing them is how one run carries both.
//
// Order is not a preference here. Evidence.Attestation covers every field
// except the signature, so an attestor that writes a field after another has
// signed leaves a signature over facts that are no longer the facts. The signing
// attestor goes LAST, and a chain that puts it anywhere else fails at the run
// rather than at verification, where the only symptom would be an address that
// recovers to nobody.

import (
	"context"
	"errors"
	"fmt"

	"github.com/luxfi/geth/common"

	"github.com/luxfi/chains/agentvm"
	"github.com/luxfi/chains/agentvm/runner"
)

// ErrOrder means an attestor changed evidence that an earlier attestor had
// already signed.
var ErrOrder = errors.New("agentvm/runner/attest: evidence changed after it was signed")

// chain is several attestors applied in order, each over the last one's
// evidence.
type chain []runner.Attestor

var _ runner.Attestor = chain(nil)

// Chain composes attestors, applied left to right. The signing attestor belongs
// last: it is the only one whose output covers what the others wrote.
//
// A nil attestor is absent rather than an error, which is how runner.New treats
// a runner: a device this host does not have produces no attestor, and the
// composition is what is left.
//
// Composing cannot fail, so Chain returns no error. The ordering mistake is
// caught where it can be observed — during Attest, by reading what the evidence
// actually says before and after each step.
func Chain(as ...runner.Attestor) runner.Attestor {
	out := make(chain, 0, len(as))
	for _, a := range as {
		if a != nil {
			out = append(out, a)
		}
	}
	return out
}

// Grants is everything the composed attestors can vouch for between them.
func (c chain) Grants() agentvm.Properties {
	var g agentvm.Properties
	for _, a := range c {
		g |= a.Grants()
	}
	return g
}

// Attest applies each attestor in turn.
//
// After every step that follows a signature, the evidence is re-read: the
// attestation digest covers every signed fact, so a digest that moved means the
// step wrote one of them, and the signature standing above it no longer says
// what it appears to say. Writing the SIGNATURE does not move the digest, which
// is exactly why a signing step is allowed to be one of these steps and a
// mutating step after it is not.
func (c chain) Attest(ctx context.Context, claim common.Hash, out agentvm.Handle, r runner.Result, in agentvm.Evidence) (agentvm.Evidence, error) {
	ev := in
	for i, a := range c {
		signed := len(ev.Signature) == 65
		before := ev.Attestation(claim, out)

		next, err := a.Attest(ctx, claim, out, r, ev)
		if err != nil {
			return in, err
		}
		if signed && next.Attestation(claim, out) != before {
			return in, fmt.Errorf("%w: attestor %d wrote a signed field; the signing attestor goes last", ErrOrder, i)
		}
		ev = next
	}
	return ev, nil
}
