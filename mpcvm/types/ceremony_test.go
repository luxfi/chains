// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

import (
	"testing"

	"github.com/luxfi/threshold/pkg/quorum"
)

func newCeremony() Ceremony {
	return Ceremony{
		ID:     CeremonyID{0xAA},
		Kind:   KindFROST,
		State:  StateRegistered,
		Policy: quorum.MustNew(3, 5),
	}
}

// The reason this package exists in its current shape. A ceremony declared
// 3-of-5 must drive the protocol at degree 2 — three shares reconstruct, two do
// not. A degree-3 key would require four signers, so three custodians holding a
// key they were told was 3-of-5 could not spend it, and for a key that already
// holds funds there is no fix short of a resharing ceremony.
func TestCeremony_ThreeOfFiveIsDegreeTwo(t *testing.T) {
	c := newCeremony()

	if err := c.Validate(); err != nil {
		t.Fatalf("3-of-5 must be a valid ceremony policy, got: %v", err)
	}
	if got := c.Degree(); got != 2 {
		t.Fatalf("3-of-5 ceremony Degree() = %d, want 2", got)
	}
	if got := c.Policy.K; got != 3 {
		t.Fatalf("3-of-5 requires %d signers, want 3", got)
	}
	if got := c.Policy.N; got != 5 {
		t.Fatalf("3-of-5 has %d parties, want 5", got)
	}
	if got := c.Policy.String(); got != "3-of-5" {
		t.Fatalf("policy renders as %q, want \"3-of-5\"", got)
	}
}

// Degree must agree with the shared conversion for every deployable policy.
// If these ever diverge, the ceremony record and the generated key disagree
// about how many signers the key needs.
func TestCeremony_DegreeMatchesQuorumEverywhere(t *testing.T) {
	for n := 2; n <= 12; n++ {
		for k := 2; k <= n; k++ {
			p := quorum.MustNew(k, n)
			c := Ceremony{Kind: KindCGGMP21, Policy: p}
			if got, want := c.Degree(), p.Degree(); got != want {
				t.Fatalf("%s: Ceremony.Degree() = %d, quorum says %d", p, got, want)
			}
			if got, want := c.Degree(), k-1; got != want {
				t.Fatalf("%s: Degree() = %d, want K-1 = %d", p, got, want)
			}
		}
	}
}

// The former Threshold/Total pair could express a policy that Validate()
// accepted under k-semantics while the VM consumed it under t-semantics. The
// policy type removes the ambiguity, but the majority floor it enforced is a
// real custody requirement and must survive.
func TestCeremony_RejectsPoliciesWithTwoDisjointQuorums(t *testing.T) {
	for _, tc := range []struct {
		policy quorum.Policy
		unique bool
	}{
		{quorum.MustNew(3, 5), true},  // 2*3 > 5
		{quorum.MustNew(2, 3), true},  // 2*2 > 3
		{quorum.MustNew(4, 5), true},  // 2*4 > 5
		{quorum.MustNew(7, 10), true}, // 2*7 > 10
		{quorum.MustNew(2, 5), false}, // {a,b} and {c,d} both sign
		{quorum.MustNew(3, 6), false}, // exactly two disjoint triples
		{quorum.MustNew(2, 4), false},
	} {
		if got := HasUniqueQuorum(tc.policy); got != tc.unique {
			t.Errorf("HasUniqueQuorum(%s) = %v, want %v", tc.policy, got, tc.unique)
		}
		err := (&Ceremony{Kind: KindCGGMP21, Policy: tc.policy}).Validate()
		if tc.unique && err != nil {
			t.Errorf("Validate(%s) = %v, want accepted", tc.policy, err)
		}
		if !tc.unique && err == nil {
			t.Errorf("Validate(%s) accepted a policy with two disjoint quorums", tc.policy)
		}
	}
}

// A zero Policy is what a struct literal that forgot to set it looks like. It
// must be rejected rather than silently treated as some default, because
// Degree() of the zero policy is -1.
func TestCeremony_RejectsUnsetPolicy(t *testing.T) {
	if err := (&Ceremony{Kind: KindCGGMP21}).Validate(); err == nil {
		t.Fatal("a ceremony with no policy must not validate")
	}
	if err := (&Ceremony{Kind: KindCGGMP21, Policy: quorum.Policy{K: 1, N: 5}}).Validate(); err == nil {
		t.Fatal("1-of-5 is not a threshold policy and must not validate")
	}
	if err := (&Ceremony{Kind: KindCGGMP21, Policy: quorum.Policy{K: 6, N: 5}}).Validate(); err == nil {
		t.Fatal("6-of-5 can never be satisfied and must not validate")
	}
}

func TestCeremony_LegalTransitions(t *testing.T) {
	c := newCeremony()
	if err := c.Validate(); err != nil {
		t.Fatalf("validate: %v", err)
	}
	c, err := c.Transition(StateRound1)
	if err != nil || c.State != StateRound1 || c.Round != 1 {
		t.Fatalf("registered->round1: %v state=%s round=%d", err, c.State, c.Round)
	}
	c, err = c.Transition(StateRound2)
	if err != nil || c.State != StateRound2 || c.Round != 2 {
		t.Fatalf("round1->round2: %v state=%s round=%d", err, c.State, c.Round)
	}
	c, err = c.Transition(StateFinalized)
	if err != nil || c.State != StateFinalized {
		t.Fatalf("round2->finalized: %v state=%s", err, c.State)
	}
}

func TestCeremony_IllegalTransitionsRejected(t *testing.T) {
	c := newCeremony()
	if _, err := c.Transition(StateFinalized); err == nil {
		t.Fatal("registered -> finalized should be rejected")
	}
	if _, err := c.Transition(StateRound2); err == nil {
		t.Fatal("registered -> round2 should be rejected")
	}
}

func TestCeremony_AbortAlwaysAllowed(t *testing.T) {
	c := newCeremony()
	c, err := c.Transition(StateAborted)
	if err != nil || c.State != StateAborted {
		t.Fatalf("registered -> aborted: %v state=%s", err, c.State)
	}
}

func TestCeremonyKind_OrthogonalityFlags(t *testing.T) {
	if !KindFROST.IsMChain() || KindFROST.IsFChain() {
		t.Fatal("FROST is M-Chain only")
	}
	if !KindTFHEBootstrap.IsFChain() || KindTFHEBootstrap.IsMChain() {
		t.Fatal("TFHEBootstrap is F-Chain only")
	}
	if !KindTFHEKeygen.IsHandoff() {
		t.Fatal("TFHEKeygen is the cross-chain handoff kind")
	}
}
