// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

import "testing"

func newCeremony() Ceremony {
	return Ceremony{
		ID:        CeremonyID{0xAA},
		Kind:      KindFROST,
		State:     StateRegistered,
		Threshold: 3,
		Total:     5,
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

func TestCeremony_HonestMajorityFloor(t *testing.T) {
	c := Ceremony{Kind: KindFROST, Threshold: 2, Total: 5}
	if err := c.Validate(); err == nil {
		t.Fatal("threshold <= n/2 should be rejected")
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
