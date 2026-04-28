// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cert

import (
	"strings"
	"testing"

	"github.com/luxfi/chains/thresholdvm/types"
)

type stubVerifier struct{ lane types.CertLane }

func (s stubVerifier) Lane() types.CertLane { return s.lane }
func (s stubVerifier) Verify(_ [32]byte, _ types.Share, _ []byte) error {
	return nil
}

// Orthogonality: the M-Chain registry refuses F-Chain lanes.
func TestOrthogonality_MChainRejectsFChainLane(t *testing.T) {
	r := NewRegistry(OwnerMChain)
	err := r.Register(stubVerifier{lane: types.LaneFChainTFHE})
	if err == nil {
		t.Fatal("expected M-Chain registry to reject FChainTFHE lane")
	}
	if !strings.Contains(err.Error(), "not owned by M-Chain") {
		t.Fatalf("expected ownership error, got: %v", err)
	}
}

// Orthogonality: the F-Chain registry refuses M-Chain lanes.
func TestOrthogonality_FChainRejectsMChainLane(t *testing.T) {
	r := NewRegistry(OwnerFChain)
	err := r.Register(stubVerifier{lane: types.LaneMChainCGGMP21})
	if err == nil {
		t.Fatal("expected F-Chain registry to reject MChainCGGMP21 lane")
	}
	if !strings.Contains(err.Error(), "not owned by F-Chain") {
		t.Fatalf("expected ownership error, got: %v", err)
	}
}

// Happy path: M-Chain registers all three of its lanes.
func TestRegister_MChainOwnedLanes(t *testing.T) {
	r := NewRegistry(OwnerMChain)
	for _, lane := range []types.CertLane{
		types.LaneMChainCGGMP21,
		types.LaneMChainFROST,
		types.LaneMChainRingtailGen,
	} {
		if err := r.Register(stubVerifier{lane: lane}); err != nil {
			t.Fatalf("register %d: %v", lane, err)
		}
	}
	for _, lane := range []types.CertLane{
		types.LaneMChainCGGMP21,
		types.LaneMChainFROST,
		types.LaneMChainRingtailGen,
	} {
		if _, err := r.Verifier(lane); err != nil {
			t.Fatalf("lookup %d: %v", lane, err)
		}
	}
}

// Happy path: F-Chain registers its two lanes.
func TestRegister_FChainOwnedLanes(t *testing.T) {
	r := NewRegistry(OwnerFChain)
	for _, lane := range []types.CertLane{
		types.LaneFChainTFHE,
		types.LaneFChainBootstrap,
	} {
		if err := r.Register(stubVerifier{lane: lane}); err != nil {
			t.Fatalf("register %d: %v", lane, err)
		}
	}
}

// Double-registration is rejected.
func TestRegister_RejectsDoubleRegistration(t *testing.T) {
	r := NewRegistry(OwnerMChain)
	if err := r.Register(stubVerifier{lane: types.LaneMChainFROST}); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.Register(stubVerifier{lane: types.LaneMChainFROST}); err == nil {
		t.Fatal("expected second registration to fail")
	}
}

// Legacy alias dispatch: a legacy lane id resolves to the modern verifier.
func TestLegacyAlias_DispatchesToModern(t *testing.T) {
	r := NewRegistry(OwnerMChain)
	if err := r.Register(stubVerifier{lane: types.LaneMChainCGGMP21}); err != nil {
		t.Fatalf("register: %v", err)
	}
	const legacyTChainSign types.CertLane = 200 // arbitrary legacy id
	if err := r.RegisterLegacyAlias(legacyTChainSign, types.LaneMChainCGGMP21); err != nil {
		t.Fatalf("alias: %v", err)
	}
	v, err := r.Verifier(legacyTChainSign)
	if err != nil {
		t.Fatalf("legacy lookup: %v", err)
	}
	if v.Lane() != types.LaneMChainCGGMP21 {
		t.Fatalf("legacy alias should dispatch to MChainCGGMP21, got %d", v.Lane())
	}
	r.ClearAliases()
	if _, err := r.Verifier(legacyTChainSign); err == nil {
		t.Fatal("after ClearAliases, legacy id should not resolve")
	}
}
