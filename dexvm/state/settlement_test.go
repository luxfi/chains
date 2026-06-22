// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package state

import (
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
)

// newTestState builds a State over in-memory dbs for the settlement record tests.
func newTestState(t *testing.T) *State {
	t.Helper()
	db := memdb.New()
	base := memdb.New()
	s := New(db, base)
	if err := s.Initialize(); err != nil {
		t.Fatalf("Initialize: %v", err)
	}
	return s
}

// TestSettlement_RoundTrip proves a recorded proceeds coordinate reads back exactly —
// the keeper's dex.getSettlement contract.
func TestSettlement_RoundTrip(t *testing.T) {
	s := newTestState(t)
	ref := ids.GenerateTestID()
	out := ids.GenerateTestID()

	if _, _, found, err := s.GetSettlement(ref); err != nil || found {
		t.Fatalf("pre-write: want (not found, nil), got found=%v err=%v", found, err)
	}
	if err := s.PutSettlement(ref, out, 987654); err != nil {
		t.Fatalf("PutSettlement: %v", err)
	}
	gotOut, gotAmt, found, err := s.GetSettlement(ref)
	if err != nil {
		t.Fatalf("GetSettlement: %v", err)
	}
	if !found || gotOut != out || gotAmt != 987654 {
		t.Fatalf("got found=%v out=%s amt=%d, want true %s 987654", found, gotOut, gotAmt, out)
	}
}

// TestSettlement_Isolation proves distinct refs never alias (the record is keyed by
// the full intentID).
func TestSettlement_Isolation(t *testing.T) {
	s := newTestState(t)
	refA, refB := ids.GenerateTestID(), ids.GenerateTestID()
	outA := ids.GenerateTestID()
	if err := s.PutSettlement(refA, outA, 10); err != nil {
		t.Fatalf("PutSettlement A: %v", err)
	}
	if _, _, found, _ := s.GetSettlement(refB); found {
		t.Fatalf("refB must not resolve to refA's record")
	}
	gotOut, gotAmt, found, _ := s.GetSettlement(refA)
	if !found || gotOut != outA || gotAmt != 10 {
		t.Fatalf("refA record corrupted: out=%s amt=%d found=%v", gotOut, gotAmt, found)
	}
}

// TestSettlement_DistinctFromEscrow proves the settlement record and the escrow
// record live in disjoint key spaces under the same ref (different prefixes), so a
// swap's escrow (PutEscrow) and its proceeds coordinate (PutSettlement) coexist.
func TestSettlement_DistinctFromEscrow(t *testing.T) {
	s := newTestState(t)
	ref := ids.GenerateTestID()
	owner := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()
	out := ids.GenerateTestID()

	if err := s.PutEscrow(ref, owner, asset, 100); err != nil {
		t.Fatalf("PutEscrow: %v", err)
	}
	if err := s.PutSettlement(ref, out, 60); err != nil {
		t.Fatalf("PutSettlement: %v", err)
	}
	// Both readable under the same ref, independent.
	gotOwner, gotAsset, gotLocked, eFound, _ := s.GetEscrow(ref)
	if !eFound || gotOwner != owner || gotAsset != asset || gotLocked != 100 {
		t.Fatalf("escrow clobbered by settlement write")
	}
	gotOut, gotAmt, sFound, _ := s.GetSettlement(ref)
	if !sFound || gotOut != out || gotAmt != 60 {
		t.Fatalf("settlement clobbered by escrow write")
	}
}
