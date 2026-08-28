// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

import (
	"math"
	"strings"
	"testing"
)

// The lane space is partitioned: no lane belongs to both chains.
//
// IsMChain and IsFChain are what cert.LaneRegistry consults to decide whether a
// chain may answer for a lane. A lane both predicates claimed would be
// registrable on both chains at once, so the same protocol round would be
// verified by two different chains' code and the M/F split would exist only in
// the documentation. Lanes 0..4 are Quasar's own — a chain claiming one of
// those would be answering for consensus.
func TestCertLane_ChainsClaimDisjointHalvesOfTheLaneSpace(t *testing.T) {
	m := map[CertLane]bool{LaneMChainCGGMP21: true, LaneMChainFROST: true, LaneMChainCoronaGen: true}
	f := map[CertLane]bool{LaneFChainTFHE: true, LaneFChainBootstrap: true}

	for i := 0; i <= 255; i++ {
		lane := CertLane(i)
		if lane.IsMChain() && lane.IsFChain() {
			t.Fatalf("lane %d is claimed by both chains", lane)
		}
		if got := lane.IsMChain(); got != m[lane] {
			t.Errorf("lane %d IsMChain() = %v, want %v", lane, got, m[lane])
		}
		if got := lane.IsFChain(); got != f[lane] {
			t.Errorf("lane %d IsFChain() = %v, want %v", lane, got, f[lane])
		}
	}
}

// Lane numbers are the wire encoding and never move.
//
// A CertLane is a byte on the QuasarCertIngress wire, read by peers running
// older binaries. Renumbering a lane does not fail — it silently routes a
// ceremony's shares to another protocol's verifier on every node that has not
// upgraded.
func TestCertLane_ValuesAreFixedByLP134(t *testing.T) {
	for lane, want := range map[CertLane]uint8{
		LaneBLS: 0, LaneCorona: 1, LaneMLDSAGroth16: 2, LaneAChainAttest: 3,
		LaneBChainBridge: 4, LaneMChainCGGMP21: 5, LaneMChainFROST: 6,
		LaneMChainCoronaGen: 7, LaneFChainTFHE: 8, LaneFChainBootstrap: 9,
	} {
		if uint8(lane) != want {
			t.Errorf("lane encodes as %d, want %d", uint8(lane), want)
		}
	}
}

// PayloadFrom returns the exact window and nothing adjacent.
//
// The verifier never sees the arena, only this slice, so the window is the
// whole of what it authenticates. A window one byte wide of the truth is
// indistinguishable downstream from a bad signature.
func TestShare_PayloadIsExactlyTheNamedWindow(t *testing.T) {
	arena := []byte("0123456789")
	for _, tc := range []struct {
		off, n uint32
		want   string
	}{
		{0, 10, "0123456789"}, // exact fit over the whole arena
		{0, 1, "0"},
		{3, 4, "3456"},
		{9, 1, "9"}, // last byte
		{10, 0, ""}, // empty window at the very end
		{0, 0, ""},  // empty window at the start
		{5, 5, "56789"},
	} {
		got, err := Share{PayloadOffset: tc.off, PayloadLen: tc.n}.PayloadFrom(arena)
		if err != nil {
			t.Errorf("[%d..%d): %v", tc.off, tc.off+tc.n, err)
			continue
		}
		if string(got) != tc.want {
			t.Errorf("[%d..%d) = %q, want %q", tc.off, tc.off+tc.n, got, tc.want)
		}
	}

	if got, err := (Share{}).PayloadFrom(nil); err != nil || len(got) != 0 {
		t.Errorf("an empty window over an empty arena must succeed: %q %v", got, err)
	}
}

// A window that runs past the arena is refused, never truncated.
//
// The arena is the host chain's buffer and holds every participant's payload
// for the ceremony. Clamping an over-long window to the arena end would hand
// the verifier a neighbouring participant's bytes; reading past it would hand
// it whatever the allocator left there.
func TestShare_PayloadPastTheArenaIsRefused(t *testing.T) {
	arena := make([]byte, 16)
	for _, tc := range []struct{ off, n uint32 }{
		{0, 17}, // one byte too long
		{16, 1}, // starts at the end
		{17, 0}, // starts past the end
		{8, 9},  // window straddles the end
		{1 << 20, 1},
	} {
		if got, err := (Share{PayloadOffset: tc.off, PayloadLen: tc.n}).PayloadFrom(arena); err == nil {
			t.Errorf("[%d..%d) over a 16-byte arena returned %d bytes, want an error",
				tc.off, uint64(tc.off)+uint64(tc.n), len(got))
		}
	}
}

// The bounds arithmetic widens before it adds.
//
// PayloadOffset and PayloadLen are both uint32 and both attacker-chosen. Summed
// in uint32 they wrap at 4 GiB: offset 0xFFFFFFFF with length 1 sums to 0, so a
// bounds check on the wrapped sum passes for every arena, and the slice
// expression that follows panics with low greater than high — a remote node
// halt from two fields on the wire. Widening to uint64 first is what makes the
// sum unrepresentable-as-small.
func TestShare_PayloadWindowArithmeticDoesNotWrap(t *testing.T) {
	arena := make([]byte, 64)
	for _, tc := range []struct{ off, n uint32 }{
		{math.MaxUint32, 1},
		{math.MaxUint32, math.MaxUint32},
		{math.MaxUint32 - 3, 8},
		{1 << 31, 1 << 31},
		{0xFFFFFF00, 0x100},
	} {
		got, err := (Share{PayloadOffset: tc.off, PayloadLen: tc.n}).PayloadFrom(arena)
		if err == nil {
			t.Errorf("offset %d len %d returned %d bytes over a 64-byte arena, want an error",
				tc.off, tc.n, len(got))
		}
	}
}

// Validate rejects every envelope a verifier must never see.
//
// Each of these is a distinct way for a share to be about something other than
// what the caller thinks: a share from another ceremony (a replay), a share
// attributed to a participant that is not in the set, a round-0 share (the
// reserved value, so a zero-valued struct cannot pass as a real round), and an
// empty payload (nothing to verify, so the verifier would trivially accept).
func TestShare_ValidateRejectsEveryEnvelopeDefect(t *testing.T) {
	id := CeremonyID{0xAB}
	set, err := NewParticipantSet(id, []Participant{{Node: NodeID{1}}, {Node: NodeID{2}}})
	if err != nil {
		t.Fatalf("participant set: %v", err)
	}
	good := Share{CeremonyID: id, ParticipantID: 1, Round: 1, PayloadLen: 8}

	if err := good.Validate(set); err != nil {
		t.Fatalf("a well-formed share must validate: %v", err)
	}

	mangle := func(f func(*Share)) Share {
		s := good
		f(&s)
		return s
	}
	for _, tc := range []struct {
		name  string
		share Share
		set   *ParticipantSet
		want  string
	}{
		{"nil set", good, nil, "nil participant set"},
		{"another ceremony's id", mangle(func(s *Share) { s.CeremonyID = CeremonyID{0xAC} }), set, "does not match participant set"},
		{"zero ceremony id", mangle(func(s *Share) { s.CeremonyID = CeremonyID{} }), set, "does not match participant set"},
		{"participant one past the set", mangle(func(s *Share) { s.ParticipantID = 2 }), set, ">= set size"},
		{"participant at uint32 max", mangle(func(s *Share) { s.ParticipantID = ^uint32(0) }), set, ">= set size"},
		{"round 0", mangle(func(s *Share) { s.Round = 0 }), set, "round 0 reserved"},
		{"empty payload", mangle(func(s *Share) { s.PayloadLen = 0 }), set, "empty payload"},
	} {
		err := tc.share.Validate(tc.set)
		if err == nil {
			t.Errorf("%s: accepted", tc.name)
			continue
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: want an error mentioning %q, got: %v", tc.name, tc.want, err)
		}
	}
}

// Validate says nothing about the lane.
//
// Lane ownership is the registry's question, not the envelope's: cert's
// LaneRegistry answers it per chain, and a share validated here is still
// refused there if the chain does not own the lane. Duplicating the check in
// Validate would give two places that can disagree about who owns a lane.
func TestShare_ValidateLeavesLaneOwnershipToTheRegistry(t *testing.T) {
	id := CeremonyID{0xAB}
	set, err := NewParticipantSet(id, []Participant{{Node: NodeID{1}}})
	if err != nil {
		t.Fatalf("participant set: %v", err)
	}
	for i := 0; i <= 255; i++ {
		s := Share{CeremonyID: id, ParticipantID: 0, Round: 1, Lane: CertLane(i), PayloadLen: 1}
		if err := s.Validate(set); err != nil {
			t.Fatalf("lane %d: envelope validation must not judge the lane: %v", i, err)
		}
	}
}
