// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cert

import (
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/chains/mpcvm/types"
)

// dispatch records what a stubVerifier was handed, so a test can assert not
// only what Verify returned but whether the verifier ran at all.
type dispatch struct {
	n       int
	subject [32]byte
	share   types.Share
	payload []byte
}

type stubVerifier struct {
	lane types.CertLane
	err  error
	seen *dispatch
}

func (s stubVerifier) Lane() types.CertLane { return s.lane }

func (s stubVerifier) Verify(subject [32]byte, share types.Share, payload []byte) error {
	if s.seen != nil {
		s.seen.n++
		s.seen.subject, s.seen.share, s.seen.payload = subject, share, payload
	}
	return s.err
}

func threeParty(t *testing.T, id types.CeremonyID) *types.ParticipantSet {
	t.Helper()
	set, err := types.NewParticipantSet(id, []types.Participant{
		{Node: types.NodeID{1}}, {Node: types.NodeID{2}}, {Node: types.NodeID{3}},
	})
	if err != nil {
		t.Fatalf("participant set: %v", err)
	}
	return set
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
		types.LaneMChainCoronaGen,
	} {
		if err := r.Register(stubVerifier{lane: lane}); err != nil {
			t.Fatalf("register %d: %v", lane, err)
		}
	}
	for _, lane := range []types.CertLane{
		types.LaneMChainCGGMP21,
		types.LaneMChainFROST,
		types.LaneMChainCoronaGen,
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

// The first registration is the one that survives a second attempt.
//
// Rejecting the duplicate is only half the property. If the map were written
// before the existence check, a second verifier for an already-owned lane would
// silently displace the first while the caller saw an error and moved on — the
// chain would then dispatch that protocol's shares to whichever verifier
// registered last, which is boot order, not policy.
func TestRegister_DuplicateDoesNotDisplaceTheIncumbent(t *testing.T) {
	r := NewRegistry(OwnerMChain)
	incumbent := stubVerifier{lane: types.LaneMChainFROST, seen: &dispatch{}}
	if err := r.Register(incumbent); err != nil {
		t.Fatalf("first register: %v", err)
	}
	if err := r.Register(stubVerifier{lane: types.LaneMChainFROST, seen: &dispatch{}}); err == nil {
		t.Fatal("expected second registration to fail")
	}
	got, err := r.Verifier(types.LaneMChainFROST)
	if err != nil {
		t.Fatalf("lookup after rejected duplicate: %v", err)
	}
	if got.(stubVerifier).seen != incumbent.seen {
		t.Fatal("a rejected duplicate replaced the verifier already registered for the lane")
	}
}

// A nil verifier is refused, not stored.
//
// Storing it would put a nil interface in the dispatch table, turning a
// boot-time configuration mistake into a nil dereference on the first share
// that names the lane — long after the operator could connect the two.
func TestRegister_RefusesNilVerifier(t *testing.T) {
	r := NewRegistry(OwnerMChain)
	if err := r.Register(nil); err == nil {
		t.Fatal("a nil verifier must be refused")
	}
	if len(r.verifier) != 0 {
		t.Fatal("a refused registration left an entry in the dispatch table")
	}
}

// A registry with no owner registers nothing.
//
// Owner is the entire enforcement mechanism — Register consults it and nothing
// else. A registry built from a zero Owner (a struct literal that forgot the
// field, a chain wired before it knows which chain it is) must refuse every
// lane. Refusing none would hand a single process both chains' lanes, which is
// exactly the state the M/F split exists to prevent.
func TestRegistry_UnownedRegistryRefusesEveryLane(t *testing.T) {
	r := NewRegistry(OwnerUnknown)
	if r.Owner() != OwnerUnknown {
		t.Fatalf("Owner() = %d, want OwnerUnknown", r.Owner())
	}
	for i := 0; i <= 255; i++ {
		if err := r.Register(stubVerifier{lane: types.CertLane(i)}); err == nil {
			t.Fatalf("lane %d: an owner-unset registry accepted a verifier", i)
		}
	}
}

// Owner partitions the whole lane space, and each registry gets exactly its half.
//
// Lanes 5..7 are M-Chain's, 8..9 are F-Chain's, and 0..4 belong to neither —
// they are Quasar's own consensus and attestation lanes. Sweeping all 256
// encodable lane values rather than the ten named ones is deliberate: the lane
// arrives on the wire as a byte, so the ownership predicate has to answer for
// values LP-1340 never assigned.
func TestRegistry_OwnerPartitionsTheLaneSpace(t *testing.T) {
	for _, owner := range []struct {
		owner Owner
		owns  func(types.CertLane) bool
	}{
		{OwnerMChain, types.CertLane.IsMChain},
		{OwnerFChain, types.CertLane.IsFChain},
	} {
		r := NewRegistry(owner.owner)
		if r.Owner() != owner.owner {
			t.Fatalf("Owner() = %d, want %d", r.Owner(), owner.owner)
		}
		accepted := 0
		for i := 0; i <= 255; i++ {
			lane := types.CertLane(i)
			err := r.Register(stubVerifier{lane: lane})
			if want := owner.owns(lane); (err == nil) != want {
				t.Fatalf("owner %d lane %d: Register err=%v, owns=%v", owner.owner, lane, err, want)
			}
			if err == nil {
				accepted++
			}
		}
		if want := map[Owner]int{OwnerMChain: 3, OwnerFChain: 2}[owner.owner]; accepted != want {
			t.Fatalf("owner %d accepted %d lanes, want %d", owner.owner, accepted, want)
		}
	}
}

// Lookup keeps refusing after boot, for every lane that was never registered.
//
// Register enforces ownership once, at boot. Dispatch happens per-share
// thereafter on a lane number that arrived on the wire. If Verifier resolved an
// unregistered lane to anything but an error — a zero value, a nil interface
// the caller goes on to invoke — the boot-time partition would stop binding
// precisely where an attacker gets to choose the input.
func TestRegistry_VerifierRefusesUnregisteredLanesAfterBoot(t *testing.T) {
	r := NewRegistry(OwnerMChain)
	if err := r.Register(stubVerifier{lane: types.LaneMChainCGGMP21}); err != nil {
		t.Fatalf("register: %v", err)
	}
	for i := 0; i <= 255; i++ {
		lane := types.CertLane(i)
		v, err := r.Verifier(lane)
		if lane == types.LaneMChainCGGMP21 {
			if err != nil || v == nil {
				t.Fatalf("registered lane %d: v=%v err=%v", lane, v, err)
			}
			continue
		}
		if err == nil {
			t.Fatalf("lane %d resolved to a verifier on a registry that never registered it", lane)
		}
		if v != nil {
			t.Fatalf("lane %d returned a verifier alongside an error", lane)
		}
	}
}

// A malformed envelope never reaches a verifier.
//
// A lane verifier is protocol code that trusts its inputs: it is handed a
// payload window and a share already established to name a real participant of
// this ceremony. Every envelope defect has to be caught by the registry, and
// the verifier must not run at all — a verifier that runs on a share whose
// ParticipantID is out of range is attributing a round contribution to a
// participant that does not exist, and one that runs on a share naming another
// ceremony is accepting a replay.
func TestRegistry_VerifyRefusesMalformedEnvelopeWithoutDispatching(t *testing.T) {
	id := types.CeremonyID{0xC0}
	set := threeParty(t, id)
	arena := []byte("0123456789abcdef")
	good := types.Share{
		CeremonyID: id, ParticipantID: 2, Round: 1,
		Lane: types.LaneMChainCGGMP21, PayloadOffset: 4, PayloadLen: 4,
	}

	mangle := func(f func(*types.Share)) types.Share {
		s := good
		f(&s)
		return s
	}

	for _, tc := range []struct {
		name  string
		share types.Share
		set   *types.ParticipantSet
	}{
		{"nil participant set", good, nil},
		{"ceremony id of another ceremony", mangle(func(s *types.Share) { s.CeremonyID = types.CeremonyID{0xC1} }), set},
		{"participant one past the set", mangle(func(s *types.Share) { s.ParticipantID = 3 }), set},
		{"participant far out of range", mangle(func(s *types.Share) { s.ParticipantID = ^uint32(0) }), set},
		{"round zero", mangle(func(s *types.Share) { s.Round = 0 }), set},
		{"empty payload", mangle(func(s *types.Share) { s.PayloadLen = 0 }), set},
		{"payload window past the arena", mangle(func(s *types.Share) { s.PayloadLen = 13 }), set},
		{"payload offset past the arena", mangle(func(s *types.Share) { s.PayloadOffset = 17 }), set},
		{"lane this chain does not own", mangle(func(s *types.Share) { s.Lane = types.LaneFChainTFHE }), set},
		{"lane no chain owns", mangle(func(s *types.Share) { s.Lane = types.LaneBLS }), set},
	} {
		seen := &dispatch{}
		r := NewRegistry(OwnerMChain)
		if err := r.Register(stubVerifier{lane: types.LaneMChainCGGMP21, seen: seen}); err != nil {
			t.Fatalf("%s: register: %v", tc.name, err)
		}
		if err := r.Verify([32]byte{}, tc.share, arena, tc.set); err == nil {
			t.Errorf("%s: accepted", tc.name)
		}
		if seen.n != 0 {
			t.Errorf("%s: the verifier ran %d times on a share the registry should have refused", tc.name, seen.n)
		}
	}
}

// Verify hands the verifier the subject and exactly the window the share names.
//
// The (offset, len) indirection is the whole share ABI: the verifier never
// decodes the envelope, it only sees the bytes the registry sliced out. An
// off-by-one here hands a protocol verifier a payload shifted by a byte, which
// fails as a bad signature rather than as a bounds bug.
func TestRegistry_VerifyDispatchesTheNamedPayloadWindow(t *testing.T) {
	id := types.CeremonyID{0xC0}
	set := threeParty(t, id)
	arena := []byte("0123456789abcdef")
	subject := [32]byte{0xEE}
	seen := &dispatch{}

	r := NewRegistry(OwnerMChain)
	if err := r.Register(stubVerifier{lane: types.LaneMChainCoronaGen, seen: seen}); err != nil {
		t.Fatalf("register: %v", err)
	}

	share := types.Share{
		CeremonyID: id, ParticipantID: 0, Round: 2,
		Lane: types.LaneMChainCoronaGen, PayloadOffset: 4, PayloadLen: 6,
	}
	if err := r.Verify(subject, share, arena, set); err != nil {
		t.Fatalf("a well-formed share on a registered lane must dispatch: %v", err)
	}
	if seen.n != 1 {
		t.Fatalf("verifier ran %d times, want exactly 1", seen.n)
	}
	if seen.subject != subject {
		t.Fatalf("verifier got subject %x, want %x", seen.subject, subject)
	}
	if seen.share != share {
		t.Fatalf("verifier got share %+v, want %+v", seen.share, share)
	}
	if got := string(seen.payload); got != "456789" {
		t.Fatalf("verifier got payload %q, want %q", got, "456789")
	}
}

// A verifier's refusal is the registry's refusal.
//
// The registry is a dispatcher, not a policy layer. If it swallowed a
// verifier's error the share would be recorded as validated with no protocol
// check behind it, which is the one outcome the lane exists to prevent.
func TestRegistry_VerifierRefusalSurfaces(t *testing.T) {
	id := types.CeremonyID{0xC0}
	set := threeParty(t, id)
	refusal := errors.New("payload is not a valid round-1 commitment")

	r := NewRegistry(OwnerMChain)
	if err := r.Register(stubVerifier{lane: types.LaneMChainFROST, err: refusal}); err != nil {
		t.Fatalf("register: %v", err)
	}
	share := types.Share{
		CeremonyID: id, ParticipantID: 1, Round: 1,
		Lane: types.LaneMChainFROST, PayloadOffset: 0, PayloadLen: 4,
	}
	if err := r.Verify([32]byte{}, share, []byte("abcd"), set); !errors.Is(err, refusal) {
		t.Fatalf("Verify returned %v, want the verifier's own error", err)
	}
}
