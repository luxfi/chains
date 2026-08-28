// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

import (
	"math/bits"
	"strings"
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

// HasUniqueQuorum agrees with what it claims to mean.
//
// 2K > N is a shortcut for "no two disjoint K-subsets of the N parties exist",
// and the shortcut is the thing the custody floor is actually asserting. This
// enumerates the subsets instead of restating the arithmetic, so an edit to
// HasUniqueQuorum that keeps the comparison plausible — >= for >, N/2 rounding
// the wrong way — is caught by the definition rather than by a copy of itself.
func TestCeremony_UniqueQuorumMeansNoTwoDisjointSigningSets(t *testing.T) {
	for n := 0; n <= 7; n++ {
		for k := 0; k <= n; k++ {
			got := HasUniqueQuorum(quorum.Policy{K: k, N: n})
			if want := !disjointQuorumsExist(k, n); got != want {
				t.Errorf("HasUniqueQuorum(%d-of-%d) = %v; enumerating subsets says %v", k, n, got, want)
			}
		}
	}
}

// disjointQuorumsExist reports whether two disjoint K-subsets of an N-set exist,
// by enumerating every pair of subsets.
func disjointQuorumsExist(k, n int) bool {
	for a := 0; a < 1<<n; a++ {
		if bits.OnesCount(uint(a)) != k {
			continue
		}
		for b := 0; b < 1<<n; b++ {
			if bits.OnesCount(uint(b)) == k && a&b == 0 {
				return true
			}
		}
	}
	return false
}

// Validate refuses a ceremony with no kind, and a nil ceremony.
//
// Kind decides which lane the artifact takes and which verifier reads each
// round. KindUnknown is the zero value, so accepting it would let a
// zero-initialised struct reach the state machine and finalize into whatever
// lane the dispatch table happened to answer with.
func TestCeremony_ValidateRefusesNilAndKindless(t *testing.T) {
	if err := (*Ceremony)(nil).Validate(); err == nil {
		t.Fatal("a nil ceremony must not validate")
	}
	err := (&Ceremony{Policy: quorum.MustNew(3, 5)}).Validate()
	if err == nil || !strings.Contains(err.Error(), "kind unset") {
		t.Fatalf("a ceremony with no kind must be refused, got: %v", err)
	}
}

// Every state renders as a distinct label, including the zero value.
//
// The labels are what a transition error says, and an operator reading
// "ceremony: unknown -> unknown not legal" needs those two words to be
// different states, not the same word for two of them.
func TestCeremonyState_LabelsAreDistinct(t *testing.T) {
	seen := map[string]CeremonyState{}
	for state, want := range map[CeremonyState]string{
		StateUnknown:    "unknown",
		StateRegistered: "registered",
		StateRound1:     "round1",
		StateRound2:     "round2",
		StateFinalized:  "finalized",
		StateAborted:    "aborted",
	} {
		got := state.String()
		if got != want {
			t.Errorf("state %d renders as %q, want %q", uint8(state), got, want)
		}
		if prior, dup := seen[got]; dup {
			t.Errorf("states %d and %d both render as %q", uint8(prior), uint8(state), got)
		}
		seen[got] = state
	}
	if got := CeremonyState(200).String(); got != "unknown" {
		t.Errorf("an unassigned state renders as %q, want %q", got, "unknown")
	}
}

// The transition table is exactly four edges plus abort from anywhere.
//
// The state machine is the substrate's only mutable thing, and every other
// invariant is stated relative to a state: shares are only meaningful in Round1
// and Round2, the cert artifact only exists after Finalized. An extra edge —
// Registered straight to Finalized, Round1 back to Registered — would let a
// ceremony emit an artifact for rounds that never ran.
func TestCeremony_TransitionAdmitsOnlyTheFourEdgesAndAbort(t *testing.T) {
	type post struct {
		state CeremonyState
		round uint8
	}
	legal := map[[2]CeremonyState]post{
		{StateRegistered, StateRound1}: {StateRound1, 1},
		{StateRound1, StateRound2}:     {StateRound2, 2},
		{StateRound2, StateFinalized}:  {StateFinalized, 0},
	}
	for from := StateUnknown; from <= StateAborted; from++ {
		legal[[2]CeremonyState{from, StateAborted}] = post{StateAborted, 0}
	}

	for from := StateUnknown; from <= StateAborted; from++ {
		for to := StateUnknown; to <= StateAborted; to++ {
			before := Ceremony{ID: CeremonyID{0xAA}, Kind: KindFROST, State: from, Policy: quorum.MustNew(3, 5)}
			after, err := before.Transition(to)

			if after.ID != before.ID || after.Kind != before.Kind || after.Policy != before.Policy {
				t.Errorf("%s -> %s altered a field other than State and Round", from, to)
			}

			want, ok := legal[[2]CeremonyState{from, to}]
			if !ok {
				if err == nil {
					t.Errorf("%s -> %s was accepted", from, to)
				}
				if after.State != before.State || after.Round != before.Round {
					t.Errorf("%s -> %s: refused but returned %s/round %d instead of the ceremony unchanged",
						from, to, after.State, after.Round)
				}
				continue
			}
			if err != nil {
				t.Errorf("%s -> %s: %v", from, to, err)
				continue
			}
			if after.State != want.state || after.Round != want.round {
				t.Errorf("%s -> %s gave %s/round %d, want %s/round %d",
					from, to, after.State, after.Round, want.state, want.round)
			}
		}
	}
}

// Transition hands back a new ceremony and leaves the caller's alone.
//
// The host chain drives transitions on a block tick and only commits the result
// once the block verifies. If Transition mutated in place, a transition
// attempted on a block that is later rejected would already have advanced the
// live ceremony, and a refused transition would advance it halfway.
func TestCeremony_TransitionReturnsACopy(t *testing.T) {
	before := newCeremony()
	after, err := before.Transition(StateRound1)
	if err != nil {
		t.Fatalf("registered -> round1: %v", err)
	}
	after.State, after.Round, after.Kind = StateAborted, 9, KindCGGMP21

	if before.State != StateRegistered || before.Round != 0 || before.Kind != KindFROST {
		t.Fatalf("writing to the returned ceremony reached the receiver: %s/round %d/kind %d",
			before.State, before.Round, before.Kind)
	}
	if _, err := before.Transition(StateRound1); err != nil {
		t.Fatalf("the receiver is no longer in Registered: %v", err)
	}
}

// The copy is shallow, and the arena is deliberately shared.
//
// PayloadArena is the host chain's buffer holding every participant's payload
// for the ceremony — for a TFHE bootstrap-key round that is hundreds of
// megabytes. The substrate never allocates, so a transition must not clone it:
// a per-tick deep copy would be the arena's size times the block rate. Copying
// the scalar fields while aliasing the arena is the intended shape, and this
// pins it so a later "make Transition a real deep copy" does not quietly turn
// one buffer into one per tick.
func TestCeremony_TransitionSharesTheArenaRatherThanCloningIt(t *testing.T) {
	before := newCeremony()
	before.PayloadArena = []byte("payload")

	after, err := before.Transition(StateRound1)
	if err != nil {
		t.Fatalf("registered -> round1: %v", err)
	}
	after.PayloadArena[0] = 'P'
	if before.PayloadArena[0] != 'P' {
		t.Fatal("Transition cloned the payload arena; the substrate must not allocate it")
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

// No kind is claimed by two of the three predicates.
//
// The predicates decide which chain runs a ceremony. A kind claimed by both
// chains would run twice, once on each, producing two artifacts for one
// ceremony id. TFHEKeygen is deliberately claimed by neither chain: it is the
// M-to-F handoff, so it originates on M-Chain and finalizes into F-Chain, and a
// predicate that assigned it to a single chain would put the whole ceremony
// there and drop the handoff. The sweep runs over all 256 encodable kinds
// because the kind is a byte on the wire.
func TestCeremonyKind_PredicatesAreMutuallyExclusive(t *testing.T) {
	m := map[CeremonyKind]bool{KindCGGMP21: true, KindFROST: true, KindCoronaGen: true}
	f := map[CeremonyKind]bool{KindTFHECompute: true, KindTFHEBootstrap: true}
	handoff := map[CeremonyKind]bool{KindTFHEKeygen: true}

	for i := 0; i <= 255; i++ {
		k := CeremonyKind(i)
		claims := 0
		for _, claimed := range []bool{k.IsMChain(), k.IsFChain(), k.IsHandoff()} {
			if claimed {
				claims++
			}
		}
		if claims > 1 {
			t.Fatalf("kind %d is claimed by %d of the three predicates", k, claims)
		}
		if got := k.IsMChain(); got != m[k] {
			t.Errorf("kind %d IsMChain() = %v, want %v", k, got, m[k])
		}
		if got := k.IsFChain(); got != f[k] {
			t.Errorf("kind %d IsFChain() = %v, want %v", k, got, f[k])
		}
		if got := k.IsHandoff(); got != handoff[k] {
			t.Errorf("kind %d IsHandoff() = %v, want %v", k, got, handoff[k])
		}
	}

	if KindTFHEKeygen.IsMChain() || KindTFHEKeygen.IsFChain() {
		t.Fatal("TFHEKeygen belongs to the handoff, not to either chain alone")
	}
	if KindUnknown.IsMChain() || KindUnknown.IsFChain() || KindUnknown.IsHandoff() {
		t.Fatal("the zero kind must belong to nothing")
	}
}

// Kind numbers are the wire encoding and never move.
//
// The comment on the constant block says kinds append and never reorder. A
// renumbering is silent across a mixed-version network: a node reading kind 5
// as TFHECompute while its peer wrote FROST routes the ceremony to the wrong
// chain's protocol driver.
func TestCeremonyKind_ValuesAreAppendOnly(t *testing.T) {
	for kind, want := range map[CeremonyKind]uint8{
		KindUnknown: 0, KindCGGMP21: 1, KindFROST: 2, KindCoronaGen: 3,
		KindTFHEKeygen: 4, KindTFHECompute: 5, KindTFHEBootstrap: 6,
	} {
		if uint8(kind) != want {
			t.Errorf("kind encodes as %d, want %d", uint8(kind), want)
		}
	}
}
