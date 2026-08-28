// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// custody_test.go — the leaderless parts: who signs, which ceremony it is, and
// how both are derived rather than announced.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	validators "github.com/luxfi/validators"
	"github.com/luxfi/validators/validatorstest"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
)

// -----------------------------------------------------------------------------
// Ceremony ids
// -----------------------------------------------------------------------------

// A signing ceremony id is a function of the task and nothing else, so every
// validator that observes the same request lands on the same id with no
// coordination round and no coordinator.
func TestASigningCeremonyIdIsAFunctionOfItsTaskAlone(t *testing.T) {
	key, digest := "vault", digestOf(1)
	signers := parties(3)

	base := ceremonyID(key, digest, signers)
	require.Equal(t, base, ceremonyID(key, digest, signers))
	require.Equal(t, base, ceremonyID(key, digest, []party.ID{"pc", "pa", "pb"}),
		"the signer set is a set: enumerating it in a different order is the same task")

	require.NotEqual(t, base, ceremonyID("other", digest, signers))
	require.NotEqual(t, base, ceremonyID(key, digestOf(2), signers))
	require.NotEqual(t, base, ceremonyID(key, digest, parties(4)))
	require.Contains(t, base, "mpc/")
}

// A keygen has no message to bind, so it binds the key id, the policy and the
// committee: two nodes that disagree about any of those run different
// ceremonies rather than producing incompatible shares of the same session.
func TestAKeygenCeremonyIdBindsThePolicyAndTheCommittee(t *testing.T) {
	base := keygenCeremonyID("vault", quorum.MustNew(3, 5), parties(5))
	require.Equal(t, base, keygenCeremonyID("vault", quorum.MustNew(3, 5), parties(5)))
	require.NotEqual(t, base, keygenCeremonyID("other", quorum.MustNew(3, 5), parties(5)))
	require.NotEqual(t, base, keygenCeremonyID("vault", quorum.MustNew(4, 5), parties(5)))
	require.NotEqual(t, base, keygenCeremonyID("vault", quorum.MustNew(3, 6), parties(5)))
	require.NotEqual(t, base, keygenCeremonyID("vault", quorum.MustNew(3, 5), parties(4)))
}

// A keygen id and a signing id can never collide, even for identical inputs.
func TestAKeygenIdIsNeverASigningId(t *testing.T) {
	require.NotEqual(t,
		keygenCeremonyID("vault", quorum.MustNew(3, 5), parties(5)),
		ceremonyID("vault", digestOf(1), parties(5)))
	require.NotContains(t, ceremonyID("vault", digestOf(1), parties(5)), "keygen")
}

// -----------------------------------------------------------------------------
// Quorum selection
// -----------------------------------------------------------------------------

// The quorum for a task is a deterministic function of (key, digest), so every
// node — signer or not — computes the same subset and therefore the same
// ceremony id, with no election.
func TestEveryNodeComputesTheSameQuorumForATask(t *testing.T) {
	rec := sampleKeyRecord()
	rec.Policy = quorum.MustNew(3, 5)
	rec.Participants = parties(5)
	digest := digestOf(1)

	first := quorumFor(rec, digest)
	require.Len(t, first, 3, "a 3-of-5 key signs with three parties, not five")
	require.True(t, sortedUnique(first))
	for i := 0; i < 20; i++ {
		require.Equal(t, first, quorumFor(rec, digest))
	}
	for _, p := range first {
		require.Contains(t, rec.Participants, p)
	}
}

// The selection spreads work across the committee instead of loading the same K
// parties for every transfer, and an adversary cannot choose which subset will
// sign a message it does not control.
func TestQuorumSelectionSpreadsAcrossTheCommittee(t *testing.T) {
	rec := sampleKeyRecord()
	rec.Policy = quorum.MustNew(3, 5)
	rec.Participants = parties(5)

	seen := map[party.ID]int{}
	distinct := map[string]struct{}{}
	for i := 0; i < 60; i++ {
		q := quorumFor(rec, digestOf(byte(i)))
		key := ""
		for _, p := range q {
			seen[p]++
			key += string(p)
		}
		distinct[key] = struct{}{}
	}
	require.Len(t, seen, 5, "every committee member must be selected for some task")
	require.Greater(t, len(distinct), 1, "a selection that always picked the same subset would not spread anything")

	// And the same key with a different id ranks its parties differently, so a
	// party's position is not a property of the party.
	other := sampleKeyRecord()
	other.KeyID = "another-vault"
	other.Policy = rec.Policy
	other.Participants = rec.Participants
	differed := false
	for i := 0; i < 20 && !differed; i++ {
		differed = !samePartySet(quorumFor(rec, digestOf(byte(i))), quorumFor(other, digestOf(byte(i))))
	}
	require.True(t, differed, "the ranking must depend on the key, not only on the message")
}

// A committee smaller than the policy asks for yields whatever there is rather
// than indexing past the end.
func TestAQuorumCannotAskForMorePartiesThanThereAre(t *testing.T) {
	rec := sampleKeyRecord()
	rec.Policy = quorum.MustNew(5, 5)
	rec.Participants = parties(2)
	require.Len(t, quorumFor(rec, digestOf(1)), 2)

	rec.Participants = nil
	require.Empty(t, quorumFor(rec, digestOf(1)))
}

func TestPartyMembershipIsWhatItSays(t *testing.T) {
	require.True(t, containsParty(parties(3), "pb"))
	require.False(t, containsParty(parties(3), "pz"))
	require.False(t, containsParty(nil, "pa"))
}

// -----------------------------------------------------------------------------
// Committee formation
// -----------------------------------------------------------------------------

// Seats go to stake, not to node ids. An id is a hash of the node's
// certificate, so ids can be AIMED: certificates are cheap to generate offline
// and one that sorts early is a matter of how many were tried. An order over
// ids alone would let a party choose its own seats — and under a small policy,
// a quorum of every key the chain generates.
func TestSeatsFollowStakeAndNotAGrindableId(t *testing.T) {
	// Four validators. The two with the most stake sort LAST by id, so a
	// selection that ordered by id would pick the two poorest.
	rich := []ids.NodeID{{0xff, 1}, {0xff, 2}}
	poor := []ids.NodeID{{0x00, 1}, {0x00, 2}}
	weights := map[ids.NodeID]uint64{rich[0]: 1000, rich[1]: 999, poor[0]: 1, poor[1]: 1}

	vm := openVM(t, memdb.New(), ids.GenerateTestID(), weightedValidators(weights), nil)
	defer vm.Shutdown(ctx())

	set, err := vm.custodySet(ctx(), 0, 2)
	require.NoError(t, err)
	require.Len(t, set, 2)
	for _, r := range rich {
		require.Contains(t, set, party.ID(r.String()))
	}
	for _, p := range poor {
		require.NotContains(t, set, party.ID(p.String()),
			"a grindable id must not buy a seat that stake did not")
	}
	require.True(t, sortedUnique(set), "the set is hashed into the ceremony id, so it must be canonical")
}

// Ties break lexicographically, which is safe once stake has chosen the set:
// grinding an id then buys a position among peers whose stake you already had
// to match.
func TestEqualStakeBreaksTiesTotallyAndIdentically(t *testing.T) {
	nodes := []ids.NodeID{{1}, {2}, {3}, {4}}
	weights := map[ids.NodeID]uint64{}
	for _, n := range nodes {
		weights[n] = 5
	}
	vs := weightedValidators(weights)

	a := openVM(t, memdb.New(), ids.GenerateTestID(), vs, nil)
	b := openVM(t, memdb.New(), ids.GenerateTestID(), vs, nil)
	defer a.Shutdown(ctx())
	defer b.Shutdown(ctx())

	setA, err := a.custodySet(ctx(), 0, 3)
	require.NoError(t, err)
	setB, err := b.custodySet(ctx(), 0, 3)
	require.NoError(t, err)
	require.Equal(t, setA, setB, "every validator must derive the same custody set without negotiating one")
}

// A validator entry with no weight recorded counts as no stake rather than
// crashing the selection.
func TestAValidatorWithNoRecordedWeightHasNoStake(t *testing.T) {
	present, absent := ids.NodeID{9}, ids.NodeID{1}
	vs := &validatorstest.TestState{
		GetValidatorSetF: func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
			return map[ids.NodeID]*validators.GetValidatorOutput{
				present: {NodeID: present, Weight: 100},
				absent:  nil,
			}, nil
		},
	}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), vs, nil)
	defer vm.Shutdown(ctx())

	set, err := vm.custodySet(ctx(), 0, 1)
	require.NoError(t, err)
	require.Equal(t, []party.ID{party.ID(present.String())}, set)
}

// A policy that needs more parties than the chain has validators cannot be
// deployed, and says which number was short.
func TestAPolicyLargerThanTheValidatorSetIsRefused(t *testing.T) {
	node := ids.GenerateTestNodeID()
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), oneValidator(node), nil)
	defer vm.Shutdown(ctx())

	_, err := vm.custodySet(ctx(), 0, 5)
	require.ErrorIs(t, err, ErrPolicyTooLarge)
	require.ErrorContains(t, err, "validator set has 1")

	_, err = vm.StartKeygenWithPolicy(ctx(), "vault", quorum.MustNew(3, 5),
		authenticatedFor(vm, "B-Chain", true))
	require.ErrorIs(t, err, ErrPolicyTooLarge)
}

// The ceremony committee IS the validator set, in canonical order. There is no
// separate MPC roster to drift from it.
func TestTheCommitteeIsTheValidatorSetInCanonicalOrder(t *testing.T) {
	nodes := []ids.NodeID{{3}, {1}, {2}}
	weights := map[ids.NodeID]uint64{nodes[0]: 1, nodes[1]: 1, nodes[2]: 1}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), weightedValidators(weights), nil)
	defer vm.Shutdown(ctx())

	committee, err := vm.Committee(ctx(), 0)
	require.NoError(t, err)
	require.Len(t, committee, 3)
	require.True(t, sortedUnique(committee))
}

func TestANodeWithNoValidatorStateHasNoCommittee(t *testing.T) {
	vm := newVM(t)
	_, err := vm.Committee(ctx(), 0)
	require.ErrorIs(t, err, ErrNoCommittee)
	_, err = vm.custodySet(ctx(), 0, 1)
	require.ErrorIs(t, err, ErrNoCommittee)
}

func TestAnEmptyValidatorSetIsNoCommittee(t *testing.T) {
	vs := &validatorstest.TestState{
		GetValidatorSetF: func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
			return nil, nil
		},
	}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), vs, nil)
	defer vm.Shutdown(ctx())

	_, err := vm.Committee(ctx(), 0)
	require.ErrorIs(t, err, ErrNoCommittee)
}

func TestAnUnreadableValidatorSetIsNamedNotEmpty(t *testing.T) {
	vs := &validatorstest.TestState{
		GetValidatorSetF: func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
			return nil, errFaulty
		},
	}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), vs, nil)
	defer vm.Shutdown(ctx())

	_, err := vm.Committee(ctx(), 0)
	require.ErrorIs(t, err, errFaulty)
	_, err = vm.custodySet(ctx(), 0, 1)
	require.ErrorIs(t, err, errFaulty)
}

// -----------------------------------------------------------------------------
// Ceremonies this node cannot run
// -----------------------------------------------------------------------------

// A node outside the custody set does not run the keygen: it will verify the
// registration like any other validator when the block arrives.
func TestANodeOutsideTheCustodySetDoesNotRunTheKeygen(t *testing.T) {
	others := map[ids.NodeID]uint64{{7}: 10, {8}: 10, {9}: 10}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(), weightedValidators(others), nil)
	defer vm.Shutdown(ctx())

	_, err := vm.StartKeygenWithPolicy(ctx(), "vault", quorum.MustNew(2, 3),
		authenticatedFor(vm, "B-Chain", true))
	require.ErrorIs(t, err, ErrNotParticipant)
}

func TestAKeygenForAnAlreadyRegisteredKeyDoesNotRun(t *testing.T) {
	self, peer := ids.NodeID{1}, ids.NodeID{2}
	vm := openVM(t, memdb.New(), ids.GenerateTestID(),
		weightedValidators(map[ids.NodeID]uint64{self: 10, peer: 10}), nil)
	defer vm.Shutdown(ctx())
	vm.partyID = party.ID(self.String())

	key := newCustody(t, "vault", quorum.MustNew(3, 5), 110)
	key.register(t, vm)

	_, err := vm.StartKeygenWithPolicy(ctx(), "vault", quorum.MustNew(2, 2),
		authenticatedFor(vm, "B-Chain", true))
	require.ErrorIs(t, err, ErrKeyExists,
		"a key id is registered once; a second ceremony for it must not even start")
}

func TestAnUndeployablePolicyNeverStartsACeremony(t *testing.T) {
	vm := newVM(t)
	_, err := vm.StartKeygenWithPolicy(ctx(), "vault", quorum.Policy{K: 1, N: 1},
		authenticatedFor(vm, "B-Chain", true))
	require.ErrorContains(t, err, "undeployable policy")
}

// Signing needs a registered key, a share of it, and a place in this task's
// quorum — each refused by its own named error so an operator can tell an
// outage from normal operation.
func TestSigningRefusalsAreDistinguishable(t *testing.T) {
	vm := newVM(t)
	by := authenticatedFor(vm, "B-Chain", false)

	_, err := vm.RequestSignature(ctx(), by, "vault", digestOf(1))
	require.ErrorIs(t, err, ErrUnknownKey)

	key := newCustody(t, "vault", quorum.MustNew(3, 5), 111)
	key.register(t, vm)
	_, err = vm.RequestSignature(ctx(), by, "vault", digestOf(1))
	require.ErrorIs(t, err, ErrShareNotHeld)

	// It holds a share, but it is not a participant of this key at all.
	key.hold(vm, testShare(t, key.rec.GroupPublicKey, key.rec.Degree()))
	_, err = vm.RequestSignature(ctx(), by, "vault", digestOf(1))
	require.ErrorIs(t, err, ErrNotParticipant)

	// It is a participant, but not in this task's quorum — normal, and not an
	// error condition for the chain.
	vm.partyID = outsideQuorum(t, key.rec, digestOf(1))
	_, err = vm.RequestSignature(ctx(), by, "vault", digestOf(1))
	require.ErrorIs(t, err, ErrNotInQuorum)
}

// M-Chain signs the exact 32 bytes it is given and never re-hashes: the caller
// owns its signing domain, and a chain that re-hashed would produce signatures
// over a preimage nobody authorised.
func TestMChainSignsWhatItIsGivenAndOnlyThirtyTwoBytes(t *testing.T) {
	vm := newVM(t)
	by := authenticatedFor(vm, "B-Chain", false)
	for _, n := range []int{0, 31, 33} {
		_, err := vm.RequestSignature(ctx(), by, "vault", make([]byte, n))
		require.ErrorContainsf(t, err, "want 32", "a %d-byte digest must be refused", n)
	}
}

// A ceremony that has already been recorded is refused before it runs: asking
// again for the identical task is the identical ceremony, and recording it
// twice would double-count whatever it authorised.
func TestARecordedCeremonyIsNotRunAgain(t *testing.T) {
	vm := newVM(t)
	key := newCustody(t, "vault", quorum.MustNew(3, 5), 112)
	key.register(t, vm)
	key.hold(vm, testShare(t, key.rec.GroupPublicKey, key.rec.Degree()))

	digest := digestOf(1)
	op := key.signOpOver(t, digest)
	blk := blockOver(t, vm, op)
	require.NoError(t, blk.Verify(ctx()))
	require.NoError(t, blk.Accept(ctx()))

	vm.partyID = quorumFor(key.rec, digest)[0]
	_, err := vm.RequestSignature(ctx(), authenticatedFor(vm, "B-Chain", false), "vault", digest)
	require.ErrorIs(t, err, ErrCeremonyExists)
}

// A share that cannot sign is not a share: the signing path refuses an empty
// one rather than producing an artifact nothing verifies.
func TestAnEmptyShareSignsNothing(t *testing.T) {
	vm := newVM(t)
	rec := sampleKeyRecord()
	_, err := vm.thresholdSign(ctx(), rec, nil, digestOf(1), parties(3))
	require.ErrorIs(t, err, ErrShareNotHeld)
	_, err = vm.thresholdSign(ctx(), rec, &heldShare{}, digestOf(1), parties(3))
	require.ErrorIs(t, err, ErrShareNotHeld)

	_, _, err = (&heldShare{}).groupKeyAndDegree()
	require.ErrorContains(t, err, "empty share")
	_, _, err = (*heldShare)(nil).groupKeyAndDegree()
	require.ErrorContains(t, err, "empty share")
	_, err = (&heldShare{}).marshal()
	require.ErrorContains(t, err, "no share to store")
}

// A share of a protocol this chain does not run is refused rather than decoded
// on a guessed curve: the stored encoding holds curve points as bare bytes, so
// decoding it on the wrong curve is decoding the wrong key.
func TestAShareOfAnotherProtocolIsRefused(t *testing.T) {
	raw, _, _ := realShare(t)
	_, err := parseHeldShare("frost", raw)
	require.ErrorContains(t, err, "unknown protocol")

	got, err := parseHeldShare(KindCGGMP21, raw)
	require.NoError(t, err)
	require.Equal(t, KindCGGMP21, got.kind)
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func weightedValidators(weights map[ids.NodeID]uint64) *validatorstest.TestState {
	return &validatorstest.TestState{
		GetValidatorSetF: func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
			out := make(map[ids.NodeID]*validators.GetValidatorOutput, len(weights))
			for n, w := range weights {
				out[n] = &validators.GetValidatorOutput{NodeID: n, Weight: w}
			}
			return out, nil
		},
	}
}

// authenticatedFor is the Caller the transport would produce for a chain with
// the right named to it.
func authenticatedFor(vm *VM, name string, keygen bool) Caller {
	return Caller{name: name, perms: &ChainPermissions{ChainID: name, CanSign: true, CanKeygen: keygen}}
}

// outsideQuorum names a participant of rec that this task did NOT select.
func outsideQuorum(t *testing.T, rec *KeyRecord, digest []byte) party.ID {
	t.Helper()
	chosen := quorumFor(rec, digest)
	for _, p := range rec.Participants {
		if !containsParty(chosen, p) {
			return p
		}
	}
	t.Fatal("every participant is in the quorum; the policy leaves nobody out")
	return ""
}
