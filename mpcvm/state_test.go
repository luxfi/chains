// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// state_test.go — the line between what is replicated and what is not, and the
// root that says two validators agree.

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
)

func newState(t *testing.T) (*State, database.Database) {
	t.Helper()
	db := memdb.New()
	s, err := NewState(db, ids.GenerateTestID())
	require.NoError(t, err)
	return s, db
}

// -----------------------------------------------------------------------------
// The two keyspaces
// -----------------------------------------------------------------------------

// A secret never reaches consensus state. The share prefix and the replicated
// prefixes are disjoint by construction, and Root() folds only operation
// digests — never a stored value — so the question "could a secret have got
// into the root" is answered by reading the three Put methods rather than by
// auditing the whole VM.
func TestASecretNeverEntersReplicatedState(t *testing.T) {
	s, db := newState(t)
	secret := []byte("this is a private key share")
	require.NoError(t, s.PutShare("vault", secret))

	it := db.NewIteratorWithPrefix([]byte("c/"))
	defer it.Release()
	for it.Next() {
		require.NotContains(t, string(it.Value()), string(secret),
			"a secret appeared under the replicated prefix %q", it.Key())
	}
	require.NoError(t, it.Error())

	// And the share is where it belongs, readable only by this node.
	got, err := s.GetShare("vault")
	require.NoError(t, err)
	require.Equal(t, secret, got)

	held, err := s.HasShare("vault")
	require.NoError(t, err)
	require.True(t, held)

	absent, err := s.HasShare("nothing-here")
	require.NoError(t, err)
	require.False(t, absent)
}

// A node that holds no share for a key says so with a named error, so a caller
// can tell "not a participant" (normal) from "the store is broken".
func TestNotHoldingAShareIsNamedNotGuessed(t *testing.T) {
	s, _ := newState(t)
	_, err := s.GetShare("vault")
	require.ErrorIs(t, err, ErrShareNotHeld)
}

// An empty share is refused rather than stored. A stored empty share reads back
// as "this node participates" while being unable to contribute anything.
func TestAnEmptyShareIsRefused(t *testing.T) {
	s, _ := newState(t)
	require.Error(t, s.PutShare("vault", nil))
	require.Error(t, s.PutShare("vault", []byte{}))
	held, err := s.HasShare("vault")
	require.NoError(t, err)
	require.False(t, held)
}

// -----------------------------------------------------------------------------
// The registry
// -----------------------------------------------------------------------------

// A key id is a permanent binding to a group public key. Rebinding it would
// redirect custody of live funds, so registration happens once and PutKey is
// the only writer.
func TestAKeyIdBindsToOnePublicKeyForever(t *testing.T) {
	s, _ := newState(t)
	a := sampleKeyRecord()
	require.NoError(t, s.PutKey(a))

	b := sampleKeyRecord()
	b.GroupPublicKey = flip(b.GroupPublicKey)
	require.ErrorIs(t, s.PutKey(b), ErrKeyExists)

	got, err := s.GetKey(a.KeyID)
	require.NoError(t, err)
	require.Equal(t, a.GroupPublicKey, got.GroupPublicKey)
}

func TestAnUnregisteredKeyIsNamedNotEmpty(t *testing.T) {
	s, _ := newState(t)
	_, err := s.GetKey("nothing")
	require.ErrorIs(t, err, ErrUnknownKey)

	has, err := s.HasKey("nothing")
	require.NoError(t, err)
	require.False(t, has)
}

func TestAMalformedRecordNeverReachesTheRegistry(t *testing.T) {
	s, _ := newState(t)
	bad := sampleKeyRecord()
	bad.GroupPublicKey = bad.GroupPublicKey[:32]
	require.Error(t, s.PutKey(bad))

	has, err := s.HasKey(bad.KeyID)
	require.NoError(t, err)
	require.False(t, has, "a record that failed validation must not be on disk")
}

func TestTheRegistryListsWhatWasRegistered(t *testing.T) {
	s, _ := newState(t)
	keys, err := s.Keys()
	require.NoError(t, err)
	require.Empty(t, keys)

	for _, id := range []string{"b", "a", "c"} {
		rec := sampleKeyRecord()
		rec.KeyID = id
		require.NoError(t, s.PutKey(rec))
	}
	keys, err = s.Keys()
	require.NoError(t, err)
	require.Len(t, keys, 3)
	require.Equal(t, []string{"a", "b", "c"}, []string{keys[0].KeyID, keys[1].KeyID, keys[2].KeyID},
		"the registry is enumerated in key-id order, so two validators list it identically")
}

// -----------------------------------------------------------------------------
// KeyRecord validity — every field a later signature check trusts
// -----------------------------------------------------------------------------

func TestARecordThatALaterCheckWouldTrustIsValidatedFirst(t *testing.T) {
	for name, mangle := range map[string]func(*KeyRecord){
		"no id":                     func(r *KeyRecord) { r.KeyID = "" },
		"no protocol":               func(r *KeyRecord) { r.Kind = "" },
		"undeployable policy":       func(r *KeyRecord) { r.Policy = quorum.Policy{} },
		"one signer":                func(r *KeyRecord) { r.Policy = quorum.Policy{K: 1, N: 3} },
		"two disjoint quorums":      func(r *KeyRecord) { r.Policy = quorum.MustNew(2, 5); r.Participants = parties(5) },
		"too few participants":      func(r *KeyRecord) { r.Participants = r.Participants[:1] },
		"unsorted participants":     func(r *KeyRecord) { r.Participants = []party.ID{"p3", "p1", "p2"} },
		"repeated participant":      func(r *KeyRecord) { r.Participants = []party.ID{"p1", "p1", "p2"} },
		"uncompressed group key":    func(r *KeyRecord) { r.GroupPublicKey = make([]byte, 65) },
		"short address":             func(r *KeyRecord) { r.Address = make([]byte, 19) },
		"a generation it never had": func(r *KeyRecord) { r.Generation = 1 },
	} {
		rec := sampleKeyRecord()
		mangle(rec)
		require.Errorf(t, rec.Validate(), "%s must not validate", name)
	}
	require.NoError(t, sampleKeyRecord().Validate())
}

// The custody floor: a policy admitting two disjoint quorums lets two halves of
// the committee authorise contradictory releases of the same funds, so
// possession of a signature stops implying the committee authorised anything.
//
// CGGMP21 is unforgeable at any of these; this is a custody policy, not a
// soundness requirement, and it is enforced where the record enters state.
func TestAPolicyWithTwoDisjointQuorumsIsNotDeployableHere(t *testing.T) {
	for _, tc := range []struct {
		k, n int
		want bool
	}{
		{2, 2, true}, {2, 3, true}, {2, 4, false}, {2, 5, false},
		{3, 4, true}, {3, 5, true}, {3, 6, false}, {3, 7, false},
		{4, 5, true}, {4, 7, true}, {5, 7, true}, {7, 7, true},
	} {
		rec := sampleKeyRecord()
		rec.Policy = quorum.MustNew(tc.k, tc.n)
		rec.Participants = parties(tc.n)
		err := rec.Validate()
		if tc.want {
			require.NoErrorf(t, err, "%d-of-%d has a unique quorum and must be deployable", tc.k, tc.n)
		} else {
			require.Errorf(t, err, "%d-of-%d admits two disjoint quorums and must be refused", tc.k, tc.n)
		}
	}
}

// The degree is derived at one place, never stored beside the policy. Two
// stored numbers can disagree; one cannot.
func TestTheDegreeIsAlwaysOneBelowTheSignerCount(t *testing.T) {
	for n := 2; n <= 7; n++ {
		for k := 2; k <= n; k++ {
			rec := sampleKeyRecord()
			rec.Policy = quorum.MustNew(k, n)
			require.Equalf(t, k-1, rec.Degree(), "%d-of-%d", k, n)
		}
	}
}

// -----------------------------------------------------------------------------
// The ceremony log
// -----------------------------------------------------------------------------

func TestACeremonyIsRecordedOnce(t *testing.T) {
	s, _ := newState(t)
	rec := &CeremonyRecord{ID: "mpc/one", Kind: OpTypeSign, KeyID: "vault"}
	require.NoError(t, s.PutCeremony(rec))
	require.ErrorIs(t, s.PutCeremony(rec), ErrCeremonyExists,
		"recording a ceremony twice double-counts whatever it authorised")

	require.Error(t, s.PutCeremony(&CeremonyRecord{}), "a ceremony with no id has no primary key")

	got, err := s.GetCeremony("mpc/one")
	require.NoError(t, err)
	require.Equal(t, rec.KeyID, got.KeyID)

	_, err = s.GetCeremony("mpc/never")
	require.Error(t, err)

	all, err := s.Ceremonies()
	require.NoError(t, err)
	require.Len(t, all, 1)
}

// -----------------------------------------------------------------------------
// The root
// -----------------------------------------------------------------------------

// Two chains running identical operations must not reach identical roots, or a
// block built on one applies to the other.
func TestTheGenesisRootIsPerChain(t *testing.T) {
	a, b := ids.GenerateTestID(), ids.GenerateTestID()
	require.NotEqual(t, genesisRoot(a), genesisRoot(b))
	require.Equal(t, genesisRoot(a), genesisRoot(a))
}

// The root is a hash chain over applied operations, so it depends on both the
// set and the order.
func TestTheRootDependsOnWhatWasAppliedAndInWhatOrder(t *testing.T) {
	base := genesisRoot(ids.GenerateTestID())
	x, y := [32]byte{1}, [32]byte{2}

	require.NotEqual(t, advance(base, x), advance(base, y))
	require.NotEqual(t, advance(advance(base, x), y), advance(advance(base, y), x),
		"a root that ignored order would let two validators apply the same operations differently")
	require.Equal(t, advance(base, x), advance(base, x))
	require.NotEqual(t, base, advance(base, x))
}

// A root read back from disk is the one that was committed, and a root that is
// not 32 bytes is a corrupted store rather than a value to copy into.
func TestARootIsEitherThirtyTwoBytesOrAnError(t *testing.T) {
	s, db := newState(t)
	moved := advance(s.Root(), [32]byte{9})
	require.NoError(t, s.WriteRoot(moved))
	require.NotEqual(t, moved, s.Root(), "WriteRoot stages; it does not publish")

	s.HoldRoot(moved)
	require.Equal(t, moved, s.Root())

	require.NoError(t, s.ReadRoot())
	require.Equal(t, moved, s.Root())

	require.NoError(t, db.Put(keyRoot, []byte{1, 2, 3}))
	require.Error(t, s.ReadRoot())

	_, err := NewState(db, ids.GenerateTestID())
	require.Error(t, err, "a store whose root is not 32 bytes must not open")
}

// Opening state twice on the same database resumes; it does not re-seed.
func TestReopeningStateResumesRatherThanReseeding(t *testing.T) {
	db := memdb.New()
	chainID := ids.GenerateTestID()

	first, err := NewState(db, chainID)
	require.NoError(t, err)
	moved := advance(first.Root(), [32]byte{7})
	require.NoError(t, first.WriteRoot(moved))

	second, err := NewState(db, chainID)
	require.NoError(t, err)
	require.Equal(t, moved, second.Root())

	// Even under a different chain id: what is on disk wins over what the
	// caller says the chain is.
	third, err := NewState(db, ids.GenerateTestID())
	require.NoError(t, err)
	require.Equal(t, moved, third.Root())
}

// A read fault on the root is an error, not an empty chain.
func TestAnUnreadableRootIsAFaultNotAFreshChain(t *testing.T) {
	db := &faultyDB{Database: memdb.New()}
	db.failGet = keyRoot
	_, err := NewState(db, ids.GenerateTestID())
	require.ErrorIs(t, err, errFaulty)
}

func TestASeedThatCannotBeWrittenFailsLoudly(t *testing.T) {
	db := &faultyDB{Database: memdb.New()}
	db.failPut = keyRoot
	_, err := NewState(db, ids.GenerateTestID())
	require.ErrorIs(t, err, errFaulty)
}

// -----------------------------------------------------------------------------
// Canonical hashing
// -----------------------------------------------------------------------------

// Every variable-length field is length-prefixed before hashing. Without it,
// ("ab","c") and ("a","bc") hash identically, and a ceremony id could be forged
// by moving a byte between the key id and the digest.
func TestMovingAByteBetweenFieldsChangesTheHash(t *testing.T) {
	require.NotEqual(t,
		keygenCeremonyID("ab", quorum.MustNew(2, 3), parties(3)),
		keygenCeremonyID("a", quorum.MustNew(2, 3), parties(3)))

	// The same split, in the signing id, where the key id is caller-chosen.
	d := digestOf(1)
	require.NotEqual(t,
		ceremonyID("ab", d, parties(3)),
		ceremonyID("a", append([]byte("b"), d[:31]...), parties(3)))

	// And in the participant list, where an id could otherwise absorb its
	// neighbour.
	require.NotEqual(t,
		keygenCeremonyID("k", quorum.MustNew(2, 3), []party.ID{"ab", "c", "d"}),
		keygenCeremonyID("k", quorum.MustNew(2, 3), []party.ID{"a", "bc", "d"}))
}

// A key commitment binds everything a signature check later trusts, so a
// proposer cannot register a key under a policy or a committee other than the
// one the ceremony ran with and still produce a verifying proof.
func TestTheKeyCommitmentBindsEveryFieldASignatureCheckTrusts(t *testing.T) {
	base := KeyCommitDigest(sampleKeyRecord())
	for name, mangle := range map[string]func(*KeyRecord){
		"key id":       func(r *KeyRecord) { r.KeyID = "elsewhere" },
		"protocol":     func(r *KeyRecord) { r.Kind = "frost" },
		"signer count": func(r *KeyRecord) { r.Policy = quorum.MustNew(3, 3) },
		"party count":  func(r *KeyRecord) { r.Policy = quorum.MustNew(2, 5) },
		"committee":    func(r *KeyRecord) { r.Participants = []party.ID{"q1", "q2", "q3"} },
		"group key":    func(r *KeyRecord) { r.GroupPublicKey = flip(r.GroupPublicKey) },
		"generation":   func(r *KeyRecord) { r.Generation = 1 },
	} {
		rec := sampleKeyRecord()
		mangle(rec)
		require.NotEqualf(t, base, KeyCommitDigest(rec), "%s is not bound by the commitment", name)
	}

	// The address is NOT in the commitment — it is derived from the group key
	// and recomputed by Verify, so committing to it too would be two sources
	// for one fact.
	rec := sampleKeyRecord()
	rec.Address = make([]byte, 20)
	require.Equal(t, base, KeyCommitDigest(rec))
}

func TestACanonicalPartySetIsSortedAndDeduplicated(t *testing.T) {
	require.Equal(t, []party.ID{"a", "b", "c"}, canonicalParties([]party.ID{"c", "a", "b", "a", "c"}))
	require.Empty(t, canonicalParties(nil))

	require.True(t, sortedUnique(nil))
	require.True(t, sortedUnique([]party.ID{"a"}))
	require.True(t, sortedUnique([]party.ID{"a", "b"}))
	require.False(t, sortedUnique([]party.ID{"b", "a"}))
	require.False(t, sortedUnique([]party.ID{"a", "a"}))
}

// samePartySet compares sets, and refuses a non-canonical side rather than
// silently treating a repeated name as a distinct member.
func TestSamePartySetRefusesANonCanonicalSide(t *testing.T) {
	require.True(t, samePartySet(nil, nil))
	require.True(t, samePartySet([]party.ID{"a", "b"}, []party.ID{"a", "b"}))
	require.False(t, samePartySet([]party.ID{"a"}, []party.ID{"a", "b"}))
	require.False(t, samePartySet([]party.ID{"a", "c"}, []party.ID{"a", "b"}))
	require.False(t, samePartySet([]party.ID{"b", "a"}, []party.ID{"b", "a"}),
		"two equal unsorted lists are still not a canonical set")
	require.False(t, samePartySet([]party.ID{"a", "a"}, []party.ID{"a", "a"}))
}

// -----------------------------------------------------------------------------
// a database that can be made to fail one key
// -----------------------------------------------------------------------------

var errFaulty = errors.New("read fault")

type faultyDB struct {
	database.Database
	failGet []byte
	failPut []byte
}

func (d *faultyDB) Get(k []byte) ([]byte, error) {
	if d.failGet != nil && string(k) == string(d.failGet) {
		return nil, errFaulty
	}
	return d.Database.Get(k)
}

func (d *faultyDB) Put(k, v []byte) error {
	if d.failPut != nil && string(k) == string(d.failPut) {
		return errFaulty
	}
	return d.Database.Put(k, v)
}

func (d *faultyDB) Has(k []byte) (bool, error) {
	if d.failGet != nil && string(k) == string(d.failGet) {
		return false, errFaulty
	}
	return d.Database.Has(k)
}
