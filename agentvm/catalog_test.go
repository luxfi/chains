// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package agentvm

import (
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/aivm"
)

func TestCatalogDigestIsOverTheWholeSurface(t *testing.T) {
	base := testCatalog()
	require.Equal(t, base.Digest(), testCatalog().Digest())

	edits := map[string]func(Catalog) Catalog{
		"version":      func(c Catalog) Catalog { c.Version = 2; return c },
		"group name":   func(c Catalog) Catalog { c.Groups[0].Name = "ml"; return c },
		"group digest": func(c Catalog) Catalog { c.Groups[0].Digest = h(0xB1); return c },
		"path count":   func(c Catalog) Catalog { c.Groups[0].Paths = 93; return c },
		"op count":     func(c Catalog) Catalog { c.Groups[0].Ops = 147; return c },
		"a new group": func(c Catalog) Catalog {
			c.Groups = append(c.Groups, Group{Name: "zoo", Paths: 1, Ops: 1, Digest: h(0xB9)})
			return c
		},
	}
	for name, edit := range edits {
		require.NotEqual(t, base.Digest(), edit(testCatalog()).Digest(), name)
	}

	require.Equal(t, uint32(153), base.Paths())
	require.Equal(t, uint32(238), base.Ops())
}

func TestCatalogValidate(t *testing.T) {
	require.NoError(t, testCatalog().Validate())

	cases := map[string]struct {
		mangle func(Catalog) Catalog
		want   error
	}{
		"zero version": {func(c Catalog) Catalog { c.Version = 0; return c }, ErrCatalogVersion},
		"no groups":    {func(c Catalog) Catalog { c.Groups = nil; return c }, ErrCatalogGroups},
		"unsorted": {func(c Catalog) Catalog {
			c.Groups[0], c.Groups[1] = c.Groups[1], c.Groups[0]
			return c
		}, ErrCatalogGroups},
		"duplicate": {func(c Catalog) Catalog {
			c.Groups[1].Name = c.Groups[0].Name
			return c
		}, ErrCatalogGroups},
		"unnamed group": {func(c Catalog) Catalog { c.Groups[0].Name = ""; return c }, ErrCatalogGroups},
		"empty group":   {func(c Catalog) Catalog { c.Groups[0].Ops = 0; return c }, ErrCatalogGroups},
		"no digest": {func(c Catalog) Catalog {
			c.Groups[0].Digest = common.Hash{}
			return c
		}, ErrCatalogGroups},
	}
	for name, c := range cases {
		require.ErrorIs(t, c.mangle(testCatalog()).Validate(), c.want, name)
	}
}

// TestCatalogVersionIsWrittenOnce: a version number is what a workload was
// written against, so re-registering a different surface under it would change
// what every one of those workloads asked for.
func TestCatalogVersionIsWrittenOnce(t *testing.T) {
	e := New(aivm.NewEngine(h(0xC1), h(0xA0)))
	st := aivm.NewMemState()

	digest, err := e.RegisterCatalog(st, testCatalog())
	require.NoError(t, err)
	require.True(t, e.CatalogKnown(st, digest))
	require.Equal(t, digest, e.CatalogAt(st, 1))

	// Registering the identical surface again is the same surface, not a
	// conflict.
	again, err := e.RegisterCatalog(st, testCatalog())
	require.NoError(t, err)
	require.Equal(t, digest, again)

	// A different surface under the same version is refused.
	changed := testCatalog()
	changed.Groups[0].Ops = 999
	_, err = e.RegisterCatalog(st, changed)
	require.ErrorIs(t, err, ErrCatalogVersionTaken)

	// The next version is how a surface changes.
	changed.Version = 2
	v2, err := e.RegisterCatalog(st, changed)
	require.NoError(t, err)
	require.NotEqual(t, digest, v2)
	require.True(t, e.CatalogKnown(st, v2))
	require.Equal(t, digest, e.CatalogAt(st, 1), "version 1 still means what it meant")
}

func TestCatalogHoldsOnlyItsOwnGroups(t *testing.T) {
	e := New(aivm.NewEngine(h(0xC1), h(0xA0)))
	st := aivm.NewMemState()
	digest, err := e.RegisterCatalog(st, testCatalog())
	require.NoError(t, err)

	require.True(t, e.CatalogHolds(st, digest, GroupID("ai")))
	require.True(t, e.CatalogHolds(st, digest, GroupID("iam")))
	require.False(t, e.CatalogHolds(st, digest, GroupID("commerce")))
	require.False(t, e.CatalogHolds(st, h(0xEE), GroupID("ai")), "an unregistered catalog holds nothing")
	require.False(t, e.CatalogKnown(st, h(0xEE)))
	require.Equal(t, common.Hash{}, e.CatalogAt(st, 9))
}

// TestGroupIDIsStable: the on-chain name of a group is a pure function of its
// textual name, so a workload and an advertisement agree without coordinating.
func TestGroupIDIsStable(t *testing.T) {
	require.Equal(t, GroupID("ai"), GroupID("ai"))
	require.NotEqual(t, GroupID("ai"), GroupID("iam"))
	require.Equal(t, GroupID("ai"), Group{Name: "ai"}.ID())
	require.NotEqual(t, common.Hash{}, GroupID(""))
}

// TestAdvertiseRefusesWhatTheCatalogDoesNotDefine: an operator cannot offer a
// group no surface holds, and cannot advertise at all without a bond.
func TestAdvertiseIsCheckedAgainstTheCatalog(t *testing.T) {
	w := newWorld(t, 3, runcOnly)
	self := w.ops[0]
	op := self.addr()

	sign := func(a Advertisement) Advertisement {
		require.NoError(t, a.Authorize(op, self))
		return a
	}
	good := sign(Advertisement{
		Mechanisms: runcOnly, Placement: PlacementLocal, Domain: h(0xD1), Catalog: w.cat,
		Groups: []common.Hash{w.group}, Capacity: 2, Nonce: 9,
	})
	require.NoError(t, w.e.Advertise(w.st, op, good))

	base := func() Advertisement {
		a := good
		a.Nonce = 10
		return a
	}
	cases := map[string]struct {
		mangle func(Advertisement) Advertisement
		want   error
	}{
		"no mechanism":    {func(a Advertisement) Advertisement { a.Mechanisms = 0; return a }, ErrAdvertiseMechanisms},
		"no placement":    {func(a Advertisement) Advertisement { a.Placement = PlacementAny; return a }, ErrAdvertisePlacement},
		"no domain":       {func(a Advertisement) Advertisement { a.Domain = common.Hash{}; return a }, ErrAdvertiseDomain},
		"no capacity":     {func(a Advertisement) Advertisement { a.Capacity = 0; return a }, ErrAdvertiseCapacity},
		"huge capacity":   {func(a Advertisement) Advertisement { a.Capacity = MaxCapacity + 1; return a }, ErrAdvertiseCapacity},
		"unknown catalog": {func(a Advertisement) Advertisement { a.Catalog = h(0xEE); return a }, ErrCatalogUnknown},
		"no groups":       {func(a Advertisement) Advertisement { a.Groups = nil; return a }, ErrAdvertiseGroups},
		"undefined group": {func(a Advertisement) Advertisement { a.Groups = []common.Hash{GroupID("nope")}; return a }, ErrAdvertiseGroups},
	}
	for name, c := range cases {
		require.ErrorIs(t, w.e.Advertise(w.st, op, sign(c.mangle(base()))), c.want, name)
	}

	// An address with no bond has nothing to say.
	require.ErrorIs(t, w.e.Advertise(w.st, common.HexToAddress("0xbeef"), good), ErrOperatorUnknown)
}

// TestAdvertiseIsTheOperatorsOwn: an advertisement is a statement about a bonded
// identity, so only that identity can make it. Anyone may deliver one; nobody
// else can write one.
func TestAdvertiseIsTheOperatorsOwn(t *testing.T) {
	w := newWorld(t, 3, runcOnly)
	victim, attacker := w.ops[0], w.ops[1]

	forged := Advertisement{
		Mechanisms: runcOnly, Placement: PlacementLocal,
		Domain:  w.e.DomainOf(w.st, attacker.addr()), // collapse the victim into the attacker's domain
		Catalog: w.cat, Groups: []common.Hash{w.group}, Capacity: 1, Nonce: 5,
	}
	// Unsigned.
	require.ErrorIs(t, w.e.Advertise(w.st, victim.addr(), forged), ErrAdvertiseUnauthorized)
	// Signed by the attacker, submitted as the victim.
	require.NoError(t, forged.Authorize(victim.addr(), attacker))
	require.ErrorIs(t, w.e.Advertise(w.st, victim.addr(), forged), ErrAdvertiseUnauthorized)

	// The victim's own advertisement is untouched.
	require.Equal(t, w.domains[0], w.e.DomainOf(w.st, victim.addr()))
	advertised, _ := w.e.Capacity(w.st, victim.addr())
	require.Equal(t, uint32(4), advertised)

	// The victim can still speak for itself.
	require.NoError(t, w.advertise(t, victim, 2, func(a *Advertisement) { a.Capacity = 7 }))
	advertised, _ = w.e.Capacity(w.st, victim.addr())
	require.Equal(t, uint32(7), advertised)
}

// TestAdvertiseRefusesAReplay: a signature alone stops forgery but not a replay
// of the operator's own older advertisement, which would put it back into a state
// it has left. The nonce must move forward.
func TestAdvertiseRefusesAReplay(t *testing.T) {
	w := newWorld(t, 3, runcOnly)
	op := w.ops[0]

	require.NoError(t, w.advertise(t, op, 5, func(a *Advertisement) { a.Capacity = 9 }))
	advertised, _ := w.e.Capacity(w.st, op.addr())
	require.Equal(t, uint32(9), advertised)

	// The advertisement it made at nonce 1 in newWorld is genuinely signed and
	// would collapse its capacity back to 4. Replaying it is refused.
	require.ErrorIs(t, w.advertise(t, op, 1, nil), ErrAdvertiseReplay)
	require.ErrorIs(t, w.advertise(t, op, 5, nil), ErrAdvertiseReplay, "the same nonce twice is a replay")

	advertised, _ = w.e.Capacity(w.st, op.addr())
	require.Equal(t, uint32(9), advertised, "a refused advertisement changes nothing")

	require.NoError(t, w.advertise(t, op, 6, func(a *Advertisement) { a.Capacity = 3 }))
	advertised, _ = w.e.Capacity(w.st, op.addr())
	require.Equal(t, uint32(3), advertised)
}

// TestAdvertiseDigestBindsEveryField: the signature must not carry from one offer
// to another, including to the same offer made for a different operator.
func TestAdvertiseDigestBindsEveryField(t *testing.T) {
	a := Advertisement{
		Mechanisms: runcOnly, Placement: PlacementLocal, Domain: h(1),
		Catalog: h(2), Groups: []common.Hash{h(3)}, Capacity: 4, Nonce: 5,
	}
	op, other := common.HexToAddress("0x01"), common.HexToAddress("0x02")
	base := a.Digest(op)

	require.NotEqual(t, base, a.Digest(other), "the subject is bound")
	edits := map[string]func(Advertisement) Advertisement{
		"mechanisms": func(x Advertisement) Advertisement { x.Mechanisms = Offer(MechanismGVisor); return x },
		"placement":  func(x Advertisement) Advertisement { x.Placement = PlacementCluster; return x },
		"domain":     func(x Advertisement) Advertisement { x.Domain = h(9); return x },
		"catalog":    func(x Advertisement) Advertisement { x.Catalog = h(9); return x },
		"groups":     func(x Advertisement) Advertisement { x.Groups = []common.Hash{h(9)}; return x },
		"group count": func(x Advertisement) Advertisement {
			x.Groups = []common.Hash{h(3), h(4)}
			return x
		},
		"capacity": func(x Advertisement) Advertisement { x.Capacity = 5; return x },
		"nonce":    func(x Advertisement) Advertisement { x.Nonce = 6; return x },
	}
	for name, edit := range edits {
		require.NotEqual(t, base, edit(a).Digest(op), name)
	}
}
