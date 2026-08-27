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
	w := newWorld(t, 3, runcOnly, Require(ReplicaOne, SpreadHost))
	op := w.ops[0].addr()
	good := Advertisement{
		Mechanisms: runcOnly, Storage: Require(ReplicaOne, SpreadHost),
		Placement: PlacementLocal, Domain: h(0xD1), Catalog: w.cat,
		Groups: []common.Hash{w.group}, Capacity: 2,
	}
	require.NoError(t, w.e.Advertise(w.st, op, good))

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
		"execution as storage": {func(a Advertisement) Advertisement {
			a.Storage = Require(SyscallMediated)
			return a
		}, ErrAdvertiseStorage},
		"two on one storage axis": {func(a Advertisement) Advertisement {
			a.Storage = Require(ReplicaOne, ReplicaMany)
			return a
		}, ErrAdvertiseStorage},
	}
	for name, c := range cases {
		require.ErrorIs(t, w.e.Advertise(w.st, op, c.mangle(good)), c.want, name)
	}

	// An address with no bond has nothing to say.
	require.ErrorIs(t, w.e.Advertise(w.st, common.HexToAddress("0xbeef"), good), ErrOperatorUnknown)
}
