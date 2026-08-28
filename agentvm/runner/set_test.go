// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package runner

import (
	"context"
	"testing"

	"github.com/luxfi/geth/common"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/agentvm"
)

// stub stands in for a real runner. Selection is a pure function of a runner's
// mechanism and placement, so a stub exercises exactly the code a real one would.
type stub struct {
	mech  agentvm.Mechanism
	place agentvm.Placement
	ran   bool
}

func (s *stub) Mechanism() agentvm.Mechanism { return s.mech }
func (s *stub) Placement() agentvm.Placement { return s.place }

func (s *stub) Run(context.Context, agentvm.Workload, []byte) (Result, error) {
	s.ran = true
	return Result{Output: []byte("x"), Observed: agentvm.Witness{Serves: s.mech}}, nil
}

func local(m agentvm.Mechanism) *stub { return &stub{mech: m, place: agentvm.PlacementLocal} }

func demand(ps ...agentvm.Property) agentvm.Workload {
	return agentvm.Workload{Demand: agentvm.Require(ps...), Placement: agentvm.PlacementAny}
}

// TestNoSilentDowngrade is the rule the whole runner layer turns on. A host that
// can only run containers, asked for a user-space kernel, must return nothing —
// not its container runner with a note that it is close. There is no ordering
// here to slide down, so an unmet demand is simply unmet.
func TestNoSilentDowngrade(t *testing.T) {
	runc := local(agentvm.MechanismRunc)
	set := New(runc)

	got, err := set.For(demand(agentvm.SyscallMediated))
	require.ErrorIs(t, err, ErrNoMechanism)
	require.Nil(t, got)
	require.False(t, runc.ran, "a runner that does not serve the demand is never run")

	// The same set serves what runc actually grants.
	got, err = set.For(demand(agentvm.SyscallFiltered, agentvm.KernelShared))
	require.NoError(t, err)
	require.Equal(t, agentvm.Mechanism(agentvm.MechanismRunc), got.Mechanism())
}

// TestAbsentMechanismNeverEntersTheMatch: when runsc is not installed the gVisor
// runner is not constructed, so it is not in the set. Adding it back is the only
// thing that makes a mediated demand serviceable.
func TestAbsentMechanismNeverEntersTheMatch(t *testing.T) {
	withoutGvisor := New(local(agentvm.MechanismPlain), local(agentvm.MechanismRunc))
	_, err := withoutGvisor.For(demand(agentvm.SyscallMediated))
	require.ErrorIs(t, err, ErrNoMechanism)

	withGvisor := New(local(agentvm.MechanismPlain), local(agentvm.MechanismRunc), local(agentvm.MechanismGVisor))
	got, err := withGvisor.For(demand(agentvm.SyscallMediated))
	require.NoError(t, err)
	require.Equal(t, agentvm.Mechanism(agentvm.MechanismGVisor), got.Mechanism())
}

// TestNoUpgradeEither: gVisor is not a stronger runc. A demand for a seccomp
// filter is not served by a sentry, because they are different values on one
// axis and neither contains the other.
func TestNoUpgradeEither(t *testing.T) {
	set := New(local(agentvm.MechanismGVisor))
	_, err := set.For(demand(agentvm.SyscallFiltered))
	require.ErrorIs(t, err, ErrNoMechanism)

	// Nor does a microVM serve a demand for mediation, or gVisor a demand for a
	// guest kernel: the two rows do not contain each other.
	_, err = New(local(agentvm.MechanismFirecracker)).For(demand(agentvm.SyscallMediated))
	require.ErrorIs(t, err, ErrNoMechanism)
	_, err = New(local(agentvm.MechanismGVisor)).For(demand(agentvm.KernelGuest))
	require.ErrorIs(t, err, ErrNoMechanism)
}

// TestSelectionIsStable: a host offering several runners answers the same way
// every time, so a fleet does not drift between mechanisms run to run.
func TestSelectionIsStable(t *testing.T) {
	set := New(local(agentvm.MechanismRunc), local(agentvm.MechanismFirecracker), local(agentvm.MechanismTEE))
	for i := 0; i < 16; i++ {
		got, err := set.For(demand(agentvm.KernelGuest))
		require.NoError(t, err)
		require.Equal(t, agentvm.Mechanism(agentvm.MechanismFirecracker), got.Mechanism())
	}
}

// TestPlacementFiltersWithoutRanking: a workload that names a place is served
// only there, and one that names none is served anywhere.
func TestPlacementFiltersWithoutRanking(t *testing.T) {
	here := &stub{mech: agentvm.MechanismRunc, place: agentvm.PlacementLocal}
	cluster := &stub{mech: agentvm.MechanismRunc, place: agentvm.PlacementCluster}
	set := New(here, cluster)

	w := demand(agentvm.SyscallFiltered)
	w.Placement = agentvm.PlacementCluster
	got, err := set.For(w)
	require.NoError(t, err)
	require.Equal(t, agentvm.PlacementCluster, got.Placement())

	w.Placement = agentvm.PlacementRemote
	_, err = set.For(w)
	require.ErrorIs(t, err, ErrNoMechanism, "a place nothing here offers is not served")

	w.Placement = agentvm.PlacementAny
	got, err = set.For(w)
	require.NoError(t, err)
	require.Equal(t, agentvm.PlacementLocal, got.Placement())
}

// TestStorageDemandIsNotARunnersToGrant: replication is about where bytes went,
// so it is not consulted when choosing what executes.
func TestStorageDemandIsNotARunnersToGrant(t *testing.T) {
	set := New(local(agentvm.MechanismRunc))
	got, err := set.For(demand(agentvm.SyscallFiltered, agentvm.ReplicaMany))
	require.NoError(t, err, "a storage demand does not change which mechanism runs the code")
	require.Equal(t, agentvm.Mechanism(agentvm.MechanismRunc), got.Mechanism())
}

// TestEmptySetServesNothing.
func TestEmptySetServesNothing(t *testing.T) {
	set := New()
	_, err := set.For(demand())
	require.ErrorIs(t, err, ErrNoMechanism)
	require.Equal(t, agentvm.Mechanisms(0), set.Mechanisms())

	// A nil runner is not a runner.
	require.Equal(t, agentvm.Mechanisms(0), New(nil, nil).Mechanisms())
}

// TestMechanismsIsWhatTheHostAdvertises: the set is exactly what an operator
// tells the chain it can run, so the chain's filter and the host's selection read
// the same table.
func TestMechanismsIsWhatTheHostAdvertises(t *testing.T) {
	set := New(local(agentvm.MechanismRunc), local(agentvm.MechanismGVisor))
	ms := set.Mechanisms()
	require.True(t, ms.Has(agentvm.MechanismRunc))
	require.True(t, ms.Has(agentvm.MechanismGVisor))
	require.False(t, ms.Has(agentvm.MechanismTEE))

	require.True(t, ms.Serves(agentvm.Require(agentvm.SyscallMediated)))
	require.False(t, ms.Serves(agentvm.Require(agentvm.MemoryEncrypted)))

	// What the host can serve and what its set selects agree.
	for _, p := range []agentvm.Property{
		agentvm.SyscallFiltered, agentvm.SyscallMediated, agentvm.MemoryEncrypted, agentvm.KernelGuest,
	} {
		_, err := set.For(demand(p))
		if ms.Serves(agentvm.Require(p)) {
			require.NoError(t, err, "%s", p)
		} else {
			require.ErrorIs(t, err, ErrNoMechanism, "%s", p)
		}
	}
}

// TestResultCarriesObservationsNotConclusions: a runner reports what it saw; it
// does not sign anything, and the evidence it feeds is built by an attestor.
func TestResultCarriesObservations(t *testing.T) {
	r := local(agentvm.MechanismGVisor)
	res, err := r.Run(context.Background(), demand(), nil)
	require.NoError(t, err)
	require.Equal(t, agentvm.MechanismGVisor, res.Observed.Serves)
	require.Equal(t, common.Hash{}, res.Filter, "a runner that applied no filter reports none")
}
