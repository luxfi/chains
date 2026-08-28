// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"testing"

	"github.com/stretchr/testify/require"

	nodefee "github.com/luxfi/node/vms/types/fee"
)

func TestAChainThatChargesRefusesLessThanTheFloor(t *testing.T) {
	f := Floor(1)
	require.Error(t, f.Admit(0))
	require.Error(t, f.Admit(nodefee.MinTxFeeFloor-1))
	require.NoError(t, f.Admit(nodefee.MinTxFeeFloor))
	require.NoError(t, f.Admit(nodefee.MinTxFeeFloor+1))
	require.NoError(t, nodefee.Validate(f.Policy()),
		"the node's boot-time check must accept what a user-facing chain declares")
}

func TestAClosedChainRefusesEveryCaller(t *testing.T) {
	f := Closed()
	require.ErrorIs(t, f.Admit(0), nodefee.ErrChainAcceptsNoUserTxs)
	require.ErrorIs(t, f.Admit(nodefee.MinTxFeeFloor), nodefee.ErrChainAcceptsNoUserTxs)
	require.ErrorIs(t, f.Admit(1<<62), nodefee.ErrChainAcceptsNoUserTxs)
	require.NoError(t, nodefee.Validate(f.Policy()))
}

// TestAnUndeclaredFeeAdmitsNothing is the fail-closed shape: a chain that
// forgets to declare what it charges refuses every caller, rather than
// admitting every caller.
func TestAnUndeclaredFeeAdmitsNothing(t *testing.T) {
	var f Fee
	require.ErrorIs(t, f.Admit(0), nodefee.ErrChainAcceptsNoUserTxs)
	require.ErrorIs(t, f.Admit(1<<62), nodefee.ErrChainAcceptsNoUserTxs)
	require.Nil(t, f.Policy())
}

func TestTheFloorIsDenominatedInTheNetworksOwnAsset(t *testing.T) {
	one, two := Floor(1), Floor(2)
	require.NotEqual(t, one.asset, two.asset,
		"two networks do not share an asset, so they do not share a floor")
}
