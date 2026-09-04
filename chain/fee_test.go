// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
)

func TestAChainThatChargesRefusesLessThanTheFloor(t *testing.T) {
	f := Floor(1)
	require.Error(t, f.Admit(0))
	require.Error(t, f.Admit(fee.MinTxFeeFloor-1))
	require.NoError(t, f.Admit(fee.MinTxFeeFloor))
	require.NoError(t, f.Admit(fee.MinTxFeeFloor+1))
	require.NoError(t, fee.Validate(f.Policy()),
		"the node's boot-time check must accept what a user-facing chain declares")
}

func TestAClosedChainRefusesEveryCaller(t *testing.T) {
	f := Closed()
	require.ErrorIs(t, f.Admit(0), fee.ErrChainAcceptsNoUserTxs)
	require.ErrorIs(t, f.Admit(fee.MinTxFeeFloor), fee.ErrChainAcceptsNoUserTxs)
	require.ErrorIs(t, f.Admit(1<<62), fee.ErrChainAcceptsNoUserTxs)
	require.NoError(t, fee.Validate(f.Policy()))
}

// TestAnUndeclaredFeeAdmitsNothing is the fail-closed shape: a chain that
// forgets to declare what it charges refuses every caller, rather than
// admitting every caller.
func TestAnUndeclaredFeeAdmitsNothing(t *testing.T) {
	var f Fee
	require.ErrorIs(t, f.Admit(0), fee.ErrChainAcceptsNoUserTxs)
	require.ErrorIs(t, f.Admit(1<<62), fee.ErrChainAcceptsNoUserTxs)
	require.Nil(t, f.Policy())
}

func TestTheFloorIsDenominatedInTheNetworksOwnAsset(t *testing.T) {
	one, two := Floor(1), Floor(2)
	require.NotEqual(t, one.asset, two.asset,
		"two networks do not share an asset, so they do not share a floor")
}
