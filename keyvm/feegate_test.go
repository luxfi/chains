// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	nodefee "github.com/luxfi/node/vms/types/fee"
)

// TestAdmissionPolicy_AttachedAtInit proves the chain still declares a non-zero
// admission floor (so the boot-time Manager validate never flags K as a
// zero-fee user chain). This is the ADMISSION half; settlement is proven in
// settlement_test.go / gas_test.go.
func TestAdmissionPolicy_AttachedAtInit(t *testing.T) {
	vm := newTestVM(t, nil)
	defer func() { _ = vm.Shutdown(context.Background()) }()

	require.NotNil(t, vm.FeePolicy())
	require.Equal(t, nodefee.MinTxFeeFloor, vm.FeePolicy().MinTxFee())
	require.NoError(t, nodefee.Validate(vm.FeePolicy()))
}

// TestAdmissionAndSettlementAgree proves the two fee surfaces are consistent:
// the cheapest fee the per-algorithm settlement schedule can charge is at least
// the declared admission floor, so they can never drift apart.
func TestAdmissionAndSettlementAgree(t *testing.T) {
	require.GreaterOrEqual(t, MinScheduledFee(), nodefee.MinTxFeeFloor)
}
