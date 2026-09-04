// Copyright (c) 2019-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

package fee

import (
	"errors"
	"testing"

	"github.com/luxfi/constants"
	"github.com/luxfi/ids"
)

func TestFlatPolicy_ValidatesAtMinTxFeeFloor(t *testing.T) {
	p := FlatPolicy{Fee: MinTxFeeFloor, AssetID: constants.UTXO_ASSET_ID}
	if err := Validate(p); err != nil {
		t.Fatalf("Validate(FlatPolicy{Fee: MinTxFeeFloor}) = %v, want nil", err)
	}
	if got := p.MinTxFee(); got != MinTxFeeFloor {
		t.Errorf("MinTxFee() = %d, want %d", got, MinTxFeeFloor)
	}
	if got := p.FeeAssetID(); got != constants.UTXO_ASSET_ID {
		t.Errorf("FeeAssetID() = %v, want UTXO_ASSET_ID", got)
	}
}

func TestFlatPolicy_RejectsZeroFee(t *testing.T) {
	p := FlatPolicy{Fee: 0, AssetID: constants.UTXO_ASSET_ID}
	err := Validate(p)
	if !errors.Is(err, ErrZeroMinFee) {
		t.Fatalf("Validate(FlatPolicy{Fee: 0}) = %v, want ErrZeroMinFee", err)
	}
}

func TestFlatPolicy_ValidateFee(t *testing.T) {
	const fee = MinTxFeeFloor
	p := FlatPolicy{Fee: fee, AssetID: constants.UTXO_ASSET_ID}

	// exact pays — accepted.
	if err := p.ValidateFee(fee, constants.UTXO_ASSET_ID); err != nil {
		t.Errorf("ValidateFee(exact) = %v, want nil", err)
	}
	// over-pay — accepted.
	if err := p.ValidateFee(fee+1, constants.UTXO_ASSET_ID); err != nil {
		t.Errorf("ValidateFee(over) = %v, want nil", err)
	}
	// under-pay — refused with ErrInsufficientFee.
	if err := p.ValidateFee(fee-1, constants.UTXO_ASSET_ID); !errors.Is(err, ErrInsufficientFee) {
		t.Errorf("ValidateFee(under) = %v, want ErrInsufficientFee", err)
	}
	// wrong asset — refused with ErrWrongFeeAsset (even if paid >= fee).
	wrong := ids.GenerateTestID()
	if err := p.ValidateFee(fee, wrong); !errors.Is(err, ErrWrongFeeAsset) {
		t.Errorf("ValidateFee(wrong asset) = %v, want ErrWrongFeeAsset", err)
	}
}

func TestNoUserTxPolicy_PassesValidate(t *testing.T) {
	p := NoUserTxPolicy{}
	if err := Validate(p); err != nil {
		t.Fatalf("Validate(NoUserTxPolicy) = %v, want nil", err)
	}
	if got := p.MinTxFee(); got != 0 {
		t.Errorf("MinTxFee() = %d, want 0", got)
	}
	if got := p.FeeAssetID(); got != ids.Empty {
		t.Errorf("FeeAssetID() = %v, want ids.Empty", got)
	}
}

func TestNoUserTxPolicy_ValidateFeeAlwaysRefuses(t *testing.T) {
	p := NoUserTxPolicy{}
	// Any call into the fee gate on a committee-only chain is a wiring
	// bug — the chain should never have accepted the user tx in the
	// first place.
	if err := p.ValidateFee(0, ids.Empty); !errors.Is(err, ErrChainAcceptsNoUserTxs) {
		t.Errorf("ValidateFee(0) = %v, want ErrChainAcceptsNoUserTxs", err)
	}
	if err := p.ValidateFee(MinTxFeeFloor, constants.UTXO_ASSET_ID); !errors.Is(err, ErrChainAcceptsNoUserTxs) {
		t.Errorf("ValidateFee(paid, asset) = %v, want ErrChainAcceptsNoUserTxs", err)
	}
}

func TestPolicy_InterfaceSatisfaction(t *testing.T) {
	// Compile-time check that the two concrete types satisfy Policy.
	// (A missing method would fail the build, not this test, but
	// keeping the assertion documents the contract.)
	var _ Policy = FlatPolicy{}
	var _ Policy = NoUserTxPolicy{}
}
