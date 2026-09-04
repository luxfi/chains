// Copyright (c) 2019-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

package fee

import (
	"errors"

	"github.com/luxfi/ids"
)

// MinTxFeeFloor is the minimum tx fee, in the base unit (constants.MicroLux,
// 1e-6 LUX — written nLUX throughout this package), that any user-facing chain
// SHOULD charge. It is the lower bound used when reviewing per-VM policies;
// Validate does not enforce it (a VM is free to charge MORE), but a VM choosing
// less is flagged at review.
//
// Known intentional exception: the X-Chain prices transactions through its own
// UTXO fee subsystem, NOT a FlatPolicy, and sits deliberately outside this
// floor — its UTXO economics are set independently of the account-model floor.
const MinTxFeeFloor uint64 = 1_000_000

// Sentinel errors returned by Policy implementations and Validate.
var (
	// ErrZeroMinFee is returned by Validate when a non-sentinel policy declares
	// a zero minimum fee. User-facing chains MUST charge > 0.
	ErrZeroMinFee = errors.New("fee policy declares zero min tx fee on a user-facing chain")

	// ErrWrongFeeAsset is returned by Policy.ValidateFee when the tx pays in an
	// asset other than the policy's FeeAssetID.
	ErrWrongFeeAsset = errors.New("tx pays fee in wrong asset")

	// ErrInsufficientFee is returned by Policy.ValidateFee when the paid amount
	// is below MinTxFee.
	ErrInsufficientFee = errors.New("tx fee below policy minimum")

	// ErrChainAcceptsNoUserTxs is returned by NoUserTxPolicy.ValidateFee for
	// any tx — committee-driven chains have no user mempool, so any arrival at
	// the fee gate is a wiring bug.
	ErrChainAcceptsNoUserTxs = errors.New("chain accepts no user-submitted txs")
)

// Policy is the ADMISSION half of the fee model: how a VM decides whether a
// user-submitted tx pays enough to enter at all. Every chain that accepts user
// txs MUST declare a non-nil Policy whose MinTxFee() is > 0. Chains that accept
// no user txs declare NoUserTxPolicy — the only legal way to opt out.
//
// Policy is declared at boot and checked once by Validate; settlement of the
// admitted fee during block execution is the Ledger / Charge half of this
// package. The two compose and do not overlap.
type Policy interface {
	// MinTxFee returns the minimum fee, in nLUX, that any user tx must pay.
	// MUST be > 0 for user-facing VMs.
	MinTxFee() uint64

	// FeeAssetID returns the asset the fee is paid in. For primary-network
	// burn this is constants.UTXOAssetIDFor(networkID).
	FeeAssetID() ids.ID

	// ValidateFee returns nil if the paid amount and asset satisfy the policy,
	// else ErrWrongFeeAsset, ErrInsufficientFee or ErrChainAcceptsNoUserTxs.
	ValidateFee(paidNanoLux uint64, paidAsset ids.ID) error
}

// FlatPolicy charges a fixed fee per user tx — the canonical policy for VMs
// without dynamic gas pricing.
type FlatPolicy struct {
	// Fee is the per-tx burn amount, in nLUX. MUST be > 0.
	Fee uint64

	// AssetID is the fee asset. For primary-network burn, use
	// constants.UTXOAssetIDFor(networkID).
	AssetID ids.ID
}

// MinTxFee returns the flat fee.
func (p FlatPolicy) MinTxFee() uint64 { return p.Fee }

// FeeAssetID returns the configured fee asset.
func (p FlatPolicy) FeeAssetID() ids.ID { return p.AssetID }

// ValidateFee enforces the flat policy.
func (p FlatPolicy) ValidateFee(paid uint64, asset ids.ID) error {
	if asset != p.AssetID {
		return ErrWrongFeeAsset
	}
	if paid < p.Fee {
		return ErrInsufficientFee
	}
	return nil
}

// NoUserTxPolicy is the sentinel for chains that accept no user-submitted txs
// (committee-driven only). Distinguishing it from "policy not set" is what lets
// Validate refuse zero-fee user-facing chains without false positives on the
// committee chains.
type NoUserTxPolicy struct{}

// MinTxFee always returns 0 — there are no user txs to charge.
func (NoUserTxPolicy) MinTxFee() uint64 { return 0 }

// FeeAssetID returns ids.Empty — there is no fee asset.
func (NoUserTxPolicy) FeeAssetID() ids.ID { return ids.Empty }

// ValidateFee always returns ErrChainAcceptsNoUserTxs — any caller reaching
// this gate is a wiring bug.
func (NoUserTxPolicy) ValidateFee(uint64, ids.ID) error {
	return ErrChainAcceptsNoUserTxs
}

// Validate is the boot-time check run against a VM's declared Policy. It
// returns ErrZeroMinFee if a non-sentinel policy declares MinTxFee() == 0,
// and nil for NoUserTxPolicy (the explicit opt-out) or any MinTxFee > 0.
func Validate(p Policy) error {
	if _, ok := p.(NoUserTxPolicy); ok {
		return nil
	}
	if p.MinTxFee() == 0 {
		return ErrZeroMinFee
	}
	return nil
}
