// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"fmt"

	"github.com/luxfi/chains/fee"
)

// GasPrice is nLUX per unit of gas. It is chosen so the cheapest priced
// operation still settles >= node/vms/types/fee.MinTxFeeFloor (1 mLUX),
// unifying the new per-operation settlement with the pre-existing admission
// floor. gas_test.go asserts that relationship for every (operation, algorithm)
// pair so the two fee surfaces can never silently drift apart.
const GasPrice = fee.Gas(1_000)

// opBaseGas prices the STRUCTURAL cost of an operation — signature
// authentication, state writes, indexing — independent of any key algorithm.
var opBaseGas = map[uint8]fee.Gas{
	TxRegisterKey: 21_000,
	TxSetPolicy:   5_000,
	TxAuthorize:   10_000,
	TxRevokeKey:   3_000,
}

// algoGas prices the cryptographic work an operation DISPATCHES to the off-K MPC
// committee, BY ALGORITHM. This is the direct fix for the audit finding that one
// flat floor priced an ML-KEM encapsulation, an ML-DSA-65 threshold sign, and a
// BLS verify/aggregate identically — though their real committee cost (compute
// and round complexity) differs by an order of magnitude. Values are relative
// gas units; the ratios, not the absolutes, encode the cost model.
//
// Membership of this map is ALSO the single source of truth for "which
// algorithms K accepts": an operation naming an algorithm absent here is
// refused (fail closed), never priced at the bare base cost.
var algoGas = map[string]fee.Gas{
	"ml-kem-512":    8_000,
	"ml-kem-768":    12_000, // post-quantum KEM encapsulation
	"ml-kem-1024":   18_000,
	"ml-dsa-44":     40_000,
	"ml-dsa-65":     60_000, // post-quantum threshold sign-authorize (platform default)
	"ml-dsa-87":     90_000,
	"bls-threshold": 30_000, // BLS verify / aggregate
	"secp256k1":     15_000, // ECDSA threshold (CMP/Doerner) authorize
}

// usesAlgorithm reports whether an operation's price depends on the key
// algorithm. RegisterKey and Authorize dispatch committee cryptography and so
// are algorithm-priced; SetPolicy and RevokeKey are pure policy writes and are
// algorithm-independent.
func usesAlgorithm(txType uint8) bool {
	return txType == TxRegisterKey || txType == TxAuthorize
}

// GasFor returns the metered gas for a transaction, pricing by operation and —
// for committee-dispatching operations — by algorithm. It fails closed on an
// unknown operation type or an unknown/missing algorithm for an operation that
// requires one.
func GasFor(tx *Transaction) (fee.Gas, error) {
	base, ok := opBaseGas[tx.Type]
	if !ok {
		return 0, fmt.Errorf("keyvm gas: unknown tx type %d", tx.Type)
	}
	total := base
	if usesAlgorithm(tx.Type) {
		ag, ok := algoGas[tx.Algorithm]
		if !ok {
			return 0, fmt.Errorf("keyvm gas: %w: %q", ErrUnknownAlgorithm, tx.Algorithm)
		}
		total += ag
	}
	return total, nil
}

// FeeFor returns the nLUX fee a transaction settles: GasFor(tx) * GasPrice.
func FeeFor(tx *Transaction) (uint64, error) {
	g, err := GasFor(tx)
	if err != nil {
		return 0, err
	}
	return fee.Cost(g, GasPrice)
}

// SupportedAlgorithm reports whether algo is priced (and therefore accepted) by
// the K-Chain gas schedule.
func SupportedAlgorithm(algo string) bool {
	_, ok := algoGas[algo]
	return ok
}

// MinScheduledFee is the smallest fee any valid operation can settle (the
// cheapest base operation at GasPrice). gas_test.go asserts it is
// >= node/vms/types/fee.MinTxFeeFloor.
func MinScheduledFee() uint64 {
	min := fee.Gas(0)
	first := true
	for _, g := range opBaseGas {
		if first || g < min {
			min, first = g, false
		}
	}
	f, _ := fee.Cost(min, GasPrice)
	return f
}
