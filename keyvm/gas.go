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

// GasPerPayloadByte prices each byte of a transaction's payload.
//
// The payload is the ONLY caller-controlled variable-length field an accepted
// block carries: the header is fixed-width, and Auth/Sig are fixed-width because
// authenticate() parses them as ML-DSA-65 and refuses any other length. Those
// bytes are stored twice and forever — once in the block, and (for RegisterKey)
// again in the key record. Without a length term a megabyte of commitments rides
// on chain for the same flat fee as an empty payload, which is storage bought
// for nothing. 16 gas/byte is the EVM's non-zero calldata price, the calibrated
// analogue for permanently-stored caller-supplied bytes.
const GasPerPayloadByte = fee.Gas(16)

// usesAlgorithm reports whether an operation's price depends on the key
// algorithm. RegisterKey and Authorize dispatch committee cryptography and so
// are algorithm-priced; SetPolicy and RevokeKey are pure policy writes and are
// algorithm-independent.
func usesAlgorithm(txType uint8) bool {
	return txType == TxRegisterKey || txType == TxAuthorize
}

// GasFor returns the metered gas for a transaction: the operation's structural
// cost, plus — for committee-dispatching operations — the algorithm's cost, plus
// the payload's per-byte cost. It fails closed on an unknown operation type or an
// unknown/missing algorithm for an operation that requires one.
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
	return total + GasPerPayloadByte*fee.Gas(len(tx.Payload)), nil
}

// FeeFor returns the nLUX a transaction settles: GasFor(tx) * GasPrice. It is
// the price of the operation itself, independent of what the payer declared it
// would pay — the fee-schedule RPC quotes it before a payer has picked a limit.
func FeeFor(tx *Transaction) (uint64, error) {
	g, err := GasFor(tx)
	if err != nil {
		return 0, err
	}
	return fee.Cost(g, GasPrice)
}

// meter prices a transaction AGAINST its declared gas limit: FeeFor plus the
// payer's own ceiling. Admission, block assembly, consensus Verify and
// settlement all price through this one function, so no two of them can charge
// or refuse on a different number. A transaction whose real cost exceeds the
// limit its payer signed is refused with fee.ErrOutOfGas at every layer.
func meter(tx *Transaction) (uint64, error) {
	g, err := GasFor(tx)
	if err != nil {
		return 0, err
	}
	m := fee.NewGasMeter(fee.Gas(tx.GasLimit))
	if err := m.Consume(g); err != nil {
		return 0, err
	}
	return fee.Cost(m.Used(), GasPrice)
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
	cheapest := fee.Gas(0)
	first := true
	for _, g := range opBaseGas {
		if first || g < cheapest {
			cheapest, first = g, false
		}
	}
	f, _ := fee.Cost(cheapest, GasPrice)
	return f
}
