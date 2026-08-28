// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"fmt"

	"github.com/luxfi/chains/fee"
)

// GasPrice is nLUX per unit of gas. It is chosen so the cheapest priced
// operation still settles >= node/vms/types/fee.MinTxFeeFloor (1 mLUX),
// unifying per-operation settlement with the pre-existing admission floor.
// gas_test.go asserts that relationship for every (operation, scheme) pair so
// the two fee surfaces can never silently drift apart.
const GasPrice = fee.Gas(1_000)

// GasPerByte prices the bytes a transaction puts on the chain FOREVER: its
// payload and its scheme, the two fields whose length the payer chooses. It
// follows Ethereum's non-zero calldata rate for the same reason — storage is
// the cost a base fee cannot express — and it is what stops a ciphertext body
// riding onto F for the price of the handle that was supposed to replace it.
// The fixed part of a transaction (header, public key, signature) is bounded by
// construction and is covered by the operation's base cost.
const GasPerByte = fee.Gas(16)

// opBaseGas prices the STRUCTURAL cost of an operation — signature
// authentication, state writes, indexing — independent of any FHE scheme.
var opBaseGas = map[uint8]fee.Gas{
	TxRegisterCiphertext: 21_000,
	TxGrantPermit:        8_000,
	TxRevokePermit:       3_000,
	TxRequestDecrypt:     15_000,
	TxFulfillDecrypt:     10_000,
	TxAdvanceEpoch:       5_000,
}

// schemeGas prices the cryptographic work an operation DISPATCHES to the
// off-chain threshold committee, BY SCHEME AND RING DIMENSION — the two
// parameters that actually set the cost. A ciphertext's size is linear in the
// ring dimension N and its transform cost is N log N, so doubling N roughly
// doubles the gas; and at equal N the schemes differ because they carry
// different numbers of ring elements and moduli (TFHE's small LWE ciphertexts
// are cheapest, CKKS's rescaling chain the dearest). Pricing every FHE
// operation at one flat rate would charge a TFHE boolean the same as a CKKS
// n=2^15 vector, which is off by an order of magnitude.
//
// Membership of this map is ALSO the single source of truth for "which schemes
// F accepts": an operation naming a scheme absent here is refused (fail
// closed), never priced at the bare base cost.
var schemeGas = map[string]fee.Gas{
	"tfhe-n10": 12_000,
	"tfhe-n11": 24_000,
	"bfv-n13":  25_000,
	"bfv-n14":  50_000,
	"bgv-n13":  26_000,
	"bgv-n14":  52_000,
	"ckks-n13": 30_000,
	"ckks-n14": 60_000,
	"ckks-n15": 120_000,
}

// usesScheme reports whether an operation's price depends on the FHE scheme.
// Registering a ciphertext and requesting its decryption both scale with the
// scheme — the first in the size the network carries and indexes, the second in
// the committee's partial-decryption and combination work. Granting, revoking,
// attesting a finished result, and advancing an epoch are fixed-size record
// writes that touch no ciphertext, so they are scheme-independent.
func usesScheme(txType uint8) bool {
	return txType == TxRegisterCiphertext || txType == TxRequestDecrypt
}

// GasFor returns the metered gas for a transaction, pricing by operation and —
// for committee-dispatching operations — by scheme. It fails closed on an
// unknown operation type or an unknown/missing scheme for an operation that
// requires one.
func GasFor(tx *Transaction) (fee.Gas, error) {
	base, ok := opBaseGas[tx.Type]
	if !ok {
		return 0, fmt.Errorf("fhevm gas: unknown tx type %d", tx.Type)
	}
	total := base
	if usesScheme(tx.Type) {
		sg, ok := schemeGas[tx.Scheme]
		if !ok {
			return 0, fmt.Errorf("fhevm gas: %w: %q", ErrUnknownScheme, tx.Scheme)
		}
		total += sg
	}
	return total + fee.Gas(len(tx.Payload)+len(tx.Scheme))*GasPerByte, nil
}

// FeeFor returns the nLUX fee a transaction settles: GasFor(tx) * GasPrice.
func FeeFor(tx *Transaction) (uint64, error) {
	g, err := GasFor(tx)
	if err != nil {
		return 0, err
	}
	return fee.Cost(g, GasPrice)
}

// SupportedScheme reports whether scheme is priced (and therefore accepted) by
// the F-Chain gas schedule.
func SupportedScheme(scheme string) bool {
	_, ok := schemeGas[scheme]
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
