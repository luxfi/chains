// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package cevm

// Phase 1 of GPU sig-batch ECDSA recovery wiring for the cevm BlockExecutor.
//
// The C primitive lives in luxcpp/crypto:
//   header: ~/work/luxcpp/crypto/include/lux/crypto/secp256k1.h
//   body:   ~/work/luxcpp/crypto/secp256k1/cpp/ecrecover.cpp
//   metal:  ~/work/luxcpp/crypto/secp256k1/gpu/metal/secp256k1_first_party_driver.mm
//
// The CPU oracle (the entry point exposed to consumers) is
// `secp256k1_ecrecover_address_batch` declared at secp256k1.h:113. It takes
// hashes and (r||s||v) sigs and writes 20-byte Ethereum addresses out.
//
// We link directly against the luxcpp/crypto build tree:
//
//   ${SRCDIR}/../../../../luxcpp/crypto/build/secp256k1/libsecp256k1_cpu.a
//   ${SRCDIR}/../../../../luxcpp/crypto/build/keccak/libkeccak_cpu.a
//
// libsecp256k1_cpu.a depends on _keccak256 from libkeccak_cpu.a (used by the
// pubkey -> address step), so both archives are required.
//
// If the link fails with "library 'secp256k1_cpu' not found", build the libs
// from the luxcpp/crypto source tree:
//
//   cmake -S ~/work/luxcpp/crypto -B ~/work/luxcpp/crypto/build && \
//     cmake --build ~/work/luxcpp/crypto/build \
//       --target secp256k1_cpu keccak_cpu

/*
// luxcpp/crypto headers — pulled directly from the source tree.
#cgo CFLAGS: -I${SRCDIR}/../../../../luxcpp/crypto/include

// luxcpp/crypto static libraries — built in-tree by:
//   cmake -S ~/work/luxcpp/crypto -B ~/work/luxcpp/crypto/build && \
//   cmake --build ~/work/luxcpp/crypto/build --target secp256k1
#cgo LDFLAGS: -L${SRCDIR}/../../../../luxcpp/crypto/build/secp256k1
#cgo LDFLAGS: -L${SRCDIR}/../../../../luxcpp/crypto/build/keccak
#cgo LDFLAGS: -lsecp256k1_cpu -lkeccak_cpu -lstdc++
//
// Metal driver: dispatch in cpp/ecrecover.cpp resolves the GPU symbol via
// dlsym(RTLD_DEFAULT, ...). For dlsym to find it the .o must actually be in
// the final binary; nothing in the cgo TU references the symbol so a plain
// `-l<arch>` would let the linker drop it. We solve this with the anchor in
// cevm_secp256k1_metal_anchor_darwin.c which takes the symbol's address.
//
// CPU path is still the fallback when LUX_SECP256K1_BACKEND=cpu, when
// LUX_SECP256K1_METALLIB is unset, or on non-darwin builds.
#cgo darwin LDFLAGS: -lsecp256k1_metal -framework Metal -framework Foundation

#include <stdint.h>
#include <stddef.h>
#include "lux/crypto/secp256k1.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"math/big"
	"runtime"
	"unsafe"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// BatchRecoverSenders recovers the sender address for every transaction in
// the input slice in a single cgo dispatch into the luxcpp/crypto first-party
// secp256k1 ecrecover pipeline.
//
// The output slice is the same length as txs and indexed positionally — i.e.
// out[i] is the sender of txs[i]. Per-tx behaviour matches types.Sender
// byte-for-byte; that contract is enforced by the parity test in
// cevm_secp256k1_parity_test.go.
//
// On any per-tx recovery failure the call returns an error naming the
// offending tx index. This matches the existing parallel.Executor behaviour
// (Stage 1 in parallel/parallel.go) which errors on the first failed sender
// rather than mixing successful and failed senders mid-block.
//
// The recovered addresses are written into each tx's sigCache via
// types.CacheSender, so subsequent calls to types.Sender(signer, tx) return
// the cached value and skip recomputation.
func BatchRecoverSenders(txs types.Transactions, signer types.Signer) ([]common.Address, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	n := len(txs)
	out := make([]common.Address, n)

	// Stage 1: compute the signing hash and (r||s||v) for every tx. Each
	// tx-type has its own v normalisation: legacy/EIP-155 packs chainId
	// into v; modern (typed) txs encode v ∈ {0,1} directly. We do the
	// normalisation Go-side and feed the C kernel a uniform (hash, r, s, v)
	// tuple where v ∈ {0,1}.
	hashes := make([]byte, n*32)
	sigs := make([]byte, n*65)
	for i, tx := range txs {
		h := signer.Hash(tx)
		copy(hashes[i*32:(i+1)*32], h[:])

		r, s, v, err := rawSig(signer, tx)
		if err != nil {
			return nil, fmt.Errorf("cevm: BatchRecoverSenders tx[%d]: %w", i, err)
		}
		// r, s are big-endian 32-byte big.Ints. Pad-left into the slice.
		copyBE32(sigs[i*65:i*65+32], r)
		copyBE32(sigs[i*65+32:i*65+64], s)
		sigs[i*65+64] = v
	}

	// Stage 2: single cgo call into the C++ oracle. Pin the input/output
	// base pointers for the duration of the call — the C side only reads
	// hashes/sigs and only writes out_addr/out_st, so these four base
	// addresses are the complete pin set.
	st := make([]byte, n)
	addrs := make([]byte, n*20)

	var pinner runtime.Pinner
	defer pinner.Unpin()
	pinner.Pin(&hashes[0])
	pinner.Pin(&sigs[0])
	pinner.Pin(&addrs[0])
	pinner.Pin(&st[0])

	rc := C.secp256k1_ecrecover_address_batch(
		C.size_t(n),
		(*C.uint8_t)(unsafe.Pointer(&hashes[0])),
		(*C.uint8_t)(unsafe.Pointer(&sigs[0])),
		(*C.uint8_t)(unsafe.Pointer(&addrs[0])),
		(*C.uint8_t)(unsafe.Pointer(&st[0])),
	)
	runtime.KeepAlive(hashes)
	runtime.KeepAlive(sigs)
	runtime.KeepAlive(addrs)
	runtime.KeepAlive(st)

	if rc != C.SECP256K1_OK {
		return nil, fmt.Errorf("cevm: secp256k1_ecrecover_address_batch returned %d", int(rc))
	}

	// Stage 3: walk per-tx statuses. Any non-zero status means the GPU
	// kernel rejected this signature; fail closed on the first such index.
	for i, code := range st {
		if code != 0 {
			return nil, fmt.Errorf("cevm: BatchRecoverSenders tx[%d]: secp256k1 status %d",
				i, int(code))
		}
		copy(out[i][:], addrs[i*20:(i+1)*20])
		// Cache the recovered sender into the tx's sigCache so downstream
		// types.Sender(signer, tx) calls return the cached value with no
		// further crypto. Keeps parity with sequential recovery.
		types.CacheSender(signer, txs[i], out[i])
	}
	return out, nil
}

// rawSig extracts the (r, s, v) triple to feed into secp256k1_ecrecover.
// v MUST be normalised to {0, 1} (the recovery id) — legacy txs encode v as
// 27/28 or {35..} with chain-id, EIP-155 txs encode it as 27 + chain_id*2,
// modern (typed) txs already use {0, 1}. We mirror the per-signer logic in
// luxfi/geth/core/types/transaction_signing.go {modern,EIP155,Homestead,Frontier}Signer.Sender.
func rawSig(signer types.Signer, tx *types.Transaction) (r, s *big.Int, v byte, err error) {
	V, R, S := tx.RawSignatureValues()
	if R == nil || S == nil || V == nil {
		return nil, nil, 0, errors.New("nil signature component")
	}
	r = new(big.Int).Set(R)
	s = new(big.Int).Set(S)

	switch tx.Type() {
	case types.LegacyTxType:
		// Legacy / EIP-155: parity bit is 27 (or 28) for unprotected, or
		// chain_id*2 + {35,36} for protected. Normalise to {0,1}.
		Vc := new(big.Int).Set(V)
		if tx.Protected() {
			cid := signer.ChainID()
			if cid == nil || cid.Sign() == 0 {
				return nil, nil, 0, errors.New("protected legacy tx without chain id in signer")
			}
			// V = V - chainId*2 - 8 - 27 → 0/1
			Vc.Sub(Vc, new(big.Int).Mul(cid, big.NewInt(2)))
			Vc.Sub(Vc, big.NewInt(8))
			Vc.Sub(Vc, big.NewInt(27))
		} else {
			// Unprotected (Homestead / Frontier): V = V - 27 → 0/1
			Vc.Sub(Vc, big.NewInt(27))
		}
		if !Vc.IsInt64() {
			return nil, nil, 0, fmt.Errorf("v outside expected range: %s", Vc.String())
		}
		raw := Vc.Int64()
		if raw != 0 && raw != 1 {
			return nil, nil, 0, fmt.Errorf("invalid v after normalisation: %d", raw)
		}
		v = byte(raw)
	default:
		// Typed transactions (EIP-2930, EIP-1559, EIP-4844, EIP-7702):
		// V is already the recovery id ∈ {0,1}.
		if !V.IsInt64() {
			return nil, nil, 0, fmt.Errorf("v outside int64 for typed tx: %s", V.String())
		}
		raw := V.Int64()
		if raw != 0 && raw != 1 {
			return nil, nil, 0, fmt.Errorf("invalid v for typed tx: %d", raw)
		}
		v = byte(raw)
	}
	return r, s, v, nil
}

// copyBE32 left-pads (or truncates) a big.Int into a 32-byte big-endian
// slice at dst. The C kernel expects exactly 32 bytes per scalar.
func copyBE32(dst []byte, n *big.Int) {
	if len(dst) != 32 {
		panic("copyBE32: dst must be 32 bytes")
	}
	src := n.Bytes() // big-endian, no leading zeros
	if len(src) > 32 {
		src = src[len(src)-32:]
	}
	// Zero left padding.
	for i := range dst {
		dst[i] = 0
	}
	copy(dst[32-len(src):], src)
}
