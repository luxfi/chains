// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo

package cevm

import (
	"crypto/ecdsa"
	"math/big"
	"testing"

	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// TestBatchRecoverSenders_ParityWithSequential is the consensus-critical
// gate: for any batch of signed transactions, BatchRecoverSenders MUST
// produce byte-identical results to per-tx types.Sender. A divergence
// here is a kernel bug that would corrupt sender derivation in the
// parallel BlockExecutor.
//
// Coverage:
//   - LegacyTxType (EIP-155 protected, chain id 96369)
//   - DynamicFeeTxType (EIP-1559)
//   - AccessListTxType (EIP-2930)
//   - 64 signers across 64 txs to exercise the batch path proper.
func TestBatchRecoverSenders_ParityWithSequential(t *testing.T) {
	const N = 64
	chainID := big.NewInt(96369) // Lux mainnet C-Chain
	signer := types.NewCancunSigner(chainID)

	// Generate N independent keys + sign one tx per key, alternating tx types.
	keys := make([]*ecdsa.PrivateKey, N)
	txs := make(types.Transactions, N)
	want := make([]common.Address, N)
	for i := 0; i < N; i++ {
		k, err := luxcrypto.GenerateKey()
		if err != nil {
			t.Fatalf("GenerateKey[%d]: %v", i, err)
		}
		keys[i] = k
		// luxcrypto.PubkeyToAddress returns its own common.Address type; the
		// 20-byte payload matches geth's. Convert by raw bytes.
		la := luxcrypto.PubkeyToAddress(k.PublicKey)
		want[i] = common.BytesToAddress(la[:])

		var inner types.TxData
		switch i % 3 {
		case 0:
			// LegacyTxType (EIP-155 protected after signing).
			inner = &types.LegacyTx{
				Nonce:    uint64(i),
				GasPrice: big.NewInt(1_000_000_000),
				Gas:      21_000,
				To:       &common.Address{0xde, 0xad},
				Value:    big.NewInt(int64(i + 1)),
				Data:     nil,
			}
		case 1:
			// DynamicFeeTxType.
			inner = &types.DynamicFeeTx{
				ChainID:   chainID,
				Nonce:     uint64(i),
				GasTipCap: big.NewInt(1_000_000_000),
				GasFeeCap: big.NewInt(2_000_000_000),
				Gas:       21_000,
				To:        &common.Address{0xbe, 0xef},
				Value:     big.NewInt(int64(i + 1)),
				Data:      nil,
			}
		case 2:
			// AccessListTxType.
			inner = &types.AccessListTx{
				ChainID:  chainID,
				Nonce:    uint64(i),
				GasPrice: big.NewInt(1_000_000_000),
				Gas:      21_000,
				To:       &common.Address{0xca, 0xfe},
				Value:    big.NewInt(int64(i + 1)),
				Data:     nil,
			}
		}
		tx, err := types.SignNewTx(k, signer, inner)
		if err != nil {
			t.Fatalf("SignNewTx[%d]: %v", i, err)
		}
		// Drop the cached sender so the parity test exercises real recovery
		// on the sequential reference path.
		txs[i] = tx
	}

	// Reference: per-tx types.Sender. We freshly recover here (no cache yet).
	got := make([]common.Address, N)
	for i, tx := range txs {
		// Re-decode the signed tx so the from-cache is empty.
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatalf("MarshalBinary[%d]: %v", i, err)
		}
		var fresh types.Transaction
		if err := fresh.UnmarshalBinary(raw); err != nil {
			t.Fatalf("UnmarshalBinary[%d]: %v", i, err)
		}
		txs[i] = &fresh
		addr, err := types.Sender(signer, &fresh)
		if err != nil {
			t.Fatalf("types.Sender[%d]: %v", i, err)
		}
		got[i] = addr
		if addr != want[i] {
			t.Fatalf("types.Sender[%d] disagrees with PubkeyToAddress: got=%x want=%x",
				i, addr, want[i])
		}
	}

	// Re-marshal once more so the cache is fresh again before the batch call.
	for i, tx := range txs {
		raw, err := tx.MarshalBinary()
		if err != nil {
			t.Fatalf("re-marshal[%d]: %v", i, err)
		}
		var fresh types.Transaction
		if err := fresh.UnmarshalBinary(raw); err != nil {
			t.Fatalf("re-unmarshal[%d]: %v", i, err)
		}
		txs[i] = &fresh
	}

	// Subject: BatchRecoverSenders. Must match the reference position-for-
	// position with no errors.
	batch, err := BatchRecoverSenders(txs, signer)
	if err != nil {
		t.Fatalf("BatchRecoverSenders: %v", err)
	}
	if len(batch) != N {
		t.Fatalf("len(batch)=%d, want %d", len(batch), N)
	}
	for i := 0; i < N; i++ {
		if batch[i] != got[i] {
			t.Errorf("tx[%d]: batch=%x sequential=%x (mismatch)", i, batch[i], got[i])
		}
	}

	// Cache check: a subsequent types.Sender call on a tx the batch
	// recovered should hit the cache (same address, no error). The cache
	// is the exact reason we wire this up: downstream code can keep
	// calling types.Sender freely.
	for i, tx := range txs {
		addr, err := types.Sender(signer, tx)
		if err != nil {
			t.Errorf("post-batch Sender[%d]: %v", i, err)
		}
		if addr != batch[i] {
			t.Errorf("cache disagrees post-batch on tx[%d]: cached=%x batch=%x",
				i, addr, batch[i])
		}
	}
}

// TestBatchRecoverSenders_Empty checks the empty fast-path: zero txs in,
// zero addresses out, no error, no cgo work.
func TestBatchRecoverSenders_Empty(t *testing.T) {
	signer := types.NewCancunSigner(big.NewInt(96369))
	out, err := BatchRecoverSenders(nil, signer)
	if err != nil {
		t.Fatalf("BatchRecoverSenders(nil): %v", err)
	}
	if len(out) != 0 {
		t.Errorf("len(out)=%d, want 0", len(out))
	}
}

// TestBatchRecoverSenders_SingleTx covers n=1 — the smallest non-empty
// batch. The ecrecover pipeline has been observed to take an n==0 vs n>=1
// branch; n=1 is the boundary case that hits the actual kernel.
func TestBatchRecoverSenders_SingleTx(t *testing.T) {
	chainID := big.NewInt(96369)
	signer := types.NewCancunSigner(chainID)
	k, err := luxcrypto.GenerateKey()
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	la := luxcrypto.PubkeyToAddress(k.PublicKey)
	want := common.BytesToAddress(la[:])
	tx, err := types.SignNewTx(k, signer, &types.DynamicFeeTx{
		ChainID:   chainID,
		Nonce:     0,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       21_000,
		To:        &common.Address{0x42},
		Value:     big.NewInt(1),
	})
	if err != nil {
		t.Fatalf("SignNewTx: %v", err)
	}
	// Decode-roundtrip to clear the cache.
	raw, _ := tx.MarshalBinary()
	var fresh types.Transaction
	if err := fresh.UnmarshalBinary(raw); err != nil {
		t.Fatalf("UnmarshalBinary: %v", err)
	}

	out, err := BatchRecoverSenders(types.Transactions{&fresh}, signer)
	if err != nil {
		t.Fatalf("BatchRecoverSenders: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("len(out)=%d want 1", len(out))
	}
	if out[0] != want {
		t.Errorf("batch=%x want=%x", out[0], want)
	}
}
