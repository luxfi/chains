// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/ids"
)

// TestFeeSettledThroughConsensus is the headline proof that a K-Chain key
// operation is paid for by BURNING real on-chain balance inside a consensus
// block — not by an unbacked integer a caller writes into a JSON request.
func TestFeeSettledThroughConsensus(t *testing.T) {
	k := newTestKey(t)
	const fund = uint64(1_000_000_000) // 1000 mLUX
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): fund})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	bal, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, fund, bal, "genesis must fund the payer")
	burned0, err := vm.Burned()
	require.NoError(t, err)

	tx := registerTx(t, k, "treasury-key", 200_000, 1)

	// The fee is computed from the per-algorithm gas schedule, NOT supplied by
	// the caller: register + ml-dsa-65 = (21000 + 60000) gas * 1000 nLUX/gas.
	expectedFee, err := FeeFor(tx)
	require.NoError(t, err)
	require.Equal(t, uint64(81_000_000), expectedFee)

	txID, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	require.Equal(t, tx.ID(), txID)

	blkIntf, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := blkIntf.(*Block)

	require.NoError(t, blk.Verify(context.Background()))

	// Verify must NOT move funds (read-only affordability check).
	balPre, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, fund, balPre, "Verify must not debit")

	require.NoError(t, blk.Accept(context.Background()))

	// Accept settles: balance debited by EXACTLY the metered fee...
	balPost, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, fund-expectedFee, balPost, "payer must be debited the metered fee")

	// ...and the same amount is BURNED (circulating supply reduced).
	burned1, err := vm.Burned()
	require.NoError(t, err)
	require.Equal(t, burned0+expectedFee, burned1, "fee must be burned, not credited anywhere")

	// The operation took effect THROUGH consensus (not a synchronous RPC).
	rec, ok := vm.KeyByName("treasury-key")
	require.True(t, ok, "RegisterKey effect must be applied in Accept")
	require.Equal(t, StatusActive, rec.Status)
	require.Equal(t, k.addr, rec.Owner)
	require.Equal(t, "ml-dsa-65", rec.Algorithm)

	// Block is the new tip; mempool drained.
	la, err := vm.LastAccepted(context.Background())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), la)
	require.Empty(t, vm.mempool)
}

// TestUnfundedPayerCannotSettle proves the fee is balance-backed: a payer
// without funds cannot get an operation accepted. Admission rejects it, and even
// if forced into a block, Verify fails closed.
func TestUnfundedPayerCannotSettle(t *testing.T) {
	k := newTestKey(t)
	// Fund with far less than one operation's fee.
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tx := registerTx(t, k, "x", 200_000, 1)

	_, err := vm.SubmitTx(tx)
	require.ErrorIs(t, err, fee.ErrInsufficientFunds, "admission must reject an unaffordable tx")

	// Force it into a block anyway: consensus Verify must still refuse it.
	blk := &Block{parentID: vm.lastAccepted, height: 1, timestamp: time.Now(), transactions: []*Transaction{tx}, vm: vm}
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), fee.ErrInsufficientFunds)

	// State untouched: no key, nothing burned.
	_, ok := vm.KeyByName("x")
	require.False(t, ok)
	burned, _ := vm.Burned()
	require.Zero(t, burned)
}

// TestTamperedOrUnsignedTxRejected proves authorization integrity: K
// authenticates the payer by PUBLIC-key signature, so a tampered or unsigned
// transaction cannot spend or act.
func TestTamperedOrUnsignedTxRejected(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	// Tamper: mutate the nonce after signing — signature no longer matches.
	tx := registerTx(t, k, "x", 200_000, 1)
	tx.Nonce = 2
	tx.id = ids.Empty
	_, err := vm.SubmitTx(tx)
	require.ErrorIs(t, err, ErrBadSignature)

	// Unsigned: stripped auth/sig.
	tx2 := registerTx(t, k, "y", 200_000, 1)
	tx2.Auth = nil
	tx2.Sig = nil
	tx2.id = ids.Empty
	_, err = vm.SubmitTx(tx2)
	require.ErrorIs(t, err, ErrUnsignedTx)

	// Impersonation: a different key signs but claims k's address.
	other := newTestKey(t)
	tx3 := registerTx(t, k, "z", 200_000, 1) // Payer = k.addr
	other.sign(t, tx3)                       // signed by other, Auth = other.pub
	_, err = vm.SubmitTx(tx3)
	require.ErrorIs(t, err, ErrPayerMismatch)
}

// TestAuthorizeCeremonyThroughConsensus proves K's coordination role: an
// authorized ceremony is recorded on-chain (K triggers/coordinates) while the
// shares stay off-K. The ceremony record carries only PUBLIC data.
func TestAuthorizeCeremonyThroughConsensus(t *testing.T) {
	admin := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{admin.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	// Register a key (admin becomes its admin -> may invoke).
	reg := registerTx(t, admin, "signing-key", 200_000, 1)
	acceptOne(t, vm, reg)

	// Authorize a SIGN ceremony on it.
	keyID := deriveKeyID("signing-key")
	payload := mustJSON(t, AuthorizePayload{Ceremony: CeremonySign, Message: []byte("digest-to-sign")})
	auth := &Transaction{
		Type: TxAuthorize, Algorithm: "ml-dsa-65", Payer: admin.addr,
		KeyID: keyID, GasLimit: 200_000, Nonce: 2, Payload: payload,
	}
	admin.sign(t, auth)
	acceptOne(t, vm, auth)

	// A ceremony record now exists, authorized, carrying only public data.
	found := false
	vm.stateLock.RLock()
	for _, c := range vm.ceremonies {
		if c.KeyID == keyID && c.Type == CeremonySign {
			found = true
			require.Equal(t, CeremonyAuthorized, c.Status)
			require.Equal(t, admin.addr, c.Requester)
		}
	}
	vm.stateLock.RUnlock()
	require.True(t, found, "authorize must record an on-chain ceremony for the committee")
}

// TestReplayRejected proves a captured signed transaction cannot be resubmitted
// to drain the payer through repeated fee burns: nonce enforcement rejects it at
// admission and again in consensus Verify, and no second burn occurs.
func TestReplayRejected(t *testing.T) {
	k := newTestKey(t)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1_000_000_000})
	defer func() { _ = vm.Shutdown(context.Background()) }()

	tx := registerTx(t, k, "rk", 200_000, 1)
	acceptOne(t, vm, tx)
	balAfter, _ := vm.Balance(k.addr)

	// Resubmit the identical signed tx: rejected at admission (nonce consumed).
	_, err := vm.SubmitTx(tx)
	require.ErrorIs(t, err, ErrBadNonce)

	// Forced into a block, consensus Verify rejects it too — no second burn.
	blk := &Block{parentID: vm.lastAccepted, height: vm.height + 1, timestamp: time.Now(), transactions: []*Transaction{tx}, vm: vm}
	blk.id = blk.computeID()
	require.ErrorIs(t, blk.Verify(context.Background()), ErrBadNonce)

	bal2, _ := vm.Balance(k.addr)
	require.Equal(t, balAfter, bal2, "replay must not burn the payer again")
}

// acceptOne submits, builds, verifies, and accepts a single-tx block.
func acceptOne(t *testing.T, vm *VM, tx *Transaction) {
	t.Helper()
	_, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	require.NoError(t, err)
	return b
}
