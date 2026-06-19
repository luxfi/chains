// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"

	"github.com/luxfi/chains/dexvm/txs"
)

// custody_import_asset_bind_test.go is the PERMANENT REGRESSION for the native-
// aliasing custody bug (CRITICAL-2).
//
// THE BUG (red-team PoC, confirmed): executeImport consumed source UTXOs by ID
// ONLY and never read back the recorded asset of the value it claimed; executeDeposit
// then credited the ledger with the asset the IMPORTING TX DECLARED (Outputs[0].Asset).
// So an attacker could fund a worthless-token export, then import declaring
// Output.Asset = ids.Empty (native LUX) — and the native ledger was credited,
// backed by a bogus token. Native value materialized from nothing.
//
// THE FIX: bind the credited asset to the asset the chain ACTUALLY holds for the
// consumed UTXO. executeImport reads the recorded value (owner|asset|amount) back
// from shared memory (the export side wrote it via encodeExportedOutput) and
// rejects any tx whose declared input asset/amount disagrees, whose consumed UTXOs
// span multiple assets, or whose credited output names a different asset.
// ImportTx.Verify pins the structural half (output.Asset == input.Asset). Composed,
// the credit is provably the consumed asset.
//
// These tests use the REAL two-chain shared memory (custodyHarness), exactly the
// rail the conservation tests exercise.

// importTxAliasing builds an ImportTx that consumes utxoID but DECLARES inAsset on
// the input and outAsset on the credited output — the attacker's free choice of
// what they claim to import vs. what they actually hold.
func importTxAliasing(from ids.ShortID, sourceChain, utxoID, inAsset, outAsset ids.ID, amount uint64) *txs.ImportTx {
	return txs.NewImportTx(from, 0, sourceChain,
		[]txs.AtomicInput{{UTXOID: utxoID, Asset: inAsset, Amount: amount}},
		[]txs.AtomicOutput{{Owner: from, Asset: outAsset, Amount: amount}})
}

// TestCustody_ImportRejectsNativeAliasing_DeclaredInputLie is PoC variant A: the
// attacker lies on the INPUT asset (declaring native, ids.Empty) to make the tx
// internally consistent (input == output == native), but the consumed UTXO is
// actually a bogus token. The authoritative shared-memory bind in executeImport
// catches it: declared input asset (native) != recorded UTXO asset (bogus token).
//
// FAIL-on-old -> PASS-on-fix: pre-fix executeImport never read the recorded asset,
// so the native ledger was credited from a bogus-token UTXO. This asserts REJECTION
// and a ZERO native credit.
func TestCustody_ImportRejectsNativeAliasing_DeclaredInputLie(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	attacker := ids.GenerateTestShortID()
	bogusToken := ids.GenerateTestID() // a worthless token the attacker controls
	native := ids.Empty                // the asset they want minted

	// Fund a REAL UTXO recorded as the bogus token.
	utxo := h.fundCChain(t, attacker, bogusToken, 5000)

	// Import it while DECLARING native on both input and output (passes the
	// structural Verify; only the recorded-asset bind can catch this).
	tx := importTxAliasing(attacker, h.cChain, utxo, native, native, 5000)

	ar := newAtomicRequests()
	err := h.vm.executeDeposit(ctx, tx, ar)
	if !errors.Is(err, errImportAssetMismatch) {
		t.Fatalf("aliasing import (declared-input-lie) err = %v, want errImportAssetMismatch (CRITICAL-2 regressed: native minted from a bogus token)", err)
	}

	// The native ledger must NOT have been credited.
	if got := h.ledger.bal[ledgerKey(frameUser(attacker), native)]; got != 0 {
		t.Fatalf("native ledger credited %d from a bogus-token UTXO, want 0 (no mint)", got)
	}
	// The bogus token must NOT have been credited either (the import was rejected
	// before any credit).
	if got := h.ledger.bal[ledgerKey(frameUser(attacker), bogusToken)]; got != 0 {
		t.Fatalf("bogus-token ledger credited %d on a rejected import, want 0", got)
	}
}

// TestCustody_ImportRejectsNativeAliasing_OutputLie is PoC variant B: the attacker
// declares the INPUT truthfully (the bogus token) but sets the credited OUTPUT to
// native. ImportTx.Verify's structural bind (output.Asset == input.Asset) rejects
// it before any state is touched.
func TestCustody_ImportRejectsNativeAliasing_OutputLie(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	attacker := ids.GenerateTestShortID()
	bogusToken := ids.GenerateTestID()
	native := ids.Empty

	utxo := h.fundCChain(t, attacker, bogusToken, 5000)
	// Truthful input (bogus token), but output re-denominated to native.
	tx := importTxAliasing(attacker, h.cChain, utxo, bogusToken, native, 5000)

	ar := newAtomicRequests()
	err := h.vm.executeDeposit(ctx, tx, ar)
	if err == nil {
		t.Fatalf("aliasing import (output-lie) was accepted, want rejection (CRITICAL-2)")
	}

	if got := h.ledger.bal[ledgerKey(frameUser(attacker), native)]; got != 0 {
		t.Fatalf("native ledger credited %d on an output-lie import, want 0 (no mint)", got)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(attacker), bogusToken)]; got != 0 {
		t.Fatalf("bogus-token ledger credited %d on a rejected import, want 0", got)
	}
}

// TestCustody_ImportRejectsAmountInflation pins the amount axis of the same bind:
// an import that DECLARES more than the consumed UTXO actually holds is rejected,
// so the proxy never credits an inflated amount.
func TestCustody_ImportRejectsAmountInflation(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	attacker := ids.GenerateTestShortID()
	token := ids.GenerateTestID()

	utxo := h.fundCChain(t, attacker, token, 100) // chain holds 100
	// Declare 1_000_000 of the SAME asset (truthful asset, inflated amount).
	tx := importTxAliasing(attacker, h.cChain, utxo, token, token, 1_000_000)

	ar := newAtomicRequests()
	err := h.vm.executeDeposit(ctx, tx, ar)
	if !errors.Is(err, errImportAmountMismatch) {
		t.Fatalf("inflated-amount import err = %v, want errImportAmountMismatch", err)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(attacker), token)]; got != 0 {
		t.Fatalf("ledger credited %d on a rejected inflated import, want 0", got)
	}
}

// TestCustody_ImportHonestAssetCredits is the POSITIVE control: an HONEST import
// (declared input asset/amount == the recorded UTXO, output == that same asset) is
// ACCEPTED and credits the ledger in the CONSUMED asset — never native. This proves
// the bind rejects only mismatches, not legitimate non-native deposits.
func TestCustody_ImportHonestAssetCredits(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	owner := ids.GenerateTestShortID()
	token := ids.GenerateTestID()
	native := ids.Empty

	utxo := h.fundCChain(t, owner, token, 777)
	tx := importTxAliasing(owner, h.cChain, utxo, token, token, 777)

	ar := newAtomicRequests()
	if err := h.vm.executeDeposit(ctx, tx, ar); err != nil {
		t.Fatalf("honest non-native import rejected: %v", err)
	}

	// Credited in the CONSUMED token, for exactly the imported amount.
	if got := h.ledger.bal[ledgerKey(frameUser(owner), token)]; got != 777 {
		t.Fatalf("token ledger credited %d, want 777", got)
	}
	// And NOT in native (no aliasing).
	if got := h.ledger.bal[ledgerKey(frameUser(owner), native)]; got != 0 {
		t.Fatalf("native ledger credited %d on a token import, want 0", got)
	}
}

// importTxOwner builds an ImportTx that consumes utxoID (declaring asset/amount)
// but credits the value to creditOwner — which may DIFFER from the consumed UTXO's
// recorded owner. The free choice of credited owner is the attacker's lever the
// owner bind must close.
func importTxOwner(from ids.ShortID, sourceChain, utxoID, asset ids.ID, amount uint64, creditOwner ids.ShortID) *txs.ImportTx {
	return txs.NewImportTx(from, 0, sourceChain,
		[]txs.AtomicInput{{UTXOID: utxoID, Asset: asset, Amount: amount}},
		[]txs.AtomicOutput{{Owner: creditOwner, Asset: asset, Amount: amount}})
}

// TestImportDeclaredNativeConsumedBogusRejects: an import that DECLARES the native
// asset on its input but consumes a UTXO recorded as a bogus token is rejected by
// the authoritative shared-memory asset bind (declared native != recorded token),
// and credits NOTHING — the headline native-aliasing theft, refused.
func TestImportDeclaredNativeConsumedBogusRejects(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	attacker := ids.GenerateTestShortID()
	bogusToken := ids.GenerateTestID()
	native := ids.Empty

	utxo := h.fundCChain(t, attacker, bogusToken, 5000) // chain records a bogus token
	tx := importTxAliasing(attacker, h.cChain, utxo, native, native, 5000)

	ar := newAtomicRequests()
	if err := h.vm.executeDeposit(ctx, tx, ar); !errors.Is(err, errImportAssetMismatch) {
		t.Fatalf("declared-native/consumed-bogus import err = %v, want errImportAssetMismatch", err)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(attacker), native)]; got != 0 {
		t.Fatalf("native credited %d from a bogus-token UTXO, want 0", got)
	}
}

// TestImportDeclaredAssetMismatchRejects: declaring asset X while the consumed UTXO
// holds asset Y is rejected — the credited asset is bound to what the chain ACTUALLY
// holds, never what the tx declares.
func TestImportDeclaredAssetMismatchRejects(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	owner := ids.GenerateTestShortID()
	heldAsset := ids.GenerateTestID()
	declaredAsset := ids.GenerateTestID() // a different asset

	utxo := h.fundCChain(t, owner, heldAsset, 1234)
	tx := importTxAliasing(owner, h.cChain, utxo, declaredAsset, declaredAsset, 1234)

	ar := newAtomicRequests()
	if err := h.vm.executeDeposit(ctx, tx, ar); !errors.Is(err, errImportAssetMismatch) {
		t.Fatalf("declared-asset-mismatch import err = %v, want errImportAssetMismatch", err)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(owner), declaredAsset)]; got != 0 {
		t.Fatalf("declared asset credited %d on a mismatched import, want 0", got)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(owner), heldAsset)]; got != 0 {
		t.Fatalf("held asset credited %d on a rejected import, want 0", got)
	}
}

// TestImportAmountMismatchRejects: declaring more (or less) than the consumed UTXO
// records is rejected — the amount axis of the authoritative bind.
func TestImportAmountMismatchRejects(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	owner := ids.GenerateTestShortID()
	token := ids.GenerateTestID()

	utxo := h.fundCChain(t, owner, token, 100) // chain holds 100
	tx := importTxAliasing(owner, h.cChain, utxo, token, token, 1_000_000)

	ar := newAtomicRequests()
	if err := h.vm.executeDeposit(ctx, tx, ar); !errors.Is(err, errImportAmountMismatch) {
		t.Fatalf("amount-mismatch import err = %v, want errImportAmountMismatch", err)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(owner), token)]; got != 0 {
		t.Fatalf("ledger credited %d on a rejected amount-mismatch import, want 0", got)
	}
}

// TestImportWrongOwnerRejects is the OWNER axis of the bind (the cross-chain analog
// of the settlement-identity collision): an attacker consumes a UTXO whose recorded
// owner is the VICTIM, but credits the value to the attacker's OWN account. The
// owner bind rejects it (recorded victim owner != credited attacker owner), so no
// account is credited — a victim's exported value cannot be stolen on import.
//
// FAIL-on-old -> PASS-on-fix: before the owner bind, executeImport read only the
// recorded asset/amount and never the recorded owner, so the attacker's freely
// chosen credit owner was honored — stealing the victim's exported UTXO.
func TestImportWrongOwnerRejects(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	victim := ids.GenerateTestShortID()
	attacker := ids.GenerateTestShortID()
	token := ids.GenerateTestID()

	// The chain records the UTXO as owned by the VICTIM.
	utxo := h.fundCChain(t, victim, token, 9000)
	// The attacker imports it, crediting their OWN account.
	tx := importTxOwner(attacker, h.cChain, utxo, token, 9000, attacker)

	ar := newAtomicRequests()
	if err := h.vm.executeDeposit(ctx, tx, ar); !errors.Is(err, errImportWrongOwner) {
		t.Fatalf("wrong-owner import err = %v, want errImportWrongOwner (THEFT: attacker credited a victim's exported UTXO)", err)
	}
	// Neither account is credited (the import was rejected before any credit).
	if got := h.ledger.bal[ledgerKey(frameUser(attacker), token)]; got != 0 {
		t.Fatalf("attacker credited %d from the victim's UTXO, want 0", got)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(victim), token)]; got != 0 {
		t.Fatalf("victim credited %d on a rejected import, want 0", got)
	}

	// POSITIVE control: the SAME UTXO imported by/for the rightful victim owner is
	// ACCEPTED (the bind rejects only owner mismatches, not legitimate claims).
	tx2 := importTxOwner(victim, h.cChain, utxo, token, 9000, victim)
	ar2 := newAtomicRequests()
	if err := h.vm.executeDeposit(ctx, tx2, ar2); err != nil {
		t.Fatalf("rightful-owner import rejected: %v", err)
	}
	if got := h.ledger.bal[ledgerKey(frameUser(victim), token)]; got != 9000 {
		t.Fatalf("victim credited %d on a rightful import, want 9000", got)
	}
}

// TestImportSameTxIDDifferentOutputIndexDistinct proves the UTXO id binds the
// OUTPUT INDEX: two outputs of the SAME source tx (same txID, indices 0 and 1) are
// DISTINCT UTXOs — each consumable exactly once, neither aliasing the other. (If the
// id ignored the index, importing index 0 would also consume index 1.)
func TestImportSameTxIDDifferentOutputIndexDistinct(t *testing.T) {
	h := newCustodyHarness(t)

	owner := ids.GenerateTestShortID()
	token := ids.GenerateTestID()
	srcTxID := ids.GenerateTestID()

	// Two UTXOs from the same source tx, distinguished only by output index.
	utxo0 := deriveUTXOID(srcTxID, 0)
	utxo1 := deriveUTXOID(srcTxID, 1)
	if utxo0 == utxo1 {
		t.Fatal("deriveUTXOID ignores the output index — same-tx outputs collide")
	}
	// Seed both into shared memory with distinct amounts.
	for _, u := range []struct {
		id  ids.ID
		amt uint64
	}{{utxo0, 100}, {utxo1, 200}} {
		val := encodeExportedOutput(txs.AtomicOutput{Owner: owner, Asset: token, Amount: u.amt})
		if err := h.cChainSM.Apply(map[ids.ID]*atomic.Requests{
			h.proxyChain: {PutRequests: []*atomic.Element{{Key: u.id[:], Value: val, Traits: [][]byte{owner[:]}}}},
		}); err != nil {
			t.Fatalf("seed UTXO: %v", err)
		}
	}

	// Import output 0 (amount 100). Output 1 stays unconsumed and independently
	// claimable.
	ar := newAtomicRequests()
	if err := h.vm.executeImport(importTxOwner(owner, h.cChain, utxo0, token, 100, owner), ar); err != nil {
		t.Fatalf("import output 0: %v", err)
	}
	// Output 1 is NOT consumed by importing output 0.
	if consumed, _ := h.vm.state.IsConsumed(utxo1); consumed {
		t.Fatal("importing output 0 also consumed output 1 (output index not bound into the UTXO id)")
	}
	// And output 1 imports cleanly on its own (amount 200).
	ar2 := newAtomicRequests()
	if err := h.vm.executeImport(importTxOwner(owner, h.cChain, utxo1, token, 200, owner), ar2); err != nil {
		t.Fatalf("import output 1: %v", err)
	}
}

// TestImportReplaySameUTXORejects proves the same UTXO cannot be consumed twice: a
// second import of an already-consumed UTXO is rejected (errUTXOAlreadyImported), so
// the proxy never mints by re-importing already-claimed value.
func TestImportReplaySameUTXORejects(t *testing.T) {
	h := newCustodyHarness(t)

	owner := ids.GenerateTestShortID()
	token := ids.GenerateTestID()
	utxo := h.fundCChain(t, owner, token, 500)

	// First import consumes the UTXO.
	ar := newAtomicRequests()
	if err := h.vm.executeImport(importTxOwner(owner, h.cChain, utxo, token, 500, owner), ar); err != nil {
		t.Fatalf("first import: %v", err)
	}
	// Replaying the SAME UTXO is rejected.
	ar2 := newAtomicRequests()
	if err := h.vm.executeImport(importTxOwner(owner, h.cChain, utxo, token, 500, owner), ar2); !errors.Is(err, errUTXOAlreadyImported) {
		t.Fatalf("replay of consumed UTXO err = %v, want errUTXOAlreadyImported", err)
	}
}
