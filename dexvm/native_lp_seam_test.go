// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"testing"

	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

// native_lp_seam_test.go proves the D side of the LP D-COMMITTED LIQUIDITY rail
// (precompile/dex 0x9999 modifyLiquidity / collectPosition) consumes/produces the
// EXACT atomic wire the C side reads/writes — WITHOUT any new D-side primitive. A
// position-commit object (DL01) is byte-identical to any cross-chain value object
// (owner|asset|amount), so:
//
//   - C->D COMMIT leg  == executeDeposit (atomic import -> credit the position's
//     collateral into the D-Chain CLOB ledger). D's position (range + fee accrual)
//     lives in the CLOB, FUNDED by consuming the C->D commit object exactly once.
//   - D->C COLLECT leg == executeWithdraw (debit the LP's realized D-Chain balance —
//     principal + accrued fees the CLOB credited the maker — and atomically export it
//     back to C). C is credited ONLY by consuming this D->C object.
//
// These tests drive the REAL executors on LP-shaped value, the same way
// native_seam_roundtrip_test.go does for the swap rail, closing the LP round trip
// across the genuine atomic core. The ship rule holds: D position funded ONLY by a
// consumed C->D object; C credited ONLY by a consumed D->C object.

// TestNativeLP_CommitImportsFundsDPosition drives the REAL executeDeposit on a
// position-commit-shaped (DL01) C->D object: it consumes the object exactly once and
// credits the LP's collateral into the D-Chain ledger — the native funding of a D
// position. A position is funded ONLY by consuming this object.
func TestNativeLP_CommitImportsFundsDPosition(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	lp := ids.GenerateTestShortID()
	token := ids.GenerateTestID() // the LP's committed asset (e.g. currency0)
	const principal = 1000

	// The precompile's SubmitPositionCommit wrote a railLP C->D commit object (rail|
	// owner|asset|amount) into shared memory; model it with fundCChainRail (proven
	// byte-identical to the precompile wire in TestNativeSeam_WireMatchesPrecompile).
	commitUTXO := h.fundCChainRail(t, txs.RailLP, lp, token, principal)

	// REAL executeDeposit: atomic import (consume-once) + credit the D-Chain ledger
	// with exactly the committed value — the LP's position collateral is now funded on
	// D. The CLOB opens/rests the position against this collateral (the matcher's job).
	arDep := newAtomicRequests()
	commitTx := txs.NewImportTx(lp, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: commitUTXO, Asset: token, Amount: principal}},
		[]txs.AtomicOutput{{Rail: txs.RailLP, Owner: lp, Asset: token, Amount: principal}})
	if err := h.vm.executeDeposit(ctx, commitTx, arDep); err != nil {
		t.Fatalf("executeDeposit of DL01 commit object: %v", err)
	}
	// The commit object was consumed exactly once (atomic Remove against the source).
	req, ok := arDep.reqs[h.cChain]
	if !ok || len(req.RemoveRequests) != 1 {
		t.Fatalf("commit import must accumulate exactly one atomic Remove of the consumed C->D object")
	}
	// The D-Chain ledger now holds the LP's committed collateral (the matcher credits
	// it). The ledger is the position's funding; without this consumed object there is
	// no funding — the ship rule's C->D leg.
	if got := h.ledger.bal[ledgerKey(frameUser(lp), token)]; got != principal {
		t.Fatalf("D-Chain ledger must hold the committed principal %d, got %d", principal, got)
	}

	// REPLAY: a second import of the same commit object is rejected (consume-once), so
	// a re-executed/reorged commit cannot double-fund the position.
	arReplay := newAtomicRequests()
	if err := h.vm.executeImport(commitTx, arReplay); err == nil {
		t.Fatal("re-importing the same DL01 commit object must be rejected (consume-once)")
	}
}

// TestNativeLP_CollectExportsPrincipalPlusFees drives the REAL executeWithdraw on the
// LP's realized D-Chain balance (principal + accrued fees the CLOB credited the
// maker): it debits the ledger and atomically EXPORTS a D->C object the precompile's
// collectPosition consumes to credit C. C is credited ONLY by consuming this object.
func TestNativeLP_CollectExportsPrincipalPlusFees(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	lp := ids.GenerateTestShortID()
	token := ids.GenerateTestID()
	const principal = 1000
	const fees = 80
	const withdrawable = principal + fees // what the CLOB credited the maker

	// Fund + commit the principal (the C->D leg), then model the CLOB crediting the
	// maker `fees` more from taker flow (the ledger now owes the LP principal+fees).
	commitUTXO := h.fundCChainRail(t, txs.RailLP, lp, token, principal)
	arDep := newAtomicRequests()
	commitTx := txs.NewImportTx(lp, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: commitUTXO, Asset: token, Amount: principal}},
		[]txs.AtomicOutput{{Rail: txs.RailLP, Owner: lp, Asset: token, Amount: principal}})
	if err := h.vm.executeDeposit(ctx, commitTx, arDep); err != nil {
		t.Fatalf("commit deposit: %v", err)
	}
	h.ledger.bal[ledgerKey(frameUser(lp), token)] += fees // CLOB credits the maker its earned fees.

	// COLLECT: REAL executeWithdraw debits the LP's realized balance (clamped to
	// availability) and exports EXACTLY that back to C. The realized debit is the
	// ledger's, never more (no mint).
	arWd := newAtomicRequests()
	realized, err := h.vm.executeWithdraw(ctx, lp, token, withdrawable, h.cChain, ids.GenerateTestID(), 0, 12345, arWd)
	if err != nil {
		t.Fatalf("executeWithdraw (collect): %v", err)
	}
	if realized != withdrawable {
		t.Fatalf("collect must realize principal+fees = %d, got %d", withdrawable, realized)
	}
	// Exactly one D->C object was exported, decoding under the precompile wire to
	// (lp, token, withdrawable) — the precompile's collectPosition would credit the LP
	// exactly this. C is credited ONLY by consuming this object.
	req, ok := arWd.reqs[h.cChain]
	if !ok || len(req.PutRequests) != 1 {
		t.Fatalf("collect export must produce exactly one D->C object")
	}
	r, o, a, amt, decOK := decodeExportedOutput(req.PutRequests[0].Value)
	if !decOK || r != txs.RailLP || o != lp || a != token || amt != withdrawable {
		t.Fatalf("D->C collect object mismatch: ok=%v rail=%d owner=%v asset=%v amount=%d", decOK, r, o, a, amt)
	}
	// The ledger was fully drained for this asset (principal+fees withdrawn).
	if got := h.ledger.bal[ledgerKey(frameUser(lp), token)]; got != 0 {
		t.Fatalf("D-Chain ledger must be 0 after the full collect, got %d", got)
	}
}

// TestNativeLP_CommitCollectRoundTripConserves drives BOTH real executors end-to-end:
// commit (C->D import funds the position) -> earn fees on D -> collect (D->C export
// returns principal+fees), asserting the D side conserves — the exported value equals
// the committed principal plus the ledger-credited fees, sourced only from consumed
// objects and ledger credits, never minted.
func TestNativeLP_CommitCollectRoundTripConserves(t *testing.T) {
	h := newCustodyHarness(t)
	ctx := context.Background()

	lp := ids.GenerateTestShortID()
	token := ids.GenerateTestID()
	const principal = 1500
	const fees = 120

	// --- C->D commit (position funded). ---
	commitUTXO := h.fundCChainRail(t, txs.RailLP, lp, token, principal)
	arDep := newAtomicRequests()
	commitTx := txs.NewImportTx(lp, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: commitUTXO, Asset: token, Amount: principal}},
		[]txs.AtomicOutput{{Rail: txs.RailLP, Owner: lp, Asset: token, Amount: principal}})
	if err := h.vm.executeDeposit(ctx, commitTx, arDep); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if len(arDep.reqs[h.cChain].RemoveRequests) != 1 {
		t.Fatal("commit must consume the C->D object exactly once")
	}

	// --- D earns fees for the LP (modeled CLOB maker credit). ---
	h.ledger.bal[ledgerKey(frameUser(lp), token)] += fees

	// --- D->C collect (principal + fees returned). ---
	arWd := newAtomicRequests()
	realized, err := h.vm.executeWithdraw(ctx, lp, token, principal+fees, h.cChain, ids.GenerateTestID(), 0, 999, arWd)
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	// CONSERVATION: the LP committed `principal` (consumed C->D object) and the CLOB
	// credited `fees`; the collect exports exactly principal+fees — value moves only
	// via the consumed object + the ledger credit, never minted on the proxy.
	if realized != principal+fees {
		t.Fatalf("round-trip realized %d != committed+fees %d", realized, principal+fees)
	}
	r, o, a, amt, ok := decodeExportedOutput(arWd.reqs[h.cChain].PutRequests[0].Value)
	if !ok || r != txs.RailLP || o != lp || a != token || amt != principal+fees {
		t.Fatalf("round-trip D->C object mismatch: ok=%v rail=%d owner=%v asset=%v amount=%d", ok, r, o, a, amt)
	}
}
