// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"encoding/binary"
	"testing"

	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

// native_seam_roundtrip_test.go proves the D side of the native C<->D atomic
// settlement seam (precompile/dex 0x9999) consumes/produces the EXACT wire the C
// side reads/writes. The precompile encodes a cross-chain object as
// owner(20)|asset(32)|amount(8) (precompile/dex/native_wire.go encodeAtomicObject),
// byte-identical to this VM's encodeExportedOutput; this test:
//
//  1. asserts that byte-identity (the contract between the two repos), and
//  2. drives the REAL executeImport (C->D leg) on a precompile-shaped object and
//     the REAL executeExport (D->C leg) producing an object the precompile decodes.
//
// Together with the precompile-side Test9999RoundTrip_CToDMatchDToC (which drives
// the real precompile client over a real atomic.SharedMemory), this closes the
// round trip: C creates a C->D object -> D imports+matches -> D exports a D->C
// object -> C imports+credits, with one wire format on both ends.

// encodeAtomicObjectC replicates precompile/dex.encodeAtomicObject byte-for-byte:
// rail(1) | owner(20) | asset(32) | amount(8). (The chains repo cannot import the
// precompile — it is a leaf library, and importing it would invert the dependency —
// so the 61-byte contract is replicated here and asserted byte-identical to the VM's
// own encodeExportedOutput below.)
func encodeAtomicObjectC(rail txs.Rail, owner ids.ShortID, asset ids.ID, amount uint64) []byte {
	v := make([]byte, 1+20+32+8)
	v[0] = byte(rail)
	copy(v[1:21], owner[:])
	copy(v[21:53], asset[:])
	binary.BigEndian.PutUint64(v[53:61], amount)
	return v
}

// TestNativeSeam_WireMatchesPrecompile asserts the precompile's C<->D object wire
// is byte-identical to this VM's encodeExportedOutput, so an object written by one
// side is consumed natively by the other. A drift here would silently break the
// seam (the import would read a misaligned asset/amount), so this is the canary.
func TestNativeSeam_WireMatchesPrecompile(t *testing.T) {
	owner := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()
	const amount = 123456789

	// Assert byte-identity on BOTH rails — the rail byte (object[0]) must round-trip
	// identically through the VM's encode and the precompile-replicated encode.
	for _, rail := range []txs.Rail{txs.RailSwap, txs.RailLP} {
		fromVM := encodeExportedOutput(txs.AtomicOutput{Rail: rail, Owner: owner, Asset: asset, Amount: amount})
		fromPrecompile := encodeAtomicObjectC(rail, owner, asset, amount)

		if len(fromVM) != exportedOutputSize {
			t.Fatalf("VM object width %d != canonical %d", len(fromVM), exportedOutputSize)
		}
		if len(fromPrecompile) != exportedOutputSize {
			t.Fatalf("precompile object width %d != canonical %d", len(fromPrecompile), exportedOutputSize)
		}
		for i := range fromVM {
			if fromVM[i] != fromPrecompile[i] {
				t.Fatalf("rail %d wire drift at byte %d: VM=%02x precompile=%02x", rail, i, fromVM[i], fromPrecompile[i])
			}
		}
		// And the VM decodes the precompile-shaped object to the same (rail, owner, asset, amount).
		r, o, a, amt, ok := decodeExportedOutput(fromPrecompile)
		if !ok || r != rail || o != owner || a != asset || amt != amount {
			t.Fatalf("VM decode of precompile object mismatch: ok=%v rail=%d owner=%v asset=%v amt=%d", ok, r, o, a, amt)
		}
	}
}

// TestNativeSeam_CtoD_ImportsPrecompileObject drives the REAL executeImport on a
// C->D object written in the PRECOMPILE's wire format. This is the D side of the
// C->D leg: D is funded ONLY by consuming the C->D object the precompile wrote.
func TestNativeSeam_CtoD_ImportsPrecompileObject(t *testing.T) {
	h := newCustodyHarness(t)

	owner := ids.GenerateTestShortID()
	token := ids.GenerateTestID()
	const amount = 5000

	// Write the C->D object EXACTLY as the precompile's SubmitSwapIntent would
	// (precompile-shaped bytes), into the shared-memory partition the proxy imports
	// from. fundCChain uses encodeExportedOutput, proven byte-identical above, so this
	// is the precompile's wire on the wire.
	utxo := h.fundCChain(t, owner, token, amount)

	// REAL executeImport consumes it and credits the D-side ledger in the consumed
	// asset for exactly the amount — the native funding of the D order/position.
	ar := newAtomicRequests()
	tx := txs.NewImportTx(owner, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: utxo, Asset: token, Amount: amount}},
		[]txs.AtomicOutput{{Owner: owner, Asset: token, Amount: amount}})
	if err := h.vm.executeImport(tx, ar); err != nil {
		t.Fatalf("executeImport of precompile-shaped C->D object: %v", err)
	}
	// The import accumulated a Remove of the consumed object against the source chain
	// (the atomic consume committed at accept) — D consumed the C->D object exactly
	// once. A second import of the same object is replay-rejected (proven by the
	// existing TestImportReplaySameUTXORejects).
	req, ok := ar.reqs[h.cChain]
	if !ok || len(req.RemoveRequests) != 1 {
		t.Fatalf("import must accumulate exactly one atomic Remove of the consumed C->D object")
	}
}

// TestNativeSeam_DtoC_ExportDecodesAsPrecompileObject drives the REAL executeExport
// (D->C leg) and asserts the produced object decodes under the PRECOMPILE's wire
// shape — so the precompile's ImportSettlement consumes it natively. This is the
// D side of the D->C leg: C is credited ONLY by consuming this object.
func TestNativeSeam_DtoC_ExportDecodesAsPrecompileObject(t *testing.T) {
	h := newCustodyHarness(t)

	owner := ids.GenerateTestShortID()
	token := ids.GenerateTestID()
	const amount = 90

	// REAL executeExport writes a D->C object (the settlement proceeds) into shared
	// memory keyed by the destination (C) chain.
	ar := newAtomicRequests()
	exp := txs.NewSettlementExportTx(owner, 0, h.cChain,
		[]txs.AtomicOutput{{Owner: owner, Asset: token, Amount: amount}},
		ids.GenerateTestID(), 12345)
	if err := h.vm.executeExport(exp, ar); err != nil {
		t.Fatalf("executeExport: %v", err)
	}
	req, ok := ar.reqs[h.cChain]
	if !ok || len(req.PutRequests) != 1 {
		t.Fatalf("export must produce exactly one D->C object")
	}
	obj := req.PutRequests[0].Value

	// The precompile decodes this object (rail|owner|asset|amount) and binds the credit
	// to it. Replicate the precompile's decode (decodeAtomicObject) at the canonical
	// offsets and assert it reads the exact recorded value — i.e. the precompile would
	// credit `owner` exactly `amount` of `token` on the swap rail (a fill export).
	if len(obj) != exportedOutputSize {
		t.Fatalf("D->C object width %d != canonical %d", len(obj), exportedOutputSize)
	}
	pRail := txs.Rail(obj[0])
	var pOwner ids.ShortID
	copy(pOwner[:], obj[1:21])
	var pAsset ids.ID
	copy(pAsset[:], obj[21:53])
	pAmount := binary.BigEndian.Uint64(obj[53:61])
	if pRail != txs.RailSwap || pOwner != owner || pAsset != token || pAmount != amount {
		t.Fatalf("precompile decode of D->C object mismatch: rail=%d owner=%v asset=%v amount=%d", pRail, pOwner, pAsset, pAmount)
	}

	// The export Trait is the owner address (so the precompile / destination indexes
	// the object by recipient) — the same Trait the precompile filters on.
	if len(req.PutRequests[0].Traits) != 1 || string(req.PutRequests[0].Traits[0]) != string(owner[:]) {
		t.Fatalf("D->C object Trait must be the owner address for recipient indexing")
	}
}

// TestNativeSeam_FullRoundTrip drives BOTH real executors in sequence: a
// precompile-shaped C->D object is imported (funding D), then D exports a D->C
// object that decodes under the precompile wire (crediting C) — the complete
// C->D->C round trip across the real dexvm atomic executors.
func TestNativeSeam_FullRoundTrip(t *testing.T) {
	h := newCustodyHarness(t)
	_ = context.Background()

	taker := ids.GenerateTestShortID()
	tokenIn := ids.GenerateTestID()
	tokenOut := ids.GenerateTestID()

	// --- C->D: import the precompile-shaped intent object (D funded). ---
	inUTXO := h.fundCChain(t, taker, tokenIn, 100)
	arIn := newAtomicRequests()
	imp := txs.NewImportTx(taker, 0, h.cChain,
		[]txs.AtomicInput{{UTXOID: inUTXO, Asset: tokenIn, Amount: 100}},
		[]txs.AtomicOutput{{Owner: taker, Asset: tokenIn, Amount: 100}})
	if err := h.vm.executeImport(imp, arIn); err != nil {
		t.Fatalf("round-trip C->D import: %v", err)
	}

	// --- D matches (modeled): 100 tokenIn -> 90 tokenOut. ---
	// --- D->C: export the settlement object (C credited on import). ---
	arOut := newAtomicRequests()
	exp := txs.NewSettlementExportTx(taker, 0, h.cChain,
		[]txs.AtomicOutput{{Owner: taker, Asset: tokenOut, Amount: 90}},
		inUTXO, 777)
	if err := h.vm.executeExport(exp, arOut); err != nil {
		t.Fatalf("round-trip D->C export: %v", err)
	}

	// The D->C object decodes to (taker, tokenOut, 90) under the precompile wire —
	// the precompile would credit the taker exactly 90 tokenOut. Conservation: the
	// taker's 100 tokenIn was consumed on C (import Remove) and 90 tokenOut returns
	// (export Put) — value moves only via these atomic objects, never minted.
	obj := arOut.reqs[h.cChain].PutRequests[0].Value
	r, o, a, amt, ok := decodeExportedOutput(obj)
	if !ok || r != txs.RailSwap || o != taker || a != tokenOut || amt != 90 {
		t.Fatalf("round-trip D->C object mismatch: ok=%v rail=%d owner=%v asset=%v amt=%d", ok, r, o, a, amt)
	}
	if len(arIn.reqs[h.cChain].RemoveRequests) != 1 {
		t.Fatalf("round-trip: C->D object must be consumed exactly once")
	}
}
