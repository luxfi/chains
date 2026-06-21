// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"testing"

	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

// native_rail_bind_test.go proves the D side of the H1 rail bind (defense in depth,
// symmetric to the precompile's C-side gates): executeImport binds the credited
// outputs' RAIL to the consumed UTXO's RECORDED rail, so an import cannot re-lane
// value — credit a railSwap object onto the LP lane or a railLP object onto the swap
// lane. The recorded rail (written by the export side via encodeExportedOutput) is
// authoritative; the importing tx cannot freely choose it.

// TestNativeRail_ImportRejectsRailMismatch — an import whose declared output rail
// disagrees with the consumed UTXO's RECORDED rail is REJECTED (errImportMixedRails),
// so a cross-rail object cannot be re-laned at the import. Proven on both directions
// (railSwap object claimed as LP, railLP object claimed as swap).
func TestNativeRail_ImportRejectsRailMismatch(t *testing.T) {
	cases := []struct {
		name     string
		recorded txs.Rail // the rail written into the source UTXO
		claimed  txs.Rail // the rail the importing tx's output declares
	}{
		{"swap-object-claimed-as-LP", txs.RailSwap, txs.RailLP},
		{"LP-object-claimed-as-swap", txs.RailLP, txs.RailSwap},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newCustodyHarness(t)
			owner := ids.GenerateTestShortID()
			token := ids.GenerateTestID()
			const amount = 1000

			// The source UTXO records `recorded` rail.
			utxo := h.fundCChainRail(t, tc.recorded, owner, token, amount)

			// The importing tx declares the MISMATCHED `claimed` rail on its output.
			ar := newAtomicRequests()
			tx := txs.NewImportTx(owner, 0, h.cChain,
				[]txs.AtomicInput{{UTXOID: utxo, Asset: token, Amount: amount}},
				[]txs.AtomicOutput{{Rail: tc.claimed, Owner: owner, Asset: token, Amount: amount}})
			err := h.vm.executeImport(tx, ar)
			if err == nil {
				t.Fatal("a cross-rail import (output rail != recorded UTXO rail) MUST be rejected")
			}
			// The consumed-set must be UNTOUCHED on a rejected import (all-or-nothing) —
			// the rightful owner can still claim the UTXO on its correct rail.
			consumed, cerr := h.vm.state.IsConsumed(utxo)
			if cerr != nil {
				t.Fatalf("IsConsumed: %v", cerr)
			}
			if consumed {
				t.Fatal("a rejected cross-rail import must NOT burn the consumed UTXO")
			}
		})
	}
}

// TestNativeRail_ImportAcceptsMatchingRail — the positive control: an import whose
// output rail MATCHES the recorded UTXO rail succeeds on BOTH lanes, so the rail bind
// is a precise match, not a blanket refusal.
func TestNativeRail_ImportAcceptsMatchingRail(t *testing.T) {
	for _, rail := range []txs.Rail{txs.RailSwap, txs.RailLP} {
		h := newCustodyHarness(t)
		owner := ids.GenerateTestShortID()
		token := ids.GenerateTestID()
		const amount = 1000

		utxo := h.fundCChainRail(t, rail, owner, token, amount)
		ar := newAtomicRequests()
		tx := txs.NewImportTx(owner, 0, h.cChain,
			[]txs.AtomicInput{{UTXOID: utxo, Asset: token, Amount: amount}},
			[]txs.AtomicOutput{{Rail: rail, Owner: owner, Asset: token, Amount: amount}})
		if err := h.vm.executeImport(tx, ar); err != nil {
			t.Fatalf("rail %d: a matching-rail import must succeed, got: %v", rail, err)
		}
		if len(ar.reqs[h.cChain].RemoveRequests) != 1 {
			t.Fatalf("rail %d: a matching-rail import must consume the UTXO exactly once", rail)
		}
	}
}
