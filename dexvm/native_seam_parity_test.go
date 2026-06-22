// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"encoding/hex"
	"testing"

	"github.com/luxfi/chains/dexvm/txs"
	"github.com/luxfi/ids"
)

// native_seam_parity_test.go pins the C<->D atomic object wire BYTE-FOR-BYTE on the dexvm
// (D) side. It is the twin of the precompile's native_seam_parity_test.go: BOTH repos encode
// the SAME shared-memory UTXO value — rail(1) | owner(20) | asset(32) | amount(8) | spent(8)
// = 69 bytes — and a one-sided change is a silent consensus break (D exports a width C cannot
// decode -> every swap settlement reverts and no taker is credited). The golden vector below
// is IDENTICAL to the precompile's parityGoldenHex; if either repo's layout drifts, one of the
// two parity tests fails before the bytes reach consensus. The trailing spent(8) is the
// matched-input witness the C-side ImportSettlement reads to enforce the taker-authenticated
// MEV floor; it MUST round-trip on this side too.
const parityGoldenHex = "00" + // rail (RailSwap)
	"112233445566778899aabbccddeeff0102030405" + // owner (20)
	"a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf" + // asset (32)
	"0102030405060708" + // amount (8, big-endian)
	"1112131415161718" //   spent  (8, big-endian)

func parityOwner() ids.ShortID {
	return ids.ShortID{
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa,
		0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x01, 0x02, 0x03, 0x04, 0x05,
	}
}

func parityAsset() ids.ID {
	var a ids.ID
	for i := range a {
		a[i] = byte(0xA0 + i)
	}
	return a
}

// TestSeamWire_GoldenMatchesPrecompile pins the dexvm encoder against the cross-repo golden:
// encodeExportedOutput must produce the EXACT bytes the precompile's encodeAtomicObjectSpent
// does for the same inputs (lockstep), at the canonical 69-byte width.
func TestSeamWire_GoldenMatchesPrecompile(t *testing.T) {
	want, err := hex.DecodeString(parityGoldenHex)
	if err != nil {
		t.Fatalf("bad golden hex: %v", err)
	}
	if len(want) != exportedOutputSize {
		t.Fatalf("golden width %d != exportedOutputSize %d — the wire changed on ONE side only "+
			"(consensus break). Update BOTH repos in lockstep.", len(want), exportedOutputSize)
	}
	out := txs.AtomicOutput{
		Rail:   txs.RailSwap,
		Owner:  parityOwner(),
		Asset:  parityAsset(),
		Amount: 0x0102030405060708,
		Spent:  0x1112131415161718,
	}
	got := encodeExportedOutput(out)
	if hex.EncodeToString(got) != parityGoldenHex {
		t.Fatalf("dexvm seam wire DIVERGED from the precompile golden:\n got=%s\nwant=%s\n"+
			"the C<->D atomic object is no longer byte-identical — every swap settlement would fail "+
			"to decode on C. Re-align atomic.go with precompile/dex/native_wire.go.",
			hex.EncodeToString(got), parityGoldenHex)
	}
}

// TestSeamWire_RoundTripCarriesSpent pins that decode is the exact inverse of encode and that
// the trailing spent witness survives — the value the MEV floor depends on.
func TestSeamWire_RoundTripCarriesSpent(t *testing.T) {
	out := txs.AtomicOutput{
		Rail:   txs.RailSwap,
		Owner:  parityOwner(),
		Asset:  parityAsset(),
		Amount: 9_000_000,
		Spent:  4_500_000,
	}
	enc := encodeExportedOutput(out)
	rail, owner, asset, amount, spent, ok := decodeExportedOutput(enc)
	if !ok {
		t.Fatal("decode of a canonical 69-byte object must succeed")
	}
	if rail != out.Rail || owner != out.Owner || asset != out.Asset || amount != out.Amount {
		t.Fatalf("round-trip mismatch: rail=%d owner=%x asset=%x amount=%d", rail, owner, asset, amount)
	}
	if spent != out.Spent {
		t.Fatalf("round-trip SPENT = %d, want %d — the matched-input witness was lost (the C-side MEV "+
			"floor would silently read 0 and never engage).", spent, out.Spent)
	}
}

// TestSeamWire_WrongWidthRejected pins that a non-canonical width never decodes (the corrupt-
// record defense; a stale 61-byte object or any other width is refused, never read as value).
func TestSeamWire_WrongWidthRejected(t *testing.T) {
	for _, n := range []int{0, 60, 61, 68, 70, 100} {
		if _, _, _, _, _, ok := decodeExportedOutput(make([]byte, n)); ok {
			t.Fatalf("a %d-byte object must NOT decode (only the canonical %d is valid)", n, exportedOutputSize)
		}
	}
}
