// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build redteam

package dexvm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"testing"
	"time"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

// swapRelayFromField re-encodes a relay's wire bytes (type(1)|JSON) with ONLY the
// "from" field changed to newFrom, leaving the signature and every other field
// byte-identical — so a Verify failure isolates the From axis.
func swapRelayFromField(t *testing.T, wire []byte, newFrom ids.ShortID) []byte {
	t.Helper()
	var m map[string]json.RawMessage
	if err := json.Unmarshal(wire[1:], &m); err != nil {
		t.Fatalf("unmarshal relay body: %v", err)
	}
	fromJSON, err := newFrom.MarshalJSON()
	if err != nil {
		t.Fatalf("marshal from: %v", err)
	}
	m["from"] = fromJSON
	body, err := json.Marshal(m)
	if err != nil {
		t.Fatalf("remarshal relay body: %v", err)
	}
	return append([]byte{wire[0]}, body...)
}

// redteam_escrow_owner_test.go is the CRITICAL escrow-theft RED suite. It proves
// the FIXED ship rule for the swap rail's value-return leg:
//
//	the collateral an import locks is owned by the AUTHENTICATED owner recorded on
//	the consumed C->D object; ONLY that owner may settle it, and the proceeds +
//	refund are exported to THAT owner — never to the relay tx's (unauthenticated)
//	sender.
//
// The pre-fix exploit (proven CLOSED here): the escrow stored only (asset, amount)
// with NO owner, and settleFromFills exported both legs to `taker = r.sender` (the
// RelayOrderTx sender). RelayOrderTx.Verify authenticated nothing, so any fee-paying
// tx could name a VICTIM's collateral ref with an attacker From; a ~zero fill made
// refund == locked, exported to the attacker out of the SHARED seam reserve =
// cross-depositor theft. Now the escrow records the importer's owner and settle
// binds BOTH authority and payout to it.

// TestRED_Escrow_SettleBoundToImporterOwner is the END-TO-END theft proof on the
// real import -> relay -> settle path. A victim imports collateral; an ATTACKER
// submits a RelayOrderTx naming the victim's collateral ref with the attacker as
// From. At settle (proposer build+accept), the refund/proceeds MUST go to the
// victim (the recorded escrow owner) and the attacker MUST receive nothing.
func TestRED_Escrow_SettleBoundToImporterOwner(t *testing.T) {
	// Zero fills => the whole locked collateral is a refund (the cleanest theft
	// vector: attacker tries to walk away with the full lock).
	cvm, matcher, cChainSM, proxyChain, _ := newCountingHarness(t, nil)
	ctx := context.Background()

	victim := ids.GenerateTestShortID()
	attacker := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()
	const locked uint64 = 1000

	// The VICTIM imports 1000 of `asset` (the C-Chain exported it to the proxy for
	// the victim; the import binds the escrow owner = victim from the recorded UTXO).
	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, victim, asset, locked)
	importTx := newImportTxBytes(t, victim, cvm.inner.cChainID(), srcUTXOID, asset, locked)

	// The ATTACKER submits a settling relay (clob_submit) naming the VICTIM's
	// collateral ref, with the attacker as the tx sender (From). Pre-fix this would
	// export the refund to the attacker; post-fix the settle is bound to the escrow
	// owner (victim) and refuses/redirects.
	attackerRelay := newRelayTxBytes(t, attacker, srcUTXOID, clobSubmitPayload(asset, locked))

	// Proposer builds (relays once; matcher returns ZERO fills) + accepts (settle).
	cvm.inner.clock.Set(time.Unix(1, 0))
	cvm.pendingTxs = [][]byte{importTx, attackerRelay}
	built, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := cvm.SetPreference(ctx, built.ID()); err != nil {
		t.Fatalf("SetPreference: %v", err)
	}
	if err := built.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	attackerCredited := creditedTo(t, cChainSM, proxyChain, attacker)
	victimCredited := creditedTo(t, cChainSM, proxyChain, victim)
	t.Logf("AFTER ATTACKER-RELAY SETTLE: attacker credited=%d  victim credited=%d (locked=%d)",
		attackerCredited, victimCredited, locked)

	// THE THEFT IS CLOSED: the attacker (the relay sender, NOT the escrow owner)
	// receives NOTHING. The collateral never leaves the victim's ownership.
	if attackerCredited != 0 {
		t.Fatalf("ESCROW THEFT: the attacker (relay sender, not the escrow owner) was credited %d "+
			"out of the victim's locked collateral — settle authority + payout MUST bind to the "+
			"recorded escrow owner, never the unauthenticated relay sender.", attackerCredited)
	}
	// The escrow is left intact for the rightful owner (the unauthorized settle is
	// refused before it consumes the escrow), so the victim's value is recoverable.
	_, _, _, found, eerr := cvm.inner.state.GetEscrow(srcUTXOID)
	if eerr != nil {
		t.Fatalf("escrow lookup: %v", eerr)
	}
	if !found {
		t.Fatalf("ESCROW THEFT: the unauthorized attacker settle CONSUMED the victim's escrow — a " +
			"refused settle must leave the escrow intact and recoverable by the rightful owner.")
	}
	if submits, _, _ := matcher.counts(); submits != 1 {
		t.Fatalf("expected exactly one proposer relay submit, got %d", submits)
	}
}

// TestRED_Escrow_OwnerMaySettleAndIsPaid is the POSITIVE control: when the
// RIGHTFUL owner (the importer) submits the settling relay, the settle succeeds and
// the owner is paid the full refund. The bind is authority, not a blanket denial.
func TestRED_Escrow_OwnerMaySettleAndIsPaid(t *testing.T) {
	cvm, matcher, cChainSM, proxyChain, _ := newCountingHarness(t, nil) // zero fills => full refund
	ctx := context.Background()

	owner := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()
	const locked uint64 = 1000

	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, owner, asset, locked)
	importTx := newImportTxBytes(t, owner, cvm.inner.cChainID(), srcUTXOID, asset, locked)
	ownerRelay := newRelayTxBytes(t, owner, srcUTXOID, clobSubmitPayload(asset, locked))

	cvm.inner.clock.Set(time.Unix(1, 0))
	cvm.pendingTxs = [][]byte{importTx, ownerRelay}
	built, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := cvm.SetPreference(ctx, built.ID()); err != nil {
		t.Fatalf("SetPreference: %v", err)
	}
	if err := built.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	credited := creditedTo(t, cChainSM, proxyChain, owner)
	t.Logf("AFTER RIGHTFUL-OWNER SETTLE: owner credited=%d (locked=%d)", credited, locked)
	if credited != locked {
		t.Fatalf("the rightful escrow owner's settle must refund the full locked %d, got %d", locked, credited)
	}
	// The escrow is consumed exactly once by the legitimate settle.
	if _, _, _, found, _ := cvm.inner.state.GetEscrow(srcUTXOID); found {
		t.Fatalf("a completed legitimate settle must consume the escrow exactly once (still present)")
	}
	if submits, _, _ := matcher.counts(); submits != 1 {
		t.Fatalf("expected exactly one proposer relay submit, got %d", submits)
	}
}

// TestRED_Escrow_DirectSettleRejectsForeignSender pins the authority bind at the
// unit level (independent of the build path): settleFromFills with a sender that is
// NOT the recorded escrow owner returns errSettleUnauthorized and moves no value,
// leaving the escrow intact.
func TestRED_Escrow_DirectSettleRejectsForeignSender(t *testing.T) {
	cvm, _, _, _, _ := newCountingHarness(t, nil)

	owner := ids.GenerateTestShortID()
	foreign := ids.GenerateTestShortID()
	ref := deriveUTXOID(ids.GenerateTestID(), 0)
	asset := ids.GenerateTestID()
	const locked uint64 = 500

	if err := cvm.inner.state.PutEscrow(ref, owner, asset, locked); err != nil {
		t.Fatalf("PutEscrow: %v", err)
	}

	// A foreign sender (not the escrow owner) attempts to settle => refused.
	ar := newAtomicRequests()
	err := cvm.inner.settleFromFills(foreign, ref, nil, ids.Empty, 0, false, ids.GenerateTestID(), 0, ar)
	if err != errSettleUnauthorized {
		t.Fatalf("a settle by a non-owner sender MUST return errSettleUnauthorized, got: %v", err)
	}
	if !ar.empty() {
		t.Fatalf("a refused (unauthorized) settle must export nothing")
	}
	// The escrow is intact — the rightful owner can still settle it.
	if _, _, _, found, _ := cvm.inner.state.GetEscrow(ref); !found {
		t.Fatalf("a refused unauthorized settle must leave the escrow intact")
	}

	// The rightful owner then settles successfully (zero fills => full refund).
	ar2 := newAtomicRequests()
	if err := cvm.inner.settleFromFills(owner, ref, nil, ids.Empty, 0, false, ids.GenerateTestID(), 1, ar2); err != nil {
		t.Fatalf("the rightful owner's settle must succeed, got: %v", err)
	}
	var refundToOwner uint64
	for _, reqs := range ar2.reqs {
		for _, e := range reqs.PutRequests {
			if len(e.Value) >= exportedOutputSize {
				var o ids.ShortID
				copy(o[:], e.Value[1:21]) // export wire: rail(1)|owner(20)|asset(32)|amount(8)
				if o == owner {
					refundToOwner += binary.BigEndian.Uint64(e.Value[53:61])
				}
			}
		}
	}
	if refundToOwner != locked {
		t.Fatalf("the rightful owner must be refunded the full locked %d, got %d", locked, refundToOwner)
	}
}

// --- Signature-authentication of RelayOrderTx.From (provenance hardening) -------

// TestRED_Relay_SignatureAuthenticatesFrom proves the present-gated secp256k1 bind
// on RelayOrderTx.From: a tx signed by `from`'s key Verifies; the SAME tx with From
// swapped to a victim (a spoofed-From relay carrying someone else's signature) is
// REFUSED at admission with ErrInvalidSignature; an unsigned tx is permitted (From
// carries no authority — the escrow bind is the authority).
func TestRED_Relay_SignatureAuthenticatesFrom(t *testing.T) {
	key, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	ref := deriveUTXOID(ids.GenerateTestID(), 0)

	// (a) A signed relay Verifies and stamps From = the signer's EVM address.
	signed := txs.NewRelayOrderTx(ids.ShortEmpty, 0, ZAPMethodSubmit, []byte{0x01}, ref)
	if err := signed.Sign(key); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if ids.ShortID(key.EVMAddress()) != signed.Sender() {
		t.Fatalf("Sign must set From to the signer's EVM address")
	}
	if err := signed.Verify(); err != nil {
		t.Fatalf("a correctly-signed relay must Verify, got: %v", err)
	}
	// The signed tx must survive a wire round-trip and still Verify (the signature
	// commits to the unsigned image, not to itself).
	parser := &txs.TxParser{}
	reparsed, perr := parser.Parse(signed.Bytes())
	if perr != nil {
		t.Fatalf("reparse signed relay: %v", perr)
	}
	if err := reparsed.Verify(); err != nil {
		t.Fatalf("a reparsed signed relay must Verify, got: %v", err)
	}

	// (b) SPOOFED From: re-encode the EXACT signed wire image with ONLY From swapped to
	// a victim, then reparse + Verify. The signature still recovers to the original
	// signer, not to the (victim) From, so the bind refuses it => ErrInvalidSignature.
	// (Mutating the parsed JSON's "from" field isolates the spoof to the From axis.)
	victim := ids.GenerateTestShortID()
	spoofWire := swapRelayFromField(t, signed.Bytes(), victim)
	spoof, perr2 := parser.Parse(spoofWire)
	if perr2 != nil {
		t.Fatalf("parse spoof wire: %v", perr2)
	}
	if err := spoof.Verify(); err != txs.ErrInvalidSignature {
		t.Fatalf("a spoofed-From relay (someone else's signature) MUST revert ErrInvalidSignature, got: %v", err)
	}

	// (c) UNSIGNED relay is permitted at admission (From has no authority; the escrow
	// owner bind is what governs settlement — see TestRED_Escrow_*).
	unsigned := txs.NewRelayOrderTx(victim, 0, ZAPMethodSubmit, []byte{0x01}, ref)
	if err := unsigned.Verify(); err != nil {
		t.Fatalf("an unsigned relay must be admitted (authority is the escrow bind), got: %v", err)
	}
}

// TestRED_Escrow_SignedAttackerStillCannotSteal is the defense-in-depth proof: even
// a VALID signature (the attacker signs with their OWN key, so From is authentic) does
// NOT let the attacker settle a victim's collateral — because the settle authority +
// payout bind to the escrow's recorded owner (the victim), not to the authenticated
// relay sender. Layer 1 (escrow owner) holds independently of Layer 2 (signature).
func TestRED_Escrow_SignedAttackerStillCannotSteal(t *testing.T) {
	cvm, _, cChainSM, proxyChain, _ := newCountingHarness(t, nil)
	ctx := context.Background()

	attackerKey, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	attacker := ids.ShortID(attackerKey.EVMAddress())
	victim := ids.GenerateTestShortID()
	asset := ids.GenerateTestID()
	const locked uint64 = 1000

	srcUTXOID := seedExportedUTXO(t, cChainSM, proxyChain, victim, asset, locked)
	importTx := newImportTxBytes(t, victim, cvm.inner.cChainID(), srcUTXOID, asset, locked)

	// The attacker signs a settling relay with their OWN key (so the signature is
	// VALID and From == attacker), naming the victim's collateral ref.
	relay := txs.NewRelayOrderTx(ids.ShortEmpty, 0, ZAPMethodSubmit, clobSubmitPayload(asset, locked), srcUTXOID)
	if err := relay.Sign(attackerKey); err != nil {
		t.Fatalf("attacker sign: %v", err)
	}
	if err := relay.Verify(); err != nil {
		t.Fatalf("attacker's own-key signature must itself Verify (it is authentic), got: %v", err)
	}

	cvm.inner.clock.Set(time.Unix(1, 0))
	cvm.pendingTxs = [][]byte{importTx, relay.Bytes()}
	built, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := cvm.SetPreference(ctx, built.ID()); err != nil {
		t.Fatalf("SetPreference: %v", err)
	}
	if err := built.Verify(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	if err := built.Accept(ctx); err != nil {
		t.Fatalf("accept: %v", err)
	}

	attackerCredited := creditedTo(t, cChainSM, proxyChain, attacker)
	t.Logf("AFTER SIGNED-ATTACKER SETTLE: attacker credited=%d (locked=%d)", attackerCredited, locked)
	if attackerCredited != 0 {
		t.Fatalf("DEFENSE-IN-DEPTH BROKEN: an attacker with a VALID signature (authentic From) was "+
			"credited %d of the victim's collateral — settle authority MUST be the escrow's recorded "+
			"owner (the victim), independent of who signed the relay.", attackerCredited)
	}
	// Escrow intact (unauthorized settle refused before consuming it).
	if _, _, _, found, _ := cvm.inner.state.GetEscrow(srcUTXOID); !found {
		t.Fatalf("a refused signed-attacker settle must leave the victim's escrow intact")
	}
}
