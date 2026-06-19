// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"encoding/binary"
	"fmt"

	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

// custody.go is the FUNDS-IN / FUNDS-OUT rail that connects the proxy's atomic
// shared-memory leg (atomic.go) to the D-Chain balance ledger (where the money
// lives in the order book). It is the CLOB deposit/withdraw model, decomplected
// into the two primitives the proxy already owns plus a single relay:
//
//	DEPOSIT  = atomic IMPORT (debit C/X, consume the UTXO exactly once)  THEN
//	           relay clob_deposit (credit the account's available D-Chain balance).
//	           The credited D-Chain amount EQUALS the imported value — no escrow,
//	           no settlement math; the value simply MOVES into the book's ledger.
//
//	WITHDRAW = relay clob_withdraw (debit the account's realized D-Chain balance,
//	           returning the REALIZED amount the ledger actually released)  THEN
//	           atomic EXPORT of exactly that realized amount (credit C/X).
//	           A withdraw can only export realized, un-escrowed balance, so the
//	           exported value never exceeds what the ledger debited — no mint.
//
// CONSERVATION (the whole point): every unit that leaves C/X on a deposit import
// is credited into the D-Chain ledger; every unit the ledger releases on a
// withdraw is exported back to C/X. Across deposit -> (trade inside the D-Chain)
// -> withdraw, C/X value out == C/X value in for each account, to the unit. The
// trade itself conserves inside the D-Chain ledger (dchain.settleFills moves
// maker<->taker exact integers); the proxy never mints because it only ever
// imports (consume-once) and exports (realized-only).
//
// CONSENSUS NOTE (the relay LOCATION): exactly like the order relay (RED #9),
// the irreversible/non-deterministic D-Chain relay for deposit/withdraw must run
// ONCE network-wide at the PROPOSER's BuildBlock and have its result CARRIED in
// the block bytes, so every validator settles the atomic leg from carried bytes
// (never a per-validator relay). The primitives here are the relay+atomic
// composition; wiring them into BuildBlock's carried-result plan (a withdraw
// carries its realized amount; a deposit carries only an ack) is the same
// proposer-once+carry discipline obtainFills/settleCarried already implement for
// submits, and the block/vertex wire that carries them is the network-upgrade-
// gated change. These functions are written to be driven from that plan: deposit
// returns nothing to carry (idempotent credit), withdraw returns the realized
// amount to carry into the export leg.

// userHandle renders a 20-byte account address to the 16-byte user identity the
// frozen CLOB frames carry (the leading 16 bytes of the address, the same width
// zapwire.UserSize uses). The D-Chain folds this 16-byte user to its 8-byte
// UserID; binding the proxy's deposit/withdraw to the same 16-byte slice keeps
// the credited/debited account consistent with the orders that account places.
func userHandle(addr ids.ShortID) string {
	return string(addr[:])
}

// encodeDepositFrame builds the FROZEN clob_deposit payload: user[16] + asset[32]
// + amount[8] + ref[32]. Byte-identical with
// github.com/luxfi/dex/pkg/zapwire.EncodeDeposit (the proxy cannot import the
// cgo-tagged d-chain package; the hardcoded-canonical sizes move in lockstep).
// asset is the FULL 32-byte injective cross-chain id (native == ids.Empty), keyed
// at full width on the D-Chain ledger so distinct assets never collide. ref is the
// originating-tx idempotency reference (this rail uses the consumed import's tx id)
// the D-Chain folds into its seen: dedup key.
func encodeDepositFrame(user string, asset ids.ID, amount uint64, ref ids.ID) []byte {
	out := make([]byte, DepositReqSize)
	copy(out[0:16], padUser(user))
	copy(out[16:custodyAmountOff], asset[:])
	binary.BigEndian.PutUint64(out[custodyAmountOff:custodyRefOff], amount)
	copy(out[custodyRefOff:custodyRefOff+RefSize], ref[:])
	return out
}

// encodeWithdrawFrame builds the FROZEN clob_withdraw payload: user[16] +
// asset[32] + amount[8] + ref[32]. asset is the FULL 32-byte injective cross-chain
// id (native == ids.Empty). ref is the originating-tx idempotency reference (this
// rail uses the settlement fillRef) the D-Chain folds into its seen: key.
func encodeWithdrawFrame(user string, asset ids.ID, amount uint64, ref ids.ID) []byte {
	out := make([]byte, WithdrawReqSize)
	copy(out[0:16], padUser(user))
	copy(out[16:custodyAmountOff], asset[:])
	binary.BigEndian.PutUint64(out[custodyAmountOff:custodyRefOff], amount)
	copy(out[custodyRefOff:custodyRefOff+RefSize], ref[:])
	return out
}

// padUser left-copies a user identity into a fresh 16-byte (UserSize) buffer,
// null-padded — the frozen frame's user field encoding.
func padUser(user string) []byte {
	b := make([]byte, 16)
	copy(b, user)
	return b
}

// decodeBalanceResp reads (status, realized amount) from a clob_deposit /
// clob_withdraw response (status[1] + amount[8]). A short response is malformed
// wire and is refused — the proxy never derives a settlement amount from garbage.
func decodeBalanceResp(resp []byte) (status uint8, amount uint64, err error) {
	if len(resp) < BalanceRespSize {
		return 0, 0, fmt.Errorf("dexvm custody: balance response too short: %d", len(resp))
	}
	return resp[0], binary.BigEndian.Uint64(resp[1:9]), nil
}

// executeDeposit runs the DEPOSIT rail for one import: atomically claim the
// imported value (consume-once) and relay a clob_deposit to credit exactly that
// value into the importer's available D-Chain balance. The credited amount is the
// import's total output value (the value locked by the atomic leg), so the
// D-Chain ledger gains precisely what C/X lost — conservation across the rail.
//
// The relay is the irreversible/non-deterministic leg; in production it runs once
// at the proposer's BuildBlock (carried as an idempotent ack). Here it composes
// the already-tested executeImport with the relay so a caller (BuildBlock plan,
// or the conservation test) gets the full funds-in path in one call.
func (vm *VM) executeDeposit(ctx context.Context, tx *txs.ImportTx, ar *atomicRequests) error {
	// 1) Atomic import: consume the source UTXO(s), accumulate the remove. This is
	//    the SAME consume-once-guarded primitive the escrow path used; the only
	//    difference is what happens to the value next (credited to the D-Chain
	//    ledger, not recorded as proxy escrow).
	if err := vm.executeImport(tx, ar); err != nil {
		return err
	}
	// 2) Credit the D-Chain ledger with exactly the imported value, in the imported
	//    asset, for the importer. A deposit with no credited outputs (pure fee
	//    burn) credits nothing.
	if len(tx.Outputs) == 0 {
		return nil
	}
	owner := tx.Outputs[0].Owner
	// The FULL 32-byte cross-chain asset id (native == ids.Empty) — keyed at full
	// width on the D-Chain ledger so distinct imported assets never collide.
	asset := tx.Outputs[0].Asset
	var amount uint64
	for _, o := range tx.Outputs {
		// All outputs of a single deposit are the same (owner, asset) — sum the
		// imported value into one ledger credit.
		amount += o.Amount
	}
	// The ref is the import tx's own id — the cross-chain identity of THIS deposit,
	// consumed exactly once on the atomic leg. Threading it into the clob_deposit
	// frame makes a genuinely-distinct import distinct on the D-Chain seen: index
	// (so a second genuine deposit credits separately, matching its own atomic
	// import); a true retry of the same import (same id) dedups exactly once.
	frame := encodeDepositFrame(userHandle(owner), asset, amount, tx.ID())
	resp, err := vm.relay.Relay(ctx, ZAPMethodDeposit, frame)
	if err != nil {
		return fmt.Errorf("dexvm custody: deposit relay: %w", err)
	}
	status, credited, derr := decodeBalanceResp(resp)
	if derr != nil {
		return derr
	}
	// The D-Chain must credit exactly the imported value; a short credit would
	// strand value (imported but not in the ledger). Refuse the divergence rather
	// than silently lose funds.
	if credited != amount {
		return fmt.Errorf("dexvm custody: deposit credited %d != imported %d (status %d)", credited, amount, status)
	}
	return nil
}

// executeWithdraw runs the WITHDRAW rail for one account/asset: relay a
// clob_withdraw to debit the account's realized available D-Chain balance
// (returning the REALIZED amount the ledger released, clamped to availability),
// then atomically EXPORT exactly that realized amount back to the destination
// chain. The export value is the ledger's realized debit, so C/X gains precisely
// what the D-Chain ledger released — never more (no mint).
//
// owner is the account (its address); asset is the cross-chain asset id; want is
// the requested withdrawal (the ledger clamps it to available). destChain is
// where the value is exported (C-Chain). fillRef binds the export for audit AND is
// now the clob_withdraw idempotency ref the D-Chain folds into its seen: key, so
// it MUST be UNIQUE per genuine withdraw: two distinct withdraws sharing a fillRef
// would collide on the D-Chain seen: index and the second would replay the first
// realized amount against an already-exported balance (a proxy-rail double export).
// Every current caller passes a unique id (tests: ids.GenerateTestID; the future
// BuildBlock carry-result plan must derive a per-withdraw-unique ref, e.g. the
// settlement/UTXO id). The returned realized amount is what was exported (0 =>
// nothing available, no export
// built). The relay is the irreversible leg (proposer-once + carry the realized
// amount in production).
func (vm *VM) executeWithdraw(ctx context.Context, owner ids.ShortID, asset ids.ID, want uint64, destChain, fillRef ids.ID, txIndex uint32, createdAt int64, ar *atomicRequests) (uint64, error) {
	// Consume-once on the settlement fillRef (R2), checked BEFORE the irreversible
	// relay so a duplicate withdraw fails fast without re-debiting the D-Chain or
	// double-exporting. Mirrors executeImport's IsConsumed/MarkConsumed on the
	// import UTXO id, using the SAME state consumed-set. The MarkConsumed is deferred
	// to after a successful relay with a positive realized amount (below), so a relay
	// FAILURE or a zero-realized withdraw never burns the ref — a legitimate retry of
	// a failed withdraw still works, while a genuine duplicate is rejected here.
	if consumed, cerr := vm.state.IsConsumed(fillRef); cerr != nil {
		return 0, fmt.Errorf("dexvm custody: withdraw consumed check: %w", cerr)
	} else if consumed {
		return 0, fmt.Errorf("dexvm custody: withdraw: %w: %s", errFillRefAlreadyExported, fillRef)
	}
	// The ref is the settlement fillRef — the unique reference that already binds
	// this withdraw's export for audit. Threading it into the clob_withdraw frame
	// makes a genuinely-distinct withdraw distinct on the D-Chain seen: index, so a
	// second genuine withdraw re-clamps to CURRENT available rather than replaying
	// the first realized amount against an already-exported balance (the drain).
	frame := encodeWithdrawFrame(userHandle(owner), asset, want, fillRef)
	resp, err := vm.relay.Relay(ctx, ZAPMethodWithdraw, frame)
	if err != nil {
		return 0, fmt.Errorf("dexvm custody: withdraw relay: %w", err)
	}
	_, realized, derr := decodeBalanceResp(resp)
	if derr != nil {
		return 0, derr
	}
	if realized == 0 {
		return 0, nil // nothing available to withdraw; no export leg
	}
	if realized > want {
		// The ledger released MORE than requested — impossible for a clamped
		// withdraw and a mint risk. Refuse rather than export the excess.
		return 0, fmt.Errorf("dexvm custody: withdraw realized %d exceeds requested %d (mint risk)", realized, want)
	}
	// Commit the fillRef to the consume-once set NOW that a real export will follow
	// (relay succeeded, realized>0). A second withdraw with this fillRef is refused
	// at the IsConsumed gate above before it can double-export (R2).
	if cerr := vm.state.MarkConsumed(fillRef); cerr != nil {
		return 0, fmt.Errorf("dexvm custody: withdraw mark consumed: %w", cerr)
	}
	// Atomic export of EXACTLY the realized amount in the withdrawn asset.
	out := []txs.AtomicOutput{{Owner: owner, Asset: asset, Amount: realized}}
	exportTx := txs.NewSettlementExportTx(owner, txIndex, destChain, out, fillRef, createdAt)
	if err := vm.executeExport(exportTx, ar); err != nil {
		return 0, fmt.Errorf("dexvm custody: withdraw export: %w", err)
	}
	return realized, nil
}
