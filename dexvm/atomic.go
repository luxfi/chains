// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"encoding/binary"
	"fmt"
	"hash"
	"math/big"
	"sort"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chains/atomic"

	"github.com/luxfi/chains/dexvm/txs"
)

// atomic.go — the VALUE SETTLEMENT leg of the stateless atomic ZAP proxy.
//
// This is the ONLY primitive in the proxy that moves value between two chains
// in a single atomic commit, modeled byte-for-byte on the platformvm Import/
// Export executors (node/vms/platformvm/txs/executor/standard_tx_executor.go
// ImportTx/ExportTx) and committed at block accept via atomic.SharedMemory.Apply
// (the acceptor.go:103-110 pattern). It is the X<->C shared-memory import/export
// the proxy was specced to do.
//
// CONSERVATION ORDERING (non-negotiable): import (atomic C-Chain debit into the
// proxy) -> ZAP submit to the d-chain (relay.go) -> export (atomic C-Chain
// credit) derived ONLY from the d-chain's returned fills; unfilled IOC remainder
// refunded via the export leg. The proxy NEVER mints — every exported element's
// value is value already locked by an import or already returned as a confirmed
// fill.

// atomicRequests is the per-block accumulation of cross-chain operations to
// apply atomically with the state batch at accept time.
type atomicRequests struct {
	// reqs maps a peer chainID to its remove (import) / put (export) operations.
	reqs map[ids.ID]*atomic.Requests
}

func newAtomicRequests() *atomicRequests {
	return &atomicRequests{reqs: make(map[ids.ID]*atomic.Requests)}
}

// empty reports whether no cross-chain operations were accumulated.
func (a *atomicRequests) empty() bool { return len(a.reqs) == 0 }

// forChain returns (creating if needed) the Requests for a peer chain.
func (a *atomicRequests) forChain(chainID ids.ID) *atomic.Requests {
	r, ok := a.reqs[chainID]
	if !ok {
		r = &atomic.Requests{}
		a.reqs[chainID] = r
	}
	return r
}

// hashInto folds a deterministic commitment of the accumulated cross-chain
// operations into h. The atomic requests are the block's OTHER mutated output
// (alongside the persisted state) — the import UTXO removes and the export UTXO
// puts that move value across chains. Binding them into the StateRoot is what
// makes a block whose settlement legs differ (one node exported a settle, a peer
// whose relay failed exported nothing) produce a different root, even when its
// state keys and block hash match.
//
// Determinism: the per-chain map is walked in sorted chainID order (Go map
// iteration is randomized). Within a chain the RemoveRequests and PutRequests
// keep their accumulation order — that order is itself deterministic (txs are
// processed in block order). Every variable-length field is length-prefixed so
// no two distinct request sets can collide by concatenation.
func (a *atomicRequests) hashInto(h hash.Hash) {
	chainIDs := make([]ids.ID, 0, len(a.reqs))
	for id := range a.reqs {
		chainIDs = append(chainIDs, id)
	}
	sort.Slice(chainIDs, func(i, j int) bool { return chainIDs[i].Compare(chainIDs[j]) < 0 })

	var lenBuf [8]byte
	writeChunk := func(b []byte) {
		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(b)))
		h.Write(lenBuf[:])
		h.Write(b)
	}

	for _, id := range chainIDs {
		req := a.reqs[id]
		idCopy := id
		h.Write(idCopy[:])

		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(req.RemoveRequests)))
		h.Write(lenBuf[:])
		for _, rm := range req.RemoveRequests {
			writeChunk(rm)
		}

		binary.BigEndian.PutUint64(lenBuf[:], uint64(len(req.PutRequests)))
		h.Write(lenBuf[:])
		for _, e := range req.PutRequests {
			writeChunk(e.Key)
			writeChunk(e.Value)
			binary.BigEndian.PutUint64(lenBuf[:], uint64(len(e.Traits)))
			h.Write(lenBuf[:])
			for _, tr := range e.Traits {
				writeChunk(tr)
			}
		}
	}
}

// executeImport applies an ImportTx: it claims value exported from the source
// chain by consuming its UTXOs from shared memory. The consumed-UTXO set
// guarantees each exported UTXO is claimable exactly once (no double-import).
// The RemoveRequests are accumulated and committed atomically at accept.
//
// Mirrors platformvm standard_tx_executor.go:285 ImportTx — Consume the source
// UTXOs via a shared-memory RemoveRequest keyed by the source chain.
//
// ASSET BIND (the native-aliasing fix): an import credits the ledger with the
// asset of the UTXO it ACTUALLY consumes, never an asset it merely declares. The
// consumed UTXO's recorded value (owner|asset|amount, written by the export side
// via encodeExportedOutput) is read back from shared memory and is authoritative:
// the declared input asset/amount MUST equal the recorded asset/amount, every
// consumed UTXO must be the SAME asset, and every credited output must name that
// asset. Composed with ImportTx.Verify (output.Asset == input.Asset), the credit
// is provably the consumed asset — so a bogus-token UTXO cannot be imported as
// native value. (When the runtime has no shared memory — single-chain test mode —
// there is no real cross-chain UTXO to read or alias; the structural Verify bind
// still holds.)
func (vm *VM) executeImport(tx *txs.ImportTx, ar *atomicRequests) error {
	if err := tx.Verify(); err != nil {
		return fmt.Errorf("import verify: %w", err)
	}

	sm := vm.sharedMemory()
	var (
		importedAsset ids.ID
		importedOwner ids.ShortID
		importedRail  txs.Rail
		haveAsset     bool
	)
	// PASS 1 — VALIDATE every input + output with NO state mutation. The import is
	// atomic: a rejection on ANY input/output bind must leave the consumed-set
	// UNTOUCHED, so MarkConsumed is deferred to pass 2 below. (A bind failure after
	// MarkConsumed would burn the UTXO on a rejected import, blocking the rightful
	// owner's later claim — the all-or-nothing discipline the conservation invariant
	// requires.)
	utxoIDs := make([][]byte, 0, len(tx.ImportedInputs))
	for _, in := range tx.ImportedInputs {
		// Double-spend guard: a UTXO already consumed by a prior import cannot
		// be claimed again. This is the proxy's replay protection for the
		// atomic-value leg (the conservation invariant — the proxy never mints).
		consumed, err := vm.state.IsConsumed(in.UTXOID)
		if err != nil {
			return fmt.Errorf("import: consumed check: %w", err)
		}
		if consumed {
			return fmt.Errorf("import: %w: %s", errUTXOAlreadyImported, in.UTXOID)
		}
		// Bind the declared input to the UTXO the chain ACTUALLY holds. The remove
		// has not been applied yet (it commits at accept), so the recorded value is
		// still readable here. A UTXO that does not exist in shared memory errors —
		// the proxy never credits an unbacked input.
		if sm != nil {
			id := in.UTXOID
			vals, gerr := sm.Get(tx.SourceChain, [][]byte{id[:]})
			if gerr != nil {
				return fmt.Errorf("import: read source UTXO %s: %w", in.UTXOID, gerr)
			}
			recRail, recOwner, recAsset, recAmount, _, ok := decodeExportedOutput(vals[0])
			if !ok {
				return fmt.Errorf("import: UTXO %s: %w", in.UTXOID, errImportUTXOValueMalformed)
			}
			if in.Asset != recAsset {
				return fmt.Errorf("import: UTXO %s: %w (declared %s, recorded %s)", in.UTXOID, errImportAssetMismatch, in.Asset, recAsset)
			}
			if in.Amount != recAmount {
				return fmt.Errorf("import: UTXO %s: %w (declared %d, recorded %d)", in.UTXOID, errImportAmountMismatch, in.Amount, recAmount)
			}
			if !haveAsset {
				importedAsset = recAsset
				importedOwner = recOwner
				importedRail = recRail
				haveAsset = true
			} else {
				if importedAsset != recAsset {
					return fmt.Errorf("import: %w", errImportMixedAssets)
				}
				// Every consumed UTXO must share ONE recorded owner: a deposit credits
				// one (owner,asset) ledger row, and mixing owners would let one UTXO's
				// owner authorize spending another's value.
				if importedOwner != recOwner {
					return fmt.Errorf("import: %w (UTXO %s owner %s != %s)", errImportWrongOwner, in.UTXOID, recOwner, importedOwner)
				}
				// Every consumed UTXO must share ONE recorded rail (lane): an import
				// funds a single lane, and mixing lanes would let a swap object and an LP
				// object be claimed in one credit (the cross-rail consume H1 closes).
				if importedRail != recRail {
					return fmt.Errorf("import: %w (UTXO %s rail %d != %d)", errImportMixedRails, in.UTXOID, recRail, importedRail)
				}
			}
		}
		id := in.UTXOID
		utxoIDs = append(utxoIDs, id[:])
	}

	// Every credited output must be denominated in the asset actually consumed AND
	// owned by the consumed UTXO's recorded owner — the authoritative half of the
	// native-aliasing bind (asset axis; the structural output==input half is also
	// pinned in ImportTx.Verify) and the owner-aliasing bind (owner axis; an attacker
	// must not consume a victim's exported UTXO and credit it to their own account).
	// Skipped only when no shared memory was read (single-chain test mode), where
	// Verify's structural bind already holds (and there is no real cross-chain UTXO
	// to alias).
	if haveAsset {
		for _, o := range tx.Outputs {
			if o.Asset != importedAsset {
				return fmt.Errorf("import: %w (output %s, consumed %s)", errImportOutputAsset, o.Asset, importedAsset)
			}
			if o.Owner != importedOwner {
				return fmt.Errorf("import: %w (output owner %s, consumed %s)", errImportWrongOwner, o.Owner, importedOwner)
			}
			// Authoritative rail bind: every credited output must be on the SAME lane
			// the consumed UTXO recorded — so an import cannot re-lane value (credit a
			// swap object onto the LP lane or vice-versa). Composed with Verify's
			// structural output-rail-uniformity, the credit is provably the consumed
			// object's rail (the H1 fix, owner/asset/rail all pinned to the record).
			if o.Rail != importedRail {
				return fmt.Errorf("import: %w (output rail %d, consumed %d)", errImportMixedRails, o.Rail, importedRail)
			}
		}
	}

	// PASS 2 — COMMIT: all binds passed, so mark every consumed UTXO now (the import
	// is accepted as a whole). After this point the import cannot fail.
	for _, in := range tx.ImportedInputs {
		if err := vm.state.MarkConsumed(in.UTXOID); err != nil {
			return fmt.Errorf("import: mark consumed: %w", err)
		}
	}

	// Accumulate the atomic remove against the source chain. Applied with the
	// state batch at accept (sm.Apply), exactly as platformvm does.
	req := ar.forChain(tx.SourceChain)
	req.RemoveRequests = append(req.RemoveRequests, utxoIDs...)

	// Record the locked collateral so the settle leg can refund whatever the
	// d-chain does NOT fill (value conservation: value_in == proceeds + refund).
	// Keyed by the import's collateral ref — its first imported UTXO id, the same
	// id a relay binds to via RelayOrderTx.CollateralRef. The locked amount is
	// the credited output total; its asset is the locked asset. An import with no
	// credited outputs (pure fee burn) locks nothing to refund.
	//
	// The escrow's OWNER is the AUTHENTICATED owner of the consumed C->D object —
	// importedOwner, read back from shared memory and bound to every credited output
	// above. This is the CRITICAL escrow-theft fix: settleFromFills derives BOTH the
	// settle authority and the proceeds/refund payout target from this recorded
	// owner, never from the unauthenticated relay tx sender, so a relay naming a
	// victim's collateral ref cannot settle it or redirect its value. When there is
	// no shared memory (single-chain test mode) there is no real cross-chain UTXO to
	// authenticate against; the structurally-verified credited owner (Outputs[0].Owner,
	// pinned uniform with the asset/rail axes in Verify) is the escrow owner.
	if len(tx.Outputs) > 0 {
		ref := tx.ImportedInputs[0].UTXOID
		lockedAsset := tx.Outputs[0].Asset
		escrowOwner := importedOwner
		if !haveAsset {
			escrowOwner = tx.Outputs[0].Owner
		}
		var locked uint64
		for _, o := range tx.Outputs {
			locked += o.Amount
		}
		if err := vm.state.PutEscrow(ref, escrowOwner, lockedAsset, locked); err != nil {
			return fmt.Errorf("import: record escrow: %w", err)
		}
	}
	return nil
}

// executeExport applies an ExportTx: it settles proceeds back to the
// destination chain by writing UTXO elements into shared memory. The exported
// amounts MUST have been derived ONLY from confirmed d-chain fills (the caller's
// responsibility — see settleFromFills); this executor enforces the wire shape
// and accumulates the PutRequests for the atomic accept-time commit.
//
// Mirrors platformvm standard_tx_executor.go:378 ExportTx — Produce exported
// UTXO elements (Key=utxoID, Value=utxoBytes, Traits=owner) into a PutRequest
// keyed by the destination chain.
func (vm *VM) executeExport(tx *txs.ExportTx, ar *atomicRequests) error {
	if err := tx.Verify(); err != nil {
		return fmt.Errorf("export verify: %w", err)
	}

	txID := tx.ID()
	elems := make([]*atomic.Element, 0, len(tx.ExportedOutputs))
	for i, out := range tx.ExportedOutputs {
		utxoID := deriveUTXOID(txID, uint32(i))
		elems = append(elems, &atomic.Element{
			Key:   utxoID[:],
			Value: encodeExportedOutput(out),
			// Trait = owner address, so the destination chain can index the UTXO
			// by recipient (mirrors lux.Addressable.Addresses()).
			Traits: [][]byte{out.Owner[:]},
		})
	}

	req := ar.forChain(tx.DestinationChain)
	req.PutRequests = append(req.PutRequests, elems...)
	return nil
}

// commitAtomic applies the accumulated cross-chain operations atomically with
// the proxy's state batch — the single commit point (the acceptor.go:103-110
// pattern). When the runtime has no SharedMemory (the no-atomic test harness),
// it falls back to writing the batch directly so value semantics still hold.
func (vm *VM) commitAtomic(ar *atomicRequests, batch database.Batch) error {
	sm := vm.sharedMemory()
	if sm == nil {
		// No-atomic fallback: write the state batch ourselves (the acceptor's
		// else-branch). A nil shared memory means single-chain test mode.
		if batch != nil {
			return batch.Write()
		}
		return nil
	}
	if ar.empty() {
		// Nothing cross-chain this block; still commit the state batch.
		if batch != nil {
			return batch.Write()
		}
		return nil
	}
	if batch == nil {
		return sm.Apply(ar.reqs)
	}
	return sm.Apply(ar.reqs, batch)
}

// sharedMemory returns the per-chain atomic.SharedMemory handed to the proxy by
// the chain manager (runtime.Runtime.SharedMemory), or nil in the test harness.
func (vm *VM) sharedMemory() atomic.SharedMemory {
	if vm.consensusRuntime == nil {
		return nil
	}
	sm := vm.consensusRuntime.GetSharedMemory()
	if sm == nil {
		return nil
	}
	// runtime.SharedMemory is a type alias for atomic.SharedMemory.
	return sm
}

// ---------------------------------------------------------------------------
// Wire helpers for exported UTXO elements + fill decoding.
// ---------------------------------------------------------------------------

// deriveUTXOID computes a deterministic UTXO id from (txID, outputIndex),
// mirroring lux.UTXOID.InputID() — SHA-256 over txID||index. Keeping it local
// avoids dragging the platformvm codec into the proxy.
func deriveUTXOID(txID ids.ID, index uint32) ids.ID {
	var buf [36]byte
	copy(buf[0:32], txID[:])
	binary.BigEndian.PutUint32(buf[32:36], index)
	return ids.ID(idHash(buf[:]))
}

// exportedOutputSize is the fixed shared-memory UTXO value width: rail(1) |
// owner(20) | asset(32) | amount(8) | spent(8). IDENTICAL to the precompile's
// exportedOutputSize9999 — the rail byte (the H1 lane tag) leads the object and the
// trailing spent(8) carries the matched INPUT amount on a swap proceeds leg (0 on every
// other leg) so the C-side ImportSettlement can enforce the taker's recorded slippage
// limit independently of the keeper (the taker-authenticated MEV floor). Both repos
// extend this width in lockstep; native_seam_parity_test pins it.
const exportedOutputSize = 1 + 20 + 32 + 8 + 8

// encodeExportedOutput serializes an AtomicOutput as the shared-memory value:
// rail(1) | owner(20) | asset(32) | amount(8) | spent(8). Fixed-width, deterministic.
// The rail byte is the lane the value travels (RailSwap / RailLP), bound by the
// precompile's matching consume path on the C side; spent is the matched input that
// produced a proceeds output (0 elsewhere), the price-binding witness the proceeds floor
// checks.
func encodeExportedOutput(out txs.AtomicOutput) []byte {
	v := make([]byte, exportedOutputSize)
	v[0] = byte(out.Rail)
	copy(v[1:21], out.Owner[:])
	copy(v[21:53], out.Asset[:])
	binary.BigEndian.PutUint64(v[53:61], out.Amount)
	binary.BigEndian.PutUint64(v[61:69], out.Spent)
	return v
}

// decodeExportedOutput is the inverse of encodeExportedOutput: it reads back the
// (rail, owner, asset, amount, spent) a consumed source UTXO RECORDED in shared memory.
// executeImport uses this to bind the credited rail, asset AND owner to the value the
// chain actually holds for that UTXO — not what the importing tx merely declares — so
// a bogus-token UTXO can never be imported as native value (the native-aliasing fix),
// a victim's exported UTXO can never be credited to an attacker's account (the
// owner-aliasing fix), and a cross-rail object can never fund the wrong lane (the H1
// rail fix). spent is meaningful only on a swap proceeds leg (the MEV floor witness);
// import ignores it. ok=false for any value that is not exactly the canonical width, so
// a corrupt/garbage record is never reinterpreted into a credit.
func decodeExportedOutput(v []byte) (rail txs.Rail, owner ids.ShortID, asset ids.ID, amount, spent uint64, ok bool) {
	if len(v) != exportedOutputSize {
		return 0, ids.ShortEmpty, ids.Empty, 0, 0, false
	}
	rail = txs.Rail(v[0])
	copy(owner[:], v[1:21])
	copy(asset[:], v[21:53])
	amount = binary.BigEndian.Uint64(v[53:61])
	spent = binary.BigEndian.Uint64(v[61:69])
	return rail, owner, asset, amount, spent, true
}

// ---------------------------------------------------------------------------
// Exact-integer settlement arithmetic.
//
// Fills cross the ZAP wire as EXACT integers (price is uint64 fixed-point
// ×PriceScale on the matcher's PriceInt grid; size is uint64 atomic base units),
// and on-chain value moves in the same integer asset units. There is therefore NO
// fractional notional to round and — critically — NO value-bearing float→int
// conversion anywhere on the settlement path (that conversion's out-of-range
// result is implementation-defined per the Go spec and differs by CPU
// architecture; carrying and settling exact integers is what killed the cross-arch
// consensus fork). The proxy derives base and quote from the fills with the SAME
// per-fill floor the venue's matcher (quoteUnitsFor) and the precompile's
// fillsToDelta apply, so the proxy moves EXACTLY what the venue moved — byte-for-
// byte on every validator — and the conservation invariant (the proxy never mints)
// is a direct integer identity, not a rounding argument.

// priceScaleBig is PriceScale as a *big.Int (the fixed-point divisor for quote).
var priceScaleBig = new(big.Int).SetUint64(PriceScale)

// quoteUnits returns one fill's quote in exact integers: floor(size × price /
// PriceScale), where size is atomic base units and price is fixed-point ×PriceScale.
// The multiply is done in big.Int (size × price overflows uint64) and floored by
// integer division, mirroring dex v1.14.0's v4BalanceDelta / the matcher's
// quoteUnitsFor. Returned as *big.Int so the caller accumulates without overflow.
func quoteUnits(size, price uint64) *big.Int {
	q := new(big.Int).Mul(new(big.Int).SetUint64(size), new(big.Int).SetUint64(price))
	return q.Quo(q, priceScaleBig)
}

// settleUint64 narrows an exact aggregate (base or quote, summed in big.Int) to a
// uint64 asset amount, refusing a value the proxy cannot represent exactly rather
// than wrapping it. label names the leg for the error. Negative is impossible
// (every summand is non-negative) but is refused defensively.
func settleUint64(v *big.Int, label string) (uint64, error) {
	if v.Sign() < 0 {
		return 0, fmt.Errorf("settle: negative %s %s", label, v.String())
	}
	if !v.IsUint64() {
		return 0, fmt.Errorf("settle: %s %s exceeds uint64", label, v.String())
	}
	return v.Uint64(), nil
}
