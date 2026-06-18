// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"encoding/binary"
	"fmt"
	"hash"
	"math"
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
func (vm *VM) executeImport(tx *txs.ImportTx, ar *atomicRequests) error {
	if err := tx.Verify(); err != nil {
		return fmt.Errorf("import verify: %w", err)
	}

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
		if err := vm.state.MarkConsumed(in.UTXOID); err != nil {
			return fmt.Errorf("import: mark consumed: %w", err)
		}
		id := in.UTXOID
		utxoIDs = append(utxoIDs, id[:])
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
	if len(tx.Outputs) > 0 {
		ref := tx.ImportedInputs[0].UTXOID
		lockedAsset := tx.Outputs[0].Asset
		var locked uint64
		for _, o := range tx.Outputs {
			locked += o.Amount
		}
		if err := vm.state.PutEscrow(ref, lockedAsset, locked); err != nil {
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

// encodeExportedOutput serializes an AtomicOutput as the shared-memory value:
// owner(20) | asset(32) | amount(8). Fixed-width, deterministic.
func encodeExportedOutput(out txs.AtomicOutput) []byte {
	v := make([]byte, 20+32+8)
	copy(v[0:20], out.Owner[:])
	copy(v[20:52], out.Asset[:])
	binary.BigEndian.PutUint64(v[52:60], out.Amount)
	return v
}

// float64FromBits reads a big-endian IEEE-754 float64 (the ZAP fill wire codec,
// byte-identical with dex/pkg/api and the precompile).
func float64FromBits(b []byte) float64 {
	return math.Float64frombits(binary.BigEndian.Uint64(b))
}

// isFinitePositive reports whether f is a finite, strictly positive number — the
// only values a real fill can carry. Rejects NaN/Inf/<=0.
func isFinitePositive(f float64) bool {
	return !math.IsNaN(f) && !math.IsInf(f, 0) && f > 0
}

// ---------------------------------------------------------------------------
// Conservation-safe float->integer rounding for settlement.
//
// Fills cross the ZAP wire as float64 (price, size); on-chain value moves in
// integer asset units (uint64). Converting a fractional notional to an integer
// MUST round in the direction that protects the conservation invariant — the
// proxy NEVER mints — so the rounding is asymmetric BY PURPOSE:
//
//   - quantToCredit (FLOOR): a quantity the taker RECEIVES (proceeds) or that
//     REDUCES what we owe back. Round DOWN so the proxy never credits a unit it
//     did not truly realize. Worst case the taker is under-credited by <1 unit;
//     that sub-unit is conserved on the d-chain side (the maker's leg), never
//     fabricated out of the proxy.
//   - quantToCharge (CEIL): a quantity the taker SPENDS against locked escrow
//     (so refund = locked - spent). Round UP so spent is never UNDERstated.
//     Understating spent is exactly the escrow-truncation mint (RED): it inflates
//     the refund, letting the taker walk away with proceeds PLUS more refund than
//     the unspent remainder. Ceiling spent caps refund at the true unspent value.
//
// Both take an EXACT float aggregate (summed over fills once, not per-fill
// truncated — per-fill truncation accumulates a directional leak) and apply the
// rounding ONCE at the asset boundary. A small relative epsilon absorbs IEEE-754
// representation error so an aggregate that is mathematically integral (e.g.
// 1.5*3 + 2.5*3 == 12, but may evaluate to 12 ± 1e-13) snaps to that integer
// instead of spuriously rounding to 11 or 13. epsilon is deterministic (a fixed
// constant over deterministic float inputs) so every validator rounds identically.

// settlementRoundEpsilon is the relative tolerance for snapping a float aggregate
// to a neighboring integer before directional rounding. ~1e-9 dwarfs the ~1e-13
// double-rounding error of summing realistic fill streams yet is far below one
// asset unit, so it never moves a genuinely fractional notional across an integer.
const settlementRoundEpsilon = 1e-9

// nearestIntWithin returns (n, true) when f is within a relative epsilon of the
// integer n, else (0, false). Used to snap a mathematically-integral aggregate
// back to its integer before floor/ceil.
func nearestIntWithin(f float64) (float64, bool) {
	r := math.Round(f)
	tol := settlementRoundEpsilon * math.Max(1, math.Abs(f))
	if math.Abs(f-r) <= tol {
		return r, true
	}
	return 0, false
}

// quantToCredit converts a proceeds aggregate to integer asset units, rounding
// DOWN (never credit more than realized). Non-finite or negative input, or a
// result exceeding uint64, is refused — the proxy must not settle a value it
// cannot represent exactly.
func quantToCredit(f float64) (uint64, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0, fmt.Errorf("settle: non-finite proceeds %v", f)
	}
	if r, ok := nearestIntWithin(f); ok {
		f = r
	} else {
		f = math.Floor(f)
	}
	if f > maxSettlementUnit {
		return 0, fmt.Errorf("settle: proceeds %v exceeds uint64", f)
	}
	return uint64(f), nil
}

// quantToCharge converts a spent aggregate to integer asset units, rounding UP
// (never charge less than consumed, so the refund is never inflated). Same
// finiteness / range guards as quantToCredit.
func quantToCharge(f float64) (uint64, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) || f < 0 {
		return 0, fmt.Errorf("settle: non-finite notional %v", f)
	}
	if r, ok := nearestIntWithin(f); ok {
		f = r
	} else {
		f = math.Ceil(f)
	}
	if f > maxSettlementUnit {
		return 0, fmt.Errorf("settle: notional %v exceeds uint64", f)
	}
	return uint64(f), nil
}

// maxSettlementUnit is the largest float64 that converts to uint64 without
// overflow on rounding. 2^64 is not exactly representable; the largest float64
// strictly below it is 2^64 - 2048. Using <= against this constant keeps the
// uint64() conversion in-range and deterministic.
const maxSettlementUnit = float64(1<<64 - 2048)
