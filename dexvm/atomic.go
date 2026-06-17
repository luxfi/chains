// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"encoding/binary"
	"fmt"
	"math"

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
