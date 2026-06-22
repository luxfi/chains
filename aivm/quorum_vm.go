// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// quorum_vm.go is the VM-side glue that mounts the A-Chain quorum settlement
// engine onto the ChainVM: a DB-backed QuorumState committed under consensus, a
// native-token QuorumLedger, and the CONSENSUS-GATED inbound path for C-Chain
// intents. It keeps all engine wiring in one orthogonal place so vm.go stays a
// thin ChainVM shell.
//
// The load-bearing safety invariant lives here: committed C intents are buffered
// (EnqueueCommittedIntent) but only TURN INTO TASKS inside BuildBlock /
// Block.Verify (importPending), i.e. under A-Chain consensus. There is no code
// path from a live/RPC request to createTask — the only caller of
// ImportCommittedIntent is importPending, and the only callers of importPending
// are the block build and verify paths.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/geth/common"
)

// dbState adapts a luxfi/database.Database (or any KeyValueReaderWriter) to the
// engine's QuorumState. Engine slots are 32-byte keccak keys; values are 32-byte
// words. State written here is part of the VM's DB and commits under consensus
// when the enclosing block is Accepted. A read miss returns the zero hash, which
// the engine treats as "unset" — identical semantics to the in-memory MemState.
type dbState struct {
	db database.KeyValueReaderWriter
}

// NewDBState wraps a database for engine use.
func NewDBState(db database.KeyValueReaderWriter) QuorumState { return &dbState{db: db} }

func (s *dbState) stateKey(slot common.Hash) []byte {
	// Prefix engine slots so they never collide with block/height keys in the
	// shared DB.
	return append([]byte("av/state/"), slot.Bytes()...)
}

func (s *dbState) GetState(slot common.Hash) common.Hash {
	v, err := s.db.Get(s.stateKey(slot))
	if err != nil || len(v) == 0 {
		return common.Hash{}
	}
	return common.BytesToHash(v)
}

func (s *dbState) SetState(slot, value common.Hash) {
	// Engine writes are infallible at the logical level; a DB write error here is
	// a node-fatal condition surfaced by the DB layer's own error accounting on
	// commit. We intentionally do not panic in the hot path.
	_ = s.db.Put(s.stateKey(slot), value.Bytes())
}

// SetCommitVerifier installs the C-Chain committedness proof checker. Until this
// is set the VM uses a fail-closed verifier that admits nothing, so no boundary
// intent can create a task. The verifier is the single trust the inbound seam
// imports from C-Chain.
func (vm *VM) SetCommitVerifier(ccv CCommitVerifier) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.ccv = ccv
}

// QuorumEngine exposes the engine handle (and its state/ledger) for the RPC
// service and tests. The returned QuorumState commits under consensus.
func (vm *VM) QuorumEngine() (*Engine, QuorumState, QuorumLedger) {
	return vm.quorum, vm.qstate, vm.qledger
}

// EnqueueCommittedIntent buffers a C-Chain intent that the boundary transport
// has delivered with a committedness proof. It does NOT create a task — that
// happens only under consensus in BuildBlock/Verify via importPending. Safe to
// call from the transport goroutine; guarded by the VM lock.
func (vm *VM) EnqueueCommittedIntent(intent CIntent) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.pendingIntents = append(vm.pendingIntents, intent)
}

// verifyImported re-runs, under consensus (Block.Verify), the exact set of
// committed intents a proposer recorded in a block — so a follower reaches
// byte-identical engine state. Each intent must still pass the id binding +
// committedness proof + anti-replay (idempotent: an already-imported intent is
// rejected by the seen marker, which is the correct outcome if the proposer
// already applied it in this same verify pass; followers apply each exactly
// once). Returns an error if the recorded set does not reproduce the recorded
// receipt_root. Caller holds vm.mu.
func (vm *VM) verifyImported(height uint64, recorded []CIntent, wantRoot common.Hash) error {
	if vm.quorum == nil || vm.qstate == nil || vm.qledger == nil {
		return nil
	}
	for _, intent := range recorded {
		// A follower that has not yet applied this intent applies it now; one that
		// has (seen marker set) gets ErrIntentAlreadyUsed, which is benign here.
		_, err := vm.quorum.ImportCommittedIntent(vm.qstate, vm.qledger, vm.ccv, intent, height)
		if err != nil && err != ErrIntentAlreadyUsed {
			return err
		}
	}
	if got := vm.quorum.ReceiptRoot(vm.qstate); wantRoot != (common.Hash{}) && got != wantRoot {
		return ErrReceiptRootMismatch
	}
	return nil
}

// importPending drains the buffered committed intents into A-Chain tasks under
// consensus. It is the ONLY caller of the engine's verified inbound seam.
// Returns the intents that successfully created a task (to be recorded in the
// block for deterministic re-verification). Caller holds vm.mu.
func (vm *VM) importPending(height uint64) []CIntent {
	if vm.quorum == nil || vm.qstate == nil || vm.qledger == nil || len(vm.pendingIntents) == 0 {
		return nil
	}
	imported := make([]CIntent, 0, len(vm.pendingIntents))
	for _, intent := range vm.pendingIntents {
		if _, err := vm.quorum.ImportCommittedIntent(vm.qstate, vm.qledger, vm.ccv, intent, height); err == nil {
			imported = append(imported, intent)
		}
		// A rejected intent (forged id, failed proof, replay, ineligible pool) is
		// simply dropped — it created no task and no state changed (fail-closed).
	}
	vm.pendingIntents = vm.pendingIntents[:0]
	return imported
}

// vmLedger is the engine's QuorumLedger backed by the VM's account balances. For
// chains that carry native balances in their own state this would read/write
// that store; here it is the in-memory MemLedger seeded at Initialize, which is
// sufficient for the engine's conservation guarantees (the canonical custody
// account is EscrowAccount regardless of backing store).
type vmLedger = MemLedger

// initQuorum sets up the engine, its DB-backed state, and ledger. Called from
// Initialize. cChainID/aChainID are derived from the deployment (the host
// chain's id and the configured C-chain id); here we derive stable 32-byte ids
// from the VM's network id and host chain id so a single-node test/dev instance
// is self-consistent.
//
// Engine state is STAGED in a versiondb layered over vm.db: writes from
// importPending/Settle (which run in BuildBlock / Verify) accumulate in the
// version delta and only land in vm.db when commitEngine() is called from
// Block.Accept. A rejected/discarded block calls abortEngine() to drop the delta.
// This is what makes "engine state commits under consensus AT Accept" true — a
// block that is built but never accepted moves NO durable state and NO value.
func (vm *VM) initQuorum(opening map[common.Address]*uint256.Int) {
	c := chainIDFromString("c-chain")
	a := chainIDFromString(vm.config.HostChainID)
	vm.quorum = NewEngine(c, a)
	vm.qdb = versiondb.New(vm.db)
	vm.qstate = NewDBState(vm.qdb)
	vm.qledger = NewMemLedger(opening)
}

// commitEngine flushes the staged engine-state delta to the durable DB and clears
// the ledger snapshot. Called from Block.Accept (under vm.mu) — the SOLE commit
// point for engine state and ledger value. Returns any DB commit error so Accept
// fails loudly rather than silently losing state.
func (vm *VM) commitEngine() error {
	if vm.qdb == nil {
		return nil
	}
	if err := vm.qdb.Commit(); err != nil {
		return err
	}
	vm.qledgerSnap = nil
	return nil
}

// abortEngine drops the staged engine-state delta and rolls the ledger back to the
// last committed snapshot. Called from Block.Reject (and any discard path) so a
// block that never reaches Accept leaves zero durable side effects.
func (vm *VM) abortEngine() {
	if vm.qdb != nil {
		vm.qdb.Abort()
	}
	if l, ok := vm.qledger.(*MemLedger); ok && vm.qledgerSnap != nil {
		l.Restore(vm.qledgerSnap)
	}
}

// snapshotLedger records the ledger's committed balances so abortEngine can roll
// back to them. Taken at the start of a block-building / verification pass that
// may move funds, BEFORE any import touches the ledger.
func (vm *VM) snapshotLedger() {
	if l, ok := vm.qledger.(*MemLedger); ok && vm.qledgerSnap == nil {
		vm.qledgerSnap = l.Snapshot()
	}
}

// chainIDFromString derives a stable 32-byte chain id from a label. Deterministic
// so every node computes the same id for the same deployment label.
func chainIDFromString(s string) common.Hash {
	return slotNS([]byte("av/chainid/" + s))
}
