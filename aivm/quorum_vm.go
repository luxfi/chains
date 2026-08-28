// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// quorum_vm.go is the VM-side glue that mounts the A-Chain quorum settlement
// engine onto the ChainVM: engine state, native-token custody, and the
// CONSENSUS-GATED inbound path for C-Chain intents. It keeps all engine wiring
// in one orthogonal place so vm.go stays a thin ChainVM shell.
//
// The load-bearing safety invariant lives here: committed C intents are buffered
// (EnqueueCommittedIntent) but only TURN INTO TASKS inside a block. There is no
// code path from a live/RPC request to createTask — the only caller of
// ImportCommittedIntent is pick/replay, and the only callers of those are the
// block build, verify and accept paths.
//
// TWO WRITE PLANES, never braided:
//
//   - COMMITTED state (vm.db, read/written through vm.qstate) is what the chain
//     has agreed. Every read outside a block sees exactly this.
//
//   - The VIEW (vm.view, a versiondb over vm.db) is what an ACCEPTING block
//     writes through. It is empty except between the first write of Block.Accept
//     and that block's single Commit, so a block's writes can never ride out on
//     another block's commit — the fault that let Accept(A) publish B's staged
//     intent and Reject(B) discard A's.
//
// Building and verifying write to NEITHER. They run the same transition against
// an overlay that buffers writes in memory and is then thrown away, so a block
// that is proposed, or checked and lost, moves no state and no value at all.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/geth/common"
)

// dbState adapts a luxfi/database.Database (or any KeyValueReaderWriter) to the
// engine's QuorumState. Engine slots are 32-byte keccak keys; values are 32-byte
// words. A read miss returns the zero hash, which the engine treats as "unset" —
// identical semantics to the in-memory MemState.
type dbState struct {
	db database.KeyValueReaderWriter
}

// NewDBState wraps a database for engine use.
func NewDBState(db database.KeyValueReaderWriter) QuorumState { return &dbState{db: db} }

func (s *dbState) stateKey(slot common.Hash) []byte {
	// Prefix engine slots so they never collide with block/height/tip keys in
	// the shared DB.
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

// overlay is a QuorumState that buffers writes over another one. It is how a
// transition can be RUN without being APPLIED: the proposer needs the state a
// block would reach in order to stamp its receipt root, and a validator needs it
// in order to check that stamp, and neither of them is allowed to change
// anything. Both use one of these and drop it.
//
// It is deliberately at the QuorumState layer rather than the database layer.
// The engine's whole storage contract is "32-byte slot in, 32-byte word out", so
// buffering it takes a map and two methods, with no commit path to get wrong and
// no second versiondb whose Abort someone could forget to call.
type overlay struct {
	base  QuorumState
	dirty map[common.Hash]common.Hash
}

func newOverlay(base QuorumState) *overlay {
	return &overlay{base: base, dirty: make(map[common.Hash]common.Hash)}
}

func (o *overlay) GetState(slot common.Hash) common.Hash {
	if v, ok := o.dirty[slot]; ok {
		return v
	}
	return o.base.GetState(slot)
}

func (o *overlay) SetState(slot, value common.Hash) { o.dirty[slot] = value }

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
// service and tests. The QuorumState returned is COMMITTED state: it shows what
// the chain has accepted and nothing a block in flight has proposed.
func (vm *VM) QuorumEngine() (*Engine, QuorumState, QuorumLedger) {
	return vm.quorum, vm.qstate, vm.qledger
}

// FundLedger seeds opening native balances. This is the genesis/deposit seam:
// the host L1 credits A-Chain accounts (a requester that will fund an inference
// escrow, an operator that will bond) at chain birth or via a verified
// cross-chain deposit, BEFORE any task or registration can pull from them.
//
// It goes through Seed, so the credits are durable at once rather than riding
// out on whichever block commits first. Fail-closed: a credit overflow aborts
// with no partial seeding.
func (vm *VM) FundLedger(opening map[common.Address]*uint256.Int) error {
	return vm.Seed(func(_ QuorumState, lg QuorumLedger) error {
		for a, v := range opening {
			if err := lg.Credit(a, v); err != nil {
				return err
			}
		}
		return nil
	})
}

// EnqueueCommittedIntent buffers a C-Chain intent that the boundary transport
// has delivered with a committedness proof. It does NOT create a task — that
// happens only under consensus, inside a block. Safe to call from the transport
// goroutine; guarded by the VM lock.
func (vm *VM) EnqueueCommittedIntent(intent CIntent) {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	vm.pendingIntents = append(vm.pendingIntents, intent)
}

// drop forgets the intents a block carried, once that block is durable. Until
// then they stay buffered: a proposal that loses the round has consumed nothing,
// and the next proposer must still be able to carry the same work.
//
// Caller holds vm.mu.
func (vm *VM) drop(carried []CIntent) {
	if len(carried) == 0 {
		return
	}
	gone := make(map[common.Hash]struct{}, len(carried))
	for _, in := range carried {
		gone[in.IntentID] = struct{}{}
	}
	kept := vm.pendingIntents[:0]
	for _, in := range vm.pendingIntents {
		if _, ok := gone[in.IntentID]; !ok {
			kept = append(kept, in)
		}
	}
	vm.pendingIntents = kept
}

// replay applies the intents a block RECORDED, at that block's height, and
// returns the receipt root they reach. It is what a validator runs to check a
// proposer's arithmetic and what Accept runs to make it durable — the same code
// over different storage, so the two can never disagree about what a block does.
//
// Every recorded intent must still import. An intent this node has already
// consumed reports ErrIntentAlreadyUsed and is benign — the anti-replay marker
// is exactly the right verdict, and the receipt-root comparison below is what
// decides whether the resulting state agrees.
//
// Caller holds vm.mu.
func (vm *VM) replay(st QuorumState, lg QuorumLedger, recorded []CIntent, height uint64) (common.Hash, error) {
	for _, intent := range recorded {
		_, err := vm.quorum.ImportCommittedIntent(st, lg, vm.ccv, intent, height)
		if err != nil && err != ErrIntentAlreadyUsed {
			return common.Hash{}, err
		}
	}
	return vm.settle(st, lg, height), nil
}

// pick chooses, from the buffered committed intents, the ones that import
// cleanly at this height, applying each as it goes so the next one sees the
// state the previous left. This is the PROPOSER's decision about what a block
// carries; a rejected intent (forged id, failed proof, replay, ineligible pool)
// is simply left out and no state changed for it.
//
// Caller holds vm.mu.
func (vm *VM) pick(st QuorumState, lg QuorumLedger, height uint64) ([]CIntent, common.Hash) {
	carried := make([]CIntent, 0, len(vm.pendingIntents))
	for _, intent := range vm.pendingIntents {
		if _, err := vm.quorum.ImportCommittedIntent(st, lg, vm.ccv, intent, height); err == nil {
			carried = append(carried, intent)
		}
	}
	return carried, vm.settle(st, lg, height)
}

// settle gives a verdict to every task whose reveal window has closed and
// returns the receipt root that leaves. This is what pays operators: without it
// a task sits revealed and unsettled forever, and the work the network did for
// it is never credited to anyone.
//
// It is a function of the state and the height alone, so it needs nothing
// recorded in the block — the receipt root is what checks it.
func (vm *VM) settle(st QuorumState, lg QuorumLedger, height uint64) common.Hash {
	vm.quorum.SettleDue(st, lg, height)
	return vm.quorum.ReceiptRoot(st)
}

// Seed applies the one engine mutation a chain makes outside consensus: what
// its genesis allocates. It writes through the view and commits at once, before
// any block exists, for the same reason Accept commits — left staged, a genesis
// allocation would ride out on whichever block committed first and vanish with a
// chain that never accepted one.
func (vm *VM) Seed(write func(QuorumState, QuorumLedger) error) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	staged := NewDBState(vm.view)
	if err := write(staged, newStateLedger(staged)); err != nil {
		vm.view.Abort()
		return err
	}
	if err := vm.view.Commit(); err != nil {
		vm.view.Abort()
		return err
	}
	return nil
}

// initQuorum sets up the engine, its state and its ledger. Called from
// Initialize. cChainID/aChainID are derived from the deployment (the host
// chain's id and the configured C-chain id); here we derive stable 32-byte ids
// from the VM's network id and host chain id so a single-node test/dev instance
// is self-consistent.
//
// Custody is engine state, so the ledger is a view over it rather than a second
// store: value moves through the one staging layer, commits in the one write,
// and survives a restart with the stake records it belongs to.
func (vm *VM) initQuorum() {
	c := chainIDFromString("c-chain")
	a := chainIDFromString(vm.config.HostChainID)
	vm.quorum = NewEngine(c, a)
	vm.view = versiondb.New(vm.db)
	vm.qstate = NewDBState(vm.db)
	vm.qledger = newStateLedger(vm.qstate)
}

// chainIDFromString derives a stable 32-byte chain id from a label. Deterministic
// so every node computes the same id for the same deployment label.
func chainIDFromString(s string) common.Hash {
	return slotNS([]byte("av/chainid/" + s))
}
