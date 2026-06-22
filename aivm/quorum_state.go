// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// quorum_state.go is the storage + custody SUBSTRATE the A-Chain quorum
// settlement engine runs on. It is the one place that knows how engine state is
// keyed and where native value lives. Everything above it (provider, task,
// selection, commit-reveal, settlement, receipts, import/export) is pure logic
// over these two interfaces — exactly the StateDB/Ledger split the proven
// hanzo-evm aiquorum precompile used, ported here to A-Chain-native types.
//
// Why a split:
//   - QuorumState  is opaque 32-byte slot storage. On a live A-Chain it is
//     backed by the VM's keyed DB (state committed under consensus in
//     Accept); in tests it is an in-memory map. The engine never cares which.
//   - QuorumLedger is native-token custody around a SINGLE escrow account
//     (EscrowAccount). Pull moves funds in, Pay moves funds out. Both are
//     atomic and fail-closed. No value-bearing call is ever made (every money
//     move is a balance mutation), so there is no reentrancy surface through
//     stake, escrow, pay, or slash.
//
// Slot derivation is keccak over a namespace tuple, so distinct record kinds
// can never alias keyspaces. Identical scheme to the proven precompile.

import (
	"github.com/holiman/uint256"
	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/common"
)

// EscrowAccount is the single account that holds all engine-custodied native
// value: bonded provider stake, open job reward escrow, and unwithdrawn credit.
// It holds no code; all movement is balance mutation. The conservation
// invariant the engine maintains and the tests assert:
//
//	balance(EscrowAccount) == sum(bonded stake)
//	                        + sum(open job escrow)
//	                        + sum(unwithdrawn credit)
//
// at every step, and the grand total over all accounts is constant.
var EscrowAccount = common.HexToAddress("0xA1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1A1")

// QuorumState is the minimal slot-level storage the engine needs. On A-Chain
// the VM adapts its DB to this (writes land in a block and commit under
// consensus at Accept); the in-memory MemState satisfies it for tests.
type QuorumState interface {
	GetState(slot common.Hash) common.Hash
	SetState(slot, value common.Hash)
}

// QuorumLedger is the native-value custody interface bound to EscrowAccount.
// Pull(from, amt) debits `from` and credits the escrow; Pay(to, amt) debits the
// escrow and credits `to`. Both are atomic and fail-closed (no partial state on
// error). GetBalance reads any account.
type QuorumLedger interface {
	GetBalance(a common.Address) *uint256.Int
	Pull(from common.Address, amount *uint256.Int) error
	Pay(to common.Address, amount *uint256.Int) error
}

// ---------------------------------------------------------------------------
// In-memory substrate (tests + single-process engine; the live VM swaps in a
// DB-backed QuorumState committed under consensus).
// ---------------------------------------------------------------------------

// MemState is an in-memory QuorumState: a flat slot map. Zero value is NOT
// usable; use NewMemState.
type MemState struct {
	m map[common.Hash]common.Hash
}

// NewMemState returns an empty in-memory state.
func NewMemState() *MemState { return &MemState{m: make(map[common.Hash]common.Hash)} }

// GetState returns the value at slot (zero hash if unset).
func (s *MemState) GetState(slot common.Hash) common.Hash { return s.m[slot] }

// SetState writes value at slot.
func (s *MemState) SetState(slot, value common.Hash) { s.m[slot] = value }

// MemLedger is an in-memory QuorumLedger over a balance map, custodying funds at
// EscrowAccount. Use NewMemLedger.
type MemLedger struct {
	bal map[common.Address]*uint256.Int
}

// NewMemLedger returns a ledger with the given opening balances (copied).
func NewMemLedger(opening map[common.Address]*uint256.Int) *MemLedger {
	bal := make(map[common.Address]*uint256.Int, len(opening)+1)
	for a, v := range opening {
		bal[a] = new(uint256.Int).Set(v)
	}
	if _, ok := bal[EscrowAccount]; !ok {
		bal[EscrowAccount] = uint256.NewInt(0)
	}
	return &MemLedger{bal: bal}
}

// GetBalance returns a copy of the account's balance (zero if unknown).
func (l *MemLedger) GetBalance(a common.Address) *uint256.Int {
	if v, ok := l.bal[a]; ok {
		return new(uint256.Int).Set(v)
	}
	return uint256.NewInt(0)
}

// Credit mints `amount` into `a`'s balance. This is the genesis/bootstrap seam
// for native value (the L1's own state credits an A-Chain account at chain birth
// or via a cross-chain deposit before any task/registration can pull from it).
// It is the symmetric counterpart of GetBalance/Pull/Pay and the only way the VM
// seeds opening balances onto a ledger that was constructed empty. Fail-closed on
// overflow; no state change on error.
func (l *MemLedger) Credit(a common.Address, amount *uint256.Int) error {
	cur := l.GetBalance(a)
	nv := new(uint256.Int)
	if _, overflow := nv.AddOverflow(cur, amount); overflow {
		return ErrCreditOverflow
	}
	l.bal[a] = nv
	return nil
}

// Pull debits `from` by amount and credits EscrowAccount. Fail-closed on
// insufficient balance or overflow; no state change on error.
func (l *MemLedger) Pull(from common.Address, amount *uint256.Int) error {
	src := l.GetBalance(from)
	if src.Lt(amount) {
		return ErrInsufficientFunds
	}
	esc := l.GetBalance(EscrowAccount)
	ne := new(uint256.Int)
	if _, overflow := ne.AddOverflow(esc, amount); overflow {
		return ErrStakeOverflow
	}
	l.bal[from] = new(uint256.Int).Sub(src, amount)
	l.bal[EscrowAccount] = ne
	return nil
}

// Pay debits EscrowAccount by amount and credits `to`. Fail-closed on escrow
// underflow (a hard invariant breach) or recipient overflow.
func (l *MemLedger) Pay(to common.Address, amount *uint256.Int) error {
	esc := l.GetBalance(EscrowAccount)
	if esc.Lt(amount) {
		return ErrEscrowUnderflow
	}
	dst := l.GetBalance(to)
	nd := new(uint256.Int)
	if _, overflow := nd.AddOverflow(dst, amount); overflow {
		return ErrCreditOverflow
	}
	l.bal[EscrowAccount] = new(uint256.Int).Sub(esc, amount)
	l.bal[to] = nd
	return nil
}

// Total returns the grand-total balance over every account (for the
// conservation invariant test). Pure read.
func (l *MemLedger) Total() *uint256.Int {
	sum := uint256.NewInt(0)
	for _, v := range l.bal {
		sum.Add(sum, v)
	}
	return sum
}

// Snapshot returns a deep copy of the balance map. Paired with Restore, it lets
// the VM gate ledger mutations on block Accept: BuildBlock/Verify may move funds
// while planning a block, and a rejected/discarded block restores the snapshot so
// no value moves outside consensus. (The engine's QuorumState is staged
// separately via versiondb; the two are committed/aborted together.)
func (l *MemLedger) Snapshot() map[common.Address]*uint256.Int {
	cp := make(map[common.Address]*uint256.Int, len(l.bal))
	for a, v := range l.bal {
		cp[a] = new(uint256.Int).Set(v)
	}
	return cp
}

// Restore replaces the balance map with a previously taken Snapshot (deep-copied
// again so the snapshot stays reusable).
func (l *MemLedger) Restore(snap map[common.Address]*uint256.Int) {
	nb := make(map[common.Address]*uint256.Int, len(snap))
	for a, v := range snap {
		nb[a] = new(uint256.Int).Set(v)
	}
	l.bal = nb
}

// ---------------------------------------------------------------------------
// State-slot namespaces. Distinct prefixes guarantee the keccak keyspaces of
// different record kinds never collide. Mirrors the proven precompile's layout,
// renamed to the A-Chain (av/) namespace so it never aliases a C-Chain
// precompile's slots even if they ever shared a store.
// ---------------------------------------------------------------------------

var (
	nsOperator    = []byte("av/op")          // operator registry meta
	nsModelIndex  = []byte("av/mspec.idx")   // per-ModelSpec operator-array length
	nsModelMember = []byte("av/mspec.mem")   // per-ModelSpec operator-array element
	nsModelSeen   = []byte("av/mspec.seen")  // per-(ModelSpec,operator) membership flag
	nsCredit      = []byte("av/cred")        // operator withdrawable credit ledger
	nsReqNonce    = []byte("av/req.nonce")   // requester monotonic nonce
	nsTask        = []byte("av/task")        // task record (status + params) *** also job_id domain
	nsTaskReward  = []byte("av/task.reward") // task rewardPerOperator (uint256)
	nsTaskEscrow  = []byte("av/task.escrow") // task remaining escrow (uint256)
	nsTaskIntent  = []byte("av/task.intent") // task -> source C intent id
	nsTaskFee     = []byte("av/task.fee")    // task fee paid (uint256, for the receipt)
	nsSelected    = []byte("av/sel")         // per-(task,operator) selection flag
	nsSelList     = []byte("av/sel.list")    // per-task selected-operator-array element
	nsCommit      = []byte("av/commit")      // per-(task,operator) commit hash
	nsReveal      = []byte("av/reveal")      // per-(task,operator) revealed output_hash
	nsRevealFlag  = []byte("av/reveal.f")    // per-(task,operator) revealed flag
	nsRevealList  = []byte("av/reveal.list") // per-task revealer-array element
	nsRevealCount = []byte("av/reveal.cnt")  // per-task revealer count
	nsSettled     = []byte("av/settled")     // per-task settled marker (replay guard)
	nsCanonical   = []byte("av/canon")       // per-task canonical output_hash
	nsReceiptRoot = []byte("av/receipt.root")// running receipt_root accumulator
	nsReceiptIdx  = []byte("av/receipt.idx") // count of settled receipts in the root
	nsReceiptLeaf = []byte("av/receipt.leaf")// settled receipt_hash by index (for proofs)
	nsIntentSeen  = []byte("av/intent.seen") // per-C-intent consumed marker (anti-replay)
	nsIntentTask  = []byte("av/intent.task") // per-C-intent -> A-chain task id
	nsIntentRcpt  = []byte("av/intent.rcpt") // per-C-intent settled-receipt leaf index+1 (0 = unsettled)
	nsTaskHeight  = []byte("av/task.height") // per-task settled height (so receipt is reproducible)
)

// ---------------------------------------------------------------------------
// Slot derivation (keccak of a namespace tuple).
// ---------------------------------------------------------------------------

func slotAddr(ns []byte, a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, a.Bytes()))
}

func slotHash(ns []byte, h common.Hash) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes()))
}

func slotHashAddr(ns []byte, h common.Hash, a common.Address) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes(), a.Bytes()))
}

func slotHashIdx(ns []byte, h common.Hash, idx uint32) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, h.Bytes(), u32be(idx)))
}

func slotNS(ns []byte) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns))
}

func slotNSIdx(ns []byte, idx uint32) common.Hash {
	return common.BytesToHash(crypto.Keccak256(ns, u32be(idx)))
}
