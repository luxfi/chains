// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package keyvm implements the K-Chain: an AUTH-ONLY service VM for distributed
// key management. K authorizes and coordinates key ceremonies; it never holds,
// stores, reconstructs, or transmits secret key material or threshold shares.
// See state.go for the structurally-enforced zero-secret invariant. Mutating
// operations take effect only through fee-settled consensus blocks (block.go),
// priced by a per-algorithm gas schedule (gas.go) and burned from the payer's
// on-chain balance via the native fee settlement primitive (github.com/luxfi/
// chains/fee).
package keyvm

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/rpc/v2"
	grjson "github.com/gorilla/rpc/v2/json"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/timer/mockable"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
)

const (
	// Version of the K-Chain VM.
	Version = "2.0.0"
	// VMName is the human-readable name of the K-Chain VM.
	VMName = "keyvm"

	// Database namespaces. Key/ceremony records are JSON; balances live under
	// the fee ledger's own namespace (github.com/luxfi/chains/fee).
	KeyPrefix      = "key:"
	CeremonyPrefix = "ceremony:"
	BlockPrefix    = "block:"
	// HeightPrefix indexes accepted blocks by height: HeightPrefix||u64 -> blockID.
	// Written in the same commit as the block it names, so the index can never
	// point at a block the chain did not accept.
	HeightPrefix = "height:"
)

// maxFutureSkew bounds how far ahead of the verifying node's clock a proposer may
// stamp a block. Block time is not decoration here: it is the `now` every
// authorization decision is made against (AuthPolicy.ExpiresAt), so an unbounded
// timestamp lets a proposer expire a policy early. Ten seconds is the node's
// existing clock-sync tolerance.
const maxFutureSkew = 10 * time.Second

var (
	lastAcceptedKey = []byte("keyvm/last-accepted")
	genesisMarker   = []byte("keyvm/genesis-applied")
)

// Verify VM implements the consensus ChainVM interface.
var _ chain.ChainVM = (*VM)(nil)

// Sentinel errors. Every one denies an operation — the package fails secure.
var (
	errVMShutdown    = errors.New("keyvm: shutting down")
	errNoPendingTxs  = errors.New("keyvm: no pending transactions")
	errNoParentBlock = errors.New("keyvm: no parent block")

	ErrInvalidTxType    = errors.New("keyvm: invalid transaction type")
	ErrInvalidPayload   = errors.New("keyvm: invalid transaction payload")
	ErrUnknownAlgorithm = errors.New("keyvm: unsupported algorithm")
	ErrInvalidThreshold = errors.New("keyvm: invalid threshold (need 0 < t <= n)")
	ErrInvalidCeremony  = errors.New("keyvm: invalid ceremony type")

	ErrUnsignedTx    = errors.New("keyvm: transaction missing payer auth/signature")
	ErrPayerMismatch = errors.New("keyvm: payer does not match auth public key")
	ErrBadSignature  = errors.New("keyvm: invalid payer signature")

	ErrKeyNotFound  = errors.New("keyvm: key not found")
	ErrKeyExists    = errors.New("keyvm: key already exists")
	ErrKeyRevoked   = errors.New("keyvm: key is revoked")
	ErrUnauthorized = errors.New("keyvm: payer not authorized for operation")

	// ErrBadNonce rejects a replayed or out-of-order transaction. A payer's
	// transactions MUST carry strictly increasing nonces starting at 1; this is
	// what stops a captured signed transaction from being resubmitted to drain
	// the payer's balance through repeated fee burns.
	ErrBadNonce = errors.New("keyvm: bad or replayed nonce")

	// ErrBadHeight rejects a block that does not sit exactly one above its parent.
	ErrBadHeight = errors.New("keyvm: block height is not parent height + 1")

	// ErrTimeRewound rejects a block stamped before its parent. Block time is the
	// clock every authorization decision is made against, so a proposer that could
	// rewind it could revive an expired policy.
	ErrTimeRewound = errors.New("keyvm: block timestamp is before its parent's")

	// ErrTimeAhead rejects a block stamped more than maxFutureSkew ahead of the
	// verifying node — the other half of the same guard, which stops a proposer
	// expiring a policy early.
	ErrTimeAhead = errors.New("keyvm: block timestamp is too far in the future")
)

var noncePrefix = []byte("nonce:")

// VM implements the K-Chain auth-only Virtual Machine.
//
// STRUCTURAL ZERO-SECRET NOTE: every field below is either runtime plumbing or
// a cache of PUBLIC records (KeyRecord / CeremonyRecord). There is deliberately
// no key cache of private keys, no share store, and no GPU crypto session — the
// previous design's *mlkem.PrivateKey cache, KeyShare store, and accel session
// are gone. authonly_test.go proves no reachable field can hold a secret.
type VM struct {
	cancel context.CancelFunc
	log    log.Logger
	// versdb buffers every write of a block; Commit is the chain's one durability
	// point. It is the only handle to state — there is deliberately no second
	// name for it, so no write can miss the block's commit by going elsewhere.
	versdb   *versiondb.Database
	toEngine chan<- vmcore.Message
	work     vmcore.Latch

	// networkID is the network this chain belongs to. It is ONE field, not a
	// factory copy shadowed by a config copy: the factory's value is the
	// fallback, the consensus runtime overrides it, and the node's chain config
	// blob overrides that. Most specific wins, resolved once in Initialize.
	networkID uint32
	clock     mockable.Clock

	// stateLock guards ALL chain state: the PUBLIC record caches below, the block
	// index, and the last-accepted pointer. One mutex over one body of state — the
	// pending-block map used to be guarded by shutdownLock in some paths and by
	// stateLock in others, which is a Go fatal throw waiting for a concurrent
	// build-and-abort.
	stateLock  sync.RWMutex
	keys       map[ids.ID]*KeyRecord
	keysByName map[string]ids.ID
	ceremonies map[ids.ID]*CeremonyRecord

	// Native fee balance ledger (debit + burn), backed by the VM's versiondb so
	// settlement commits atomically with the operations it pays for.
	ledger *fee.Ledger

	// Admission policy (node/vms/types/fee). Orthogonal to settlement: this is
	// the boot-time floor declaration Manager validates; the per-op burn is done
	// through `ledger`. Kept so the chain still satisfies the zero-fee refusal.
	feePolicy fee.Policy

	// Block bookkeeping, under stateLock.
	pendingBlocks map[ids.ID]*Block
	lastAccepted  ids.ID
	lastBlock     *Block
	height        uint64

	// The mempool, under its own lock. Lock order is always stateLock then
	// mempoolLock; nothing takes them the other way round.
	mempoolLock sync.Mutex
	mempool     []*Transaction

	rpcServer *rpc.Server

	// shutdownLock guards the shutdown flag and nothing else.
	shutdownLock sync.RWMutex
	shuttingDown bool
}

// Genesis is the K-Chain genesis: a funding allocation (address hex -> nLUX) and
// metadata. Initial keys are registered via consensus transactions, not genesis,
// so genesis carries no key material.
type Genesis struct {
	Version   int               `json:"version"`
	Message   string            `json:"message"`
	Timestamp int64             `json:"timestamp"`
	Alloc     map[string]uint64 `json:"alloc"`
}

// Initialize wires the VM: database, ledger, fee policy, caches, genesis seeding,
// and the JSON-RPC service.
func (vm *VM) Initialize(ctx context.Context, init vmcore.Init) error {
	_, vm.cancel = context.WithCancel(ctx)
	vm.versdb = versiondb.New(init.DB)
	vm.toEngine = init.ToEngine

	if init.Runtime != nil {
		if logger, ok := init.Runtime.Log.(log.Logger); ok {
			vm.log = logger
		}
	}
	if vm.log == nil {
		if init.Log != nil {
			vm.log = init.Log
		} else {
			vm.log = log.NewNoOpLogger()
		}
	}

	cfg, err := ParseConfig(init.Config)
	if err != nil {
		return fmt.Errorf("keyvm: parse config: %w", err)
	}

	vm.stateLock.Lock()
	vm.keys = make(map[ids.ID]*KeyRecord)
	vm.keysByName = make(map[string]ids.ID)
	vm.ceremonies = make(map[ids.ID]*CeremonyRecord)
	vm.stateLock.Unlock()
	vm.pendingBlocks = make(map[ids.ID]*Block)

	if init.Runtime != nil && init.Runtime.NetworkID != 0 {
		vm.networkID = init.Runtime.NetworkID
	}
	if cfg.NetworkID != 0 {
		vm.networkID = cfg.NetworkID
	}

	vm.ledger = fee.NewLedger(vm.versdb)
	vm.feePolicy = newFeePolicy(vm.networkID)
	if err := fee.Validate(vm.feePolicy); err != nil {
		return fmt.Errorf("keyvm: fee policy: %w", err)
	}

	genesis := &Genesis{}
	if len(init.Genesis) > 0 {
		if err := json.Unmarshal(init.Genesis, genesis); err != nil {
			return fmt.Errorf("keyvm: parse genesis: %w", err)
		}
	}

	// Genesis block at height 0.
	genesisBlock := &Block{
		id:        ids.Empty,
		parentID:  ids.Empty,
		height:    0,
		timestamp: time.Unix(genesis.Timestamp, 0),
		vm:        vm,
	}
	genesisBlock.id = genesisBlock.computeID()
	vm.lastAccepted = genesisBlock.id
	vm.lastBlock = genesisBlock

	if err := vm.seedGenesis(genesis, genesisBlock); err != nil {
		return fmt.Errorf("keyvm: seed genesis: %w", err)
	}
	if err := vm.loadState(); err != nil {
		return fmt.Errorf("keyvm: load state: %w", err)
	}
	if err := vm.initHTTP(); err != nil {
		return fmt.Errorf("keyvm: init http: %w", err)
	}

	vm.log.Info("K-Chain (auth-only) initialized",
		log.String("version", Version),
		log.Uint32("networkID", vm.networkID),
		log.Uint64("height", vm.height),
	)
	return nil
}

// seedGenesis credits the funding allocation and persists the genesis block once
// (idempotent via a marker key). It is the only trusted state mutation; all later
// mutations go through blocks. Persisting genesis is what lets the block at
// height 1 find a parent to verify against — every accepted block, genesis
// included, is retrievable by id and by height.
func (vm *VM) seedGenesis(g *Genesis, genesisBlock *Block) error {
	applied, err := vm.versdb.Has(genesisMarker)
	if err != nil {
		return err
	}
	if applied {
		return nil
	}
	for addrHex, amount := range g.Alloc {
		acct, err := accountFromHex(addrHex)
		if err != nil {
			return fmt.Errorf("alloc %q: %w", addrHex, err)
		}
		if err := vm.ledger.Credit(acct, amount); err != nil {
			return fmt.Errorf("alloc %q: %w", addrHex, err)
		}
	}
	if err := vm.recordAccepted(genesisBlock); err != nil {
		return err
	}
	if err := vm.versdb.Put(genesisMarker, []byte{1}); err != nil {
		return err
	}
	return vm.versdb.Commit()
}

// recordAccepted writes a block, its height index entry, and the last-accepted
// pointer into the versiondb. It does not commit — the caller's commit is what
// makes all three durable together, so the index can never name a block the
// chain did not accept.
func (vm *VM) recordAccepted(b *Block) error {
	if err := vm.versdb.Put(append([]byte(BlockPrefix), b.id[:]...), b.Bytes()); err != nil {
		return err
	}
	if err := vm.versdb.Put(heightKey(b.height), b.id[:]); err != nil {
		return err
	}
	return vm.versdb.Put(lastAcceptedKey, b.id[:])
}

func heightKey(h uint64) []byte {
	k := make([]byte, 0, len(HeightPrefix)+8)
	k = append(k, HeightPrefix...)
	var u8 [8]byte
	binary.BigEndian.PutUint64(u8[:], h)
	return append(k, u8[:]...)
}

// loadState rebuilds the PUBLIC caches and lastAccepted pointer from the DB.
func (vm *VM) loadState() error {
	vm.stateLock.Lock()
	defer vm.stateLock.Unlock()
	return vm.loadStateLocked()
}

// loadStateLocked is loadState's body; callers must hold stateLock. The block
// Accept error path uses it to reload caches after a versiondb Abort while it
// still holds the lock.
func (vm *VM) loadStateLocked() error {
	vm.keys = make(map[ids.ID]*KeyRecord)
	vm.keysByName = make(map[string]ids.ID)
	vm.ceremonies = make(map[ids.ID]*CeremonyRecord)

	kit := vm.versdb.NewIteratorWithPrefix([]byte(KeyPrefix))
	defer kit.Release()
	for kit.Next() {
		var rec KeyRecord
		if err := json.Unmarshal(kit.Value(), &rec); err != nil {
			vm.log.Warn("keyvm: skip corrupt key record", log.String("error", err.Error()))
			continue
		}
		r := rec
		vm.keys[r.ID] = &r
		vm.keysByName[r.Name] = r.ID
	}
	if err := kit.Error(); err != nil {
		return err
	}

	cit := vm.versdb.NewIteratorWithPrefix([]byte(CeremonyPrefix))
	defer cit.Release()
	for cit.Next() {
		var c CeremonyRecord
		if err := json.Unmarshal(cit.Value(), &c); err != nil {
			vm.log.Warn("keyvm: skip corrupt ceremony record", log.String("error", err.Error()))
			continue
		}
		cc := c
		vm.ceremonies[cc.ID] = &cc
	}
	if err := cit.Error(); err != nil {
		return err
	}

	if b, err := vm.versdb.Get(lastAcceptedKey); err == nil && len(b) == 32 {
		copy(vm.lastAccepted[:], b)
		if blk, err := vm.getBlockLocked(vm.lastAccepted); err == nil {
			vm.lastBlock = blk
			vm.height = blk.height
		}
	}
	return nil
}

// ---- PUBLIC state accessors (used by tx Apply, under stateLock held by Accept) ----

func (vm *VM) getKey(id ids.ID) (*KeyRecord, bool) {
	r, ok := vm.keys[id]
	return r, ok
}

// putRecord writes a PUBLIC record as JSON under prefix||id, then the caller
// indexes it in the matching cache. Encoding cannot fail — every field of both
// record types is a string, a byte slice, a fixed-width id or an integer — so
// the only error a caller sees is the store's.
func (vm *VM) putRecord(prefix string, id ids.ID, rec any) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return vm.versdb.Put([]byte(prefix+id.String()), data)
}

func (vm *VM) putKey(rec *KeyRecord) error {
	if err := vm.putRecord(KeyPrefix, rec.ID, rec); err != nil {
		return err
	}
	vm.keys[rec.ID] = rec
	vm.keysByName[rec.Name] = rec.ID
	return nil
}

func (vm *VM) putCeremony(c *CeremonyRecord) error {
	if err := vm.putRecord(CeremonyPrefix, c.ID, c); err != nil {
		return err
	}
	vm.ceremonies[c.ID] = c
	return nil
}

// nonceOf returns the payer's last-used nonce (0 if the account has never
// transacted). The next valid nonce is nonceOf(payer)+1. Caller holds a lock.
func (vm *VM) nonceOf(payer fee.Account) uint64 {
	key := append(append([]byte{}, noncePrefix...), payer[:]...)
	b, err := vm.versdb.Get(key)
	if err != nil || len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// setNonce records the payer's last-used nonce (writes to the versiondb, so it
// commits atomically with the block). Caller holds stateLock.
func (vm *VM) setNonce(payer fee.Account, n uint64) error {
	key := append(append([]byte{}, noncePrefix...), payer[:]...)
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], n)
	return vm.versdb.Put(key, u[:])
}

// ---- Read-only public queries (RPC) ----

// KeyByID returns a copy of a key record.
func (vm *VM) KeyByID(id ids.ID) (*KeyRecord, bool) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	r, ok := vm.keys[id]
	if !ok {
		return nil, false
	}
	c := *r
	return &c, true
}

// KeyByName returns a copy of a key record by name.
func (vm *VM) KeyByName(name string) (*KeyRecord, bool) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	id, ok := vm.keysByName[name]
	if !ok {
		return nil, false
	}
	r := *vm.keys[id]
	return &r, true
}

// Keys returns copies of all key records.
func (vm *VM) Keys() []*KeyRecord {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	out := make([]*KeyRecord, 0, len(vm.keys))
	for _, r := range vm.keys {
		c := *r
		out = append(out, &c)
	}
	return out
}

// Ceremony returns a copy of a ceremony record.
func (vm *VM) Ceremony(id ids.ID) (*CeremonyRecord, bool) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	c, ok := vm.ceremonies[id]
	if !ok {
		return nil, false
	}
	cc := *c
	return &cc, true
}

// Balance returns an account's spendable nLUX.
func (vm *VM) Balance(acct fee.Account) (uint64, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	return vm.ledger.Balance(acct)
}

// Burned returns cumulative burned supply in nLUX.
func (vm *VM) Burned() (uint64, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	return vm.ledger.Burned()
}

// ---- Mempool / consensus driver ----

// running is the per-payer effect of the transactions already accepted into a
// view: how much each payer has committed to spend, and which nonce each must
// use next. Admission carries it over the mempool, block assembly and Verify
// carry it over a block, so a payer's second transaction is always judged
// against its first.
type running struct {
	spent     map[fee.Account]uint64
	nextNonce map[fee.Account]uint64
}

func newRunning() *running {
	return &running{
		spent:     make(map[fee.Account]uint64),
		nextNonce: make(map[fee.Account]uint64),
	}
}

// checkTx is the ONE admissibility predicate for a transaction. Admission
// (SubmitTx), block assembly (BuildBlock) and consensus (Block.Verify) all
// decide through it, so a transaction one of them accepts is never one another
// refuses. That split was not cosmetic: admission used to accept ANY nonce above
// the committed one while Verify demanded exactly committed+1, so one gapped
// transaction from any funded account entered the mempool, was drained into
// every subsequent block, failed Verify, was requeued by Reject, and wedged
// block production for free and forever.
//
// On success it advances r, so the caller can walk a sequence. now is the time
// authorization is judged at — the block's timestamp inside consensus, the
// node's clock at admission. The caller holds stateLock.
func (vm *VM) checkTx(tx *Transaction, now int64, r *running) error {
	if err := tx.SyntacticVerify(); err != nil {
		return err
	}
	if err := tx.authenticate(); err != nil {
		return err
	}
	return vm.admit(tx, now, r)
}

// admit is checkTx's stateful half: nonce order, authorization, price and
// affordability against the view r has advanced to. It is split out because a
// transaction's signature is worth verifying exactly once — admission does it,
// and folding the mempool's already-authenticated backlog into a running view
// must not re-verify ML-DSA on every submission.
func (vm *VM) admit(tx *Transaction, now int64, r *running) error {
	// Replay/order guard runs BEFORE authorization so a replayed transaction is
	// rejected as such regardless of the operation's other preconditions.
	want, seen := r.nextNonce[tx.Payer]
	if !seen {
		want = vm.nonceOf(tx.Payer) + 1
	}
	if tx.Nonce != want {
		return ErrBadNonce
	}
	if _, err := tx.checkAuth(vm, now); err != nil {
		return err
	}
	feeAmt, err := meter(tx)
	if err != nil {
		return err
	}
	bal, err := vm.ledger.Balance(tx.Payer)
	if err != nil {
		return err
	}
	// Each fee is at least MinScheduledFee and a payer's cumulative spend is
	// checked against a real uint64 balance, so this sum cannot wrap: reaching
	// 2^64 nLUX would take ~6e12 transactions in one block. Even if it did, the
	// per-transaction fee.Charge in Accept is the authoritative debit and fails
	// closed against the real balance.
	next := r.spent[tx.Payer] + feeAmt
	if bal < next {
		return fee.ErrInsufficientFunds
	}
	r.spent[tx.Payer] = next
	r.nextNonce[tx.Payer] = want + 1
	return nil
}

// SubmitTx admits a transaction to the mempool and signals the engine to build a
// block. It judges the transaction against committed state PLUS everything
// already queued from the same payer, which is exactly what BuildBlock and
// Verify will judge it against. The fee is SETTLED later, in block Accept —
// never here. Returns the transaction ID.
func (vm *VM) SubmitTx(tx *Transaction) (ids.ID, error) {
	vm.mempoolLock.Lock()
	defer vm.mempoolLock.Unlock()

	now := vm.clock.Time().Unix()
	vm.stateLock.RLock()
	r := newRunning()
	// Fold in the backlog BuildBlock will place ahead of this transaction, so a
	// payer can pipeline nonces 1..n without waiting for a block. A queued
	// transaction that has since become unadmissible (its key was revoked by a
	// block accepted meanwhile) does not advance r — BuildBlock will drop it for
	// the same reason, so the newcomer must be judged as if it is not there.
	for _, queued := range vm.mempool {
		_ = vm.admit(queued, now, r)
	}
	err := vm.checkTx(tx, now, r)
	vm.stateLock.RUnlock()
	if err != nil {
		return ids.Empty, err
	}

	vm.mempool = append(vm.mempool, tx)
	vm.work.Signal()
	return tx.ID(), nil
}

// WaitForEvent blocks until there are pending transactions or the VM stops.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.work.WaitForEvent(ctx)
}

// BuildBlock drains the mempool into a new block extending the last accepted
// block. It assembles the block through the SAME predicate Verify will judge it
// by, dropping any transaction that does not pass, so a block this node builds
// always verifies. A transaction that is dropped is gone: keeping it would put
// it back in the very next block, where it would fail again.
//
// The block is not yet verified or accepted — settlement happens in Verify/Accept.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.shutdownLock.RLock()
	down := vm.shuttingDown
	vm.shutdownLock.RUnlock()
	if down {
		return nil, errVMShutdown
	}

	vm.mempoolLock.Lock()
	candidates := vm.mempool
	vm.mempool = nil
	vm.mempoolLock.Unlock()
	if len(candidates) == 0 {
		return nil, errNoPendingTxs
	}

	vm.stateLock.Lock()
	defer vm.stateLock.Unlock()

	parent := vm.lastBlock
	if parent == nil {
		vm.requeue(candidates)
		return nil, errNoParentBlock
	}

	// Block time never moves backwards: it is the clock every authorization
	// decision is made against, and Verify refuses a block stamped before its
	// parent.
	ts := vm.clock.Time()
	if ts.Before(parent.timestamp) {
		ts = parent.timestamp
	}

	r := newRunning()
	kept := candidates[:0]
	for _, tx := range candidates {
		if err := vm.checkTx(tx, ts.Unix(), r); err != nil {
			vm.log.Debug("keyvm: dropping unbuildable transaction",
				log.String("txID", tx.ID().String()),
				log.String("error", err.Error()))
			continue
		}
		kept = append(kept, tx)
	}
	if len(kept) == 0 {
		return nil, errNoPendingTxs
	}

	blk := &Block{
		parentID:     vm.lastAccepted,
		height:       parent.height + 1,
		timestamp:    ts,
		transactions: kept,
		vm:           vm,
	}
	blk.id = blk.computeID()
	vm.pendingBlocks[blk.id] = blk
	return blk, nil
}

// requeue returns transactions to the front of the mempool (on build/reject).
func (vm *VM) requeue(txs []*Transaction) {
	if len(txs) == 0 {
		return
	}
	vm.mempoolLock.Lock()
	vm.mempool = append(txs, vm.mempool...)
	vm.mempoolLock.Unlock()
	vm.work.Signal()
}

// dropFromMempool removes accepted transactions from the mempool by ID.
func (vm *VM) dropFromMempool(txs []*Transaction) {
	if len(txs) == 0 {
		return
	}
	accepted := make(map[ids.ID]struct{}, len(txs))
	for _, tx := range txs {
		accepted[tx.ID()] = struct{}{}
	}
	vm.mempoolLock.Lock()
	kept := vm.mempool[:0]
	for _, tx := range vm.mempool {
		if _, ok := accepted[tx.ID()]; !ok {
			kept = append(kept, tx)
		}
	}
	vm.mempool = kept
	vm.mempoolLock.Unlock()
}

// ---- Block storage ----

// ParseBlock decodes a block from bytes.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (chain.Block, error) {
	return parseBlock(vm, blockBytes)
}

// GetBlock returns a block by ID.
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (chain.Block, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	return vm.getBlockLocked(blockID)
}

// getBlockLocked is GetBlock's body; the caller holds stateLock.
func (vm *VM) getBlockLocked(blockID ids.ID) (*Block, error) {
	if blk, ok := vm.pendingBlocks[blockID]; ok {
		return blk, nil
	}
	if vm.lastBlock != nil && vm.lastBlock.id == blockID {
		return vm.lastBlock, nil
	}
	b, err := vm.versdb.Get(append([]byte(BlockPrefix), blockID[:]...))
	if err != nil {
		return nil, fmt.Errorf("keyvm: block %s: %w", blockID, err)
	}
	return parseBlock(vm, b)
}

// prunePending drops every processing block at or below the accepted height. A
// block the engine abandons without accepting or rejecting it is otherwise
// retained forever, and one of those is issued per build. Nothing at or below
// the accepted height can still be accepted, so nothing reachable is lost. The
// caller holds stateLock.
func (vm *VM) prunePending(acceptedHeight uint64) {
	for id, blk := range vm.pendingBlocks {
		if blk.height <= acceptedHeight {
			delete(vm.pendingBlocks, id)
		}
	}
}

// ---- ChainVM lifecycle / misc ----

func (vm *VM) SetState(ctx context.Context, state uint32) error { return nil }

func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error { return nil }

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	return vm.lastAccepted, nil
}

// GetBlockIDAtHeight returns the accepted block id at height. The index is
// written in the same commit as the block it names, so it never resolves to a
// block the chain did not accept.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	b, err := vm.versdb.Get(heightKey(height))
	if err != nil {
		return ids.Empty, fmt.Errorf("keyvm: height %d: %w", height, err)
	}
	if len(b) != ids.IDLen {
		return ids.Empty, fmt.Errorf("keyvm: height %d: corrupt index entry", height)
	}
	return ids.ID(b), nil
}

func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	handlers, err := vm.CreateHandlers(ctx)
	if err != nil {
		return nil, err
	}
	mux := http.NewServeMux()
	for path, h := range handlers {
		mux.Handle(path, h)
	}
	return mux, nil
}

func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{"/rpc": vm.rpcServer}, nil
}

func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

func (vm *VM) Version(ctx context.Context) (string, error) { return Version, nil }

func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, ver *chain.VersionInfo) error {
	return nil
}

func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error { return nil }

func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	vm.shutdownLock.RLock()
	down := vm.shuttingDown
	vm.shutdownLock.RUnlock()

	vm.stateLock.RLock()
	keyCount := len(vm.keys)
	ceremonyCount := len(vm.ceremonies)
	vm.stateLock.RUnlock()
	burned, _ := vm.Burned()

	return chain.HealthResult{
		Healthy: !down,
		Details: map[string]string{
			"version":    Version,
			"authOnly":   "true",
			"keys":       fmt.Sprintf("%d", keyCount),
			"ceremonies": fmt.Sprintf("%d", ceremonyCount),
			"height":     fmt.Sprintf("%d", vm.height),
			"burnedNLUX": fmt.Sprintf("%d", burned),
		},
	}, nil
}

// Shutdown stops the VM. There is no secret material to zero — by construction
// the VM never held any.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.shutdownLock.Lock()
	vm.shuttingDown = true
	vm.shutdownLock.Unlock()

	if vm.cancel != nil {
		vm.cancel()
	}
	if vm.versdb != nil {
		if err := vm.versdb.Close(); err != nil {
			vm.log.Error("keyvm: close db", log.String("error", err.Error()))
		}
	}
	vm.log.Info("K-Chain shut down")
	return nil
}

func (vm *VM) initHTTP() error {
	vm.rpcServer = rpc.NewServer()
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json;charset=UTF-8")
	return vm.rpcServer.RegisterService(&Service{vm: vm}, "kchain")
}

// accountFromHex parses a 20-byte hex address into a fee.Account.
func accountFromHex(s string) (fee.Account, error) {
	var a fee.Account
	b, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil {
		return a, err
	}
	if len(b) != ids.ShortIDLen {
		return a, fmt.Errorf("address must be %d bytes, got %d", ids.ShortIDLen, len(b))
	}
	copy(a[:], b)
	return a, nil
}
