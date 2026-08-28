// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package fhevm implements the F-Chain: the coordination plane for
// confidential compute (LP-8200, LP-167). F records the PUBLIC coordinates of
// encrypted values — a handle, the digest of the off-chain ciphertext body, its
// owner, the capabilities granted over it, and the threshold decryptions asked
// for and answered — and it records nothing else. It holds no ciphertext body,
// no FHE secret key, and no decryption share; see state.go for the
// structurally-enforced invariant.
//
// The FHE runtime itself is github.com/luxfi/chains/mpcvm/fhe, and F reuses it
// rather than restating it: F's records embed the runtime's types, and F's
// public parameters come from the runtime's threshold configuration. What F
// does NOT reuse is the runtime's Registry, and the reason is consensus. The
// Registry stamps records with time.Now(), which is right for the off-chain
// daemon it was written for and wrong here: two validators replaying one block
// would store different bytes, so they would return different answers to the
// same query and neither would be wrong to. So F owns its persistence, and
// every timestamp it writes comes from the accepting block.
//
// F COMMITS NO STATE ROOT, so nothing in consensus would catch that divergence
// if it happened. What stands in its place is replay_test.go, which replays a
// chain onto independently-built nodes running different clocks and requires
// their databases to be byte-identical. Putting a root in consensus needs a
// state layer per in-flight block, which this VM does not have — see LLM.md,
// where the same missing layer is why a child of a verified-but-unaccepted
// block cannot be verified.
//
// Mutating operations take effect only through fee-settled consensus blocks
// (block.go), priced by a per-scheme gas schedule (gas.go) and burned from the
// payer's on-chain balance via the native fee settlement primitive
// (github.com/luxfi/chains/fee).
package fhevm

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
	"sync/atomic"
	"time"

	"github.com/gorilla/rpc/v2"
	grjson "github.com/gorilla/rpc/v2/json"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	nodefee "github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/timer/mockable"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
)

const (
	// Version of the F-Chain VM.
	Version = "1.0.0"
	// VMName is the human-readable name of the F-Chain VM.
	VMName = "fhevm"

	// Database namespaces. Records are JSON; balances live under the fee
	// ledger's own namespace (github.com/luxfi/chains/fee).
	CiphertextPrefix = "ct:"
	PermitPrefix     = "pm:"
	DecryptPrefix    = "dr:"
	EpochPrefix      = "ep:"
	BlockPrefix      = "block:"

	// MaxMempool bounds the queue. Admission is open to anyone who can pay, so
	// without a bound the queue is whatever an adversary chooses to make it.
	MaxMempool = 4096
)

var (
	lastAcceptedKey = []byte("fhevm/last-accepted")
	genesisMarker   = []byte("fhevm/genesis-applied")
	currentEpochKey = []byte("fhevm/current-epoch")
	noncePrefix     = []byte("nonce:")
	heightPrefix    = []byte("height:")
)

// Verify VM implements the consensus ChainVM interface.
var _ chain.ChainVM = (*VM)(nil)

// Sentinel errors. Every one denies an operation — the package fails secure.
var (
	errVMShutdown    = errors.New("fhevm: shutting down")
	errNoPendingTxs  = errors.New("fhevm: no pending transactions")
	errNoParentBlock = errors.New("fhevm: no parent block")
	errClockBehind   = errors.New("fhevm: local clock trails the chain tip by more than the skew allowance")

	ErrInvalidBlock     = errors.New("fhevm: malformed block")
	ErrMempoolFull      = errors.New("fhevm: mempool is full")
	ErrInvalidTxType    = errors.New("fhevm: invalid transaction type")
	ErrInvalidPayload   = errors.New("fhevm: invalid transaction payload")
	ErrUnknownScheme    = errors.New("fhevm: unsupported FHE scheme")
	ErrInvalidThreshold = errors.New("fhevm: invalid threshold (need 0 < t <= n)")
	ErrInvalidCommittee = errors.New("fhevm: invalid committee")
	ErrHandleMismatch   = errors.New("fhevm: subject does not match its payload")

	ErrUnsignedTx    = errors.New("fhevm: transaction missing payer auth/signature")
	ErrPayerMismatch = errors.New("fhevm: payer does not match auth public key")
	ErrBadSignature  = errors.New("fhevm: invalid payer signature")

	ErrCiphertextExists   = errors.New("fhevm: ciphertext already registered")
	ErrCiphertextNotFound = errors.New("fhevm: ciphertext not found")

	ErrPermitNotFound = errors.New("fhevm: permit not found")
	ErrPermitRevoked  = errors.New("fhevm: permit is revoked")
	ErrPermitExpired  = errors.New("fhevm: permit expired")
	ErrPermitInvalid  = errors.New("fhevm: permit does not authorize this operation")

	ErrRequestNotFound = errors.New("fhevm: decrypt request not found")
	ErrRequestClosed   = errors.New("fhevm: decrypt request already answered")
	ErrRequestExpired  = errors.New("fhevm: decrypt request expired")

	ErrEpochNotFound = errors.New("fhevm: epoch not found")
	ErrEpochMismatch = errors.New("fhevm: epoch is not the next one")
	ErrNotCommittee  = errors.New("fhevm: payer is not a committee member")

	ErrUnauthorized = errors.New("fhevm: payer not authorized for operation")

	// ErrBadNonce rejects a replayed or out-of-order transaction. A payer's
	// transactions MUST carry strictly increasing nonces starting at 1; this is
	// what stops a captured signed transaction from being resubmitted to drain
	// the payer's balance through repeated fee burns.
	ErrBadNonce = errors.New("fhevm: bad or replayed nonce")

	// ErrDuplicateEffect rejects a second transaction that would bring about an
	// effect another transaction in flight already claims. See
	// Transaction.effect.
	ErrDuplicateEffect = errors.New("fhevm: effect already claimed by a pending transaction")
)

// Config is the F-Chain VM's chain configuration, parsed from the node's
// per-chain config bytes. It carries only what cannot be derived: the network
// this chain belongs to.
type Config struct {
	NetworkID uint32 `json:"networkId"`
}

// VM implements the F-Chain Virtual Machine.
//
// Every field below is either runtime plumbing or a cache of PUBLIC records
// (CiphertextRecord / PermitRecord / DecryptRecord / EpochRecord). There is
// deliberately no ciphertext store, no key-share store, and no FHE evaluation
// session: F coordinates confidential compute, it does not perform it.
type VM struct {
	cancel context.CancelFunc
	log    log.Logger
	versdb *versiondb.Database
	state  database.Database // == versdb; buffered writes commit per block
	work   vmcore.Latch

	networkID uint32
	chainID   ids.ID
	clock     mockable.Clock

	// PUBLIC state caches (authoritative copy lives in the DB).
	stateLock   sync.RWMutex
	ciphertexts map[[32]byte]*CiphertextRecord
	permits     map[[32]byte]*PermitRecord
	decrypts    map[[32]byte]*DecryptRecord
	epochs      map[uint64]*EpochRecord
	epoch       uint64 // current epoch number

	// Native fee balance ledger (debit + burn), backed by the VM's versiondb so
	// settlement commits atomically with the operations it pays for.
	ledger *fee.Ledger

	// Admission policy (node/vms/types/fee). Orthogonal to settlement: this is
	// the boot-time floor declaration Manager validates; the per-op burn is done
	// through `ledger`.
	feePolicy nodefee.Policy

	// Consensus mempool. `claims` holds the effect of every queued transaction
	// so admission can refuse a second claim on it, and `queued` the highest
	// nonce queued per payer so admission demands the same consecutive nonces
	// consensus does. Both are derived from `mempool` and rebuilt from it
	// whenever it shrinks, so neither can drift away from the queue it
	// describes.
	//
	// LOCK ORDER, everywhere, without exception: stateLock then mempoolLock.
	// Accept holds stateLock and releases from the mempool inside it, so any
	// path taking them the other way round would deadlock.
	mempoolLock sync.Mutex
	mempool     []*Transaction
	claims      map[[32]byte]struct{}
	queued      map[fee.Account]uint64

	// Block bookkeeping, under stateLock with the rest of the chain state. It
	// was under a second mutex, which meant one map with two owners: BuildBlock
	// wrote it under one and the Accept-abort path read it under the other,
	// which is a data race and in Go a fatal, unrecoverable throw.
	pendingBlocks map[ids.ID]*Block
	lastAccepted  ids.ID
	lastBlock     *Block
	height        uint64

	rpcServer *rpc.Server

	// shuttingDown is read on every build and health check and written once, so
	// it is a flag rather than a lock — and one fewer lock is one fewer ordering
	// to get wrong.
	shuttingDown atomic.Bool
}

// Genesis is the F-Chain genesis: a funding allocation (address hex -> nLUX)
// and the epoch-0 threshold committee. There is no ciphertext in genesis —
// ciphertexts are registered through consensus transactions — so genesis
// carries nothing encrypted.
type Genesis struct {
	Version   int                   `json:"version"`
	Message   string                `json:"message"`
	Timestamp int64                 `json:"timestamp"`
	Alloc     map[string]uint64     `json:"alloc"`
	Committee []fhe.CommitteeMember `json:"committee"`
	Threshold int                   `json:"threshold"`
	PublicKey []byte                `json:"publicKey"`
}

// Initialize wires the VM: database, ledger, fee policy, caches, genesis
// seeding, and the JSON-RPC service.
func (vm *VM) Initialize(ctx context.Context, init vmcore.Init) error {
	_, vm.cancel = context.WithCancel(ctx)
	vm.versdb = versiondb.New(init.DB)
	vm.state = vm.versdb

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

	var cfg Config
	if len(init.Config) > 0 {
		if err := json.Unmarshal(init.Config, &cfg); err != nil {
			return fmt.Errorf("fhevm: parse config: %w", err)
		}
	}

	vm.stateLock.Lock()
	vm.ciphertexts = make(map[[32]byte]*CiphertextRecord)
	vm.permits = make(map[[32]byte]*PermitRecord)
	vm.decrypts = make(map[[32]byte]*DecryptRecord)
	vm.epochs = make(map[uint64]*EpochRecord)
	vm.stateLock.Unlock()
	vm.pendingBlocks = make(map[ids.ID]*Block)
	vm.claims = make(map[[32]byte]struct{})
	vm.queued = make(map[fee.Account]uint64)

	if init.Runtime != nil {
		vm.networkID = init.Runtime.NetworkID
		vm.chainID = init.Runtime.ChainID
	}
	if cfg.NetworkID != 0 {
		vm.networkID = cfg.NetworkID
	}

	vm.ledger = fee.NewLedger(vm.versdb)
	vm.feePolicy = newFeePolicy(vm.networkID)
	if err := nodefee.Validate(vm.feePolicy); err != nil {
		return fmt.Errorf("fhevm: fee policy: %w", err)
	}

	genesis := &Genesis{}
	if len(init.Genesis) > 0 {
		if err := json.Unmarshal(init.Genesis, genesis); err != nil {
			return fmt.Errorf("fhevm: parse genesis: %w", err)
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

	if err := vm.seedGenesis(genesis, genesisBlock.id); err != nil {
		return fmt.Errorf("fhevm: seed genesis: %w", err)
	}
	if err := vm.loadState(); err != nil {
		return fmt.Errorf("fhevm: load state: %w", err)
	}
	if err := vm.initHTTP(); err != nil {
		return fmt.Errorf("fhevm: init http: %w", err)
	}

	vm.log.Info("F-Chain initialized",
		log.String("version", Version),
		log.Uint32("networkID", vm.networkID),
		log.Uint64("height", vm.height),
		log.Uint64("epoch", vm.epoch),
	)
	return nil
}

// seedGenesis credits the funding allocation and installs the epoch-0
// committee, once (idempotent via a marker key). It is the only trusted state
// mutation; all later mutations go through blocks.
func (vm *VM) seedGenesis(g *Genesis, genesisBlockID ids.ID) error {
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
	// A committee in genesis goes through exactly the check TxAdvanceEpoch
	// applies, so a chain cannot be born with a committee that consensus would
	// refuse to install later.
	if len(g.Committee) > 0 {
		if err := ValidateCommittee(g.Committee, g.Threshold, g.PublicKey); err != nil {
			return err
		}
		rec := &EpochRecord{EpochInfo: fhe.EpochInfo{
			Epoch:     0,
			StartTime: g.Timestamp,
			Committee: g.Committee,
			Threshold: g.Threshold,
			PublicKey: g.PublicKey,
			Status:    fhe.EpochActive,
		}}
		if err := vm.writeEpoch(rec); err != nil {
			return err
		}
		if err := vm.state.Put(currentEpochKey, encodeU64(0)); err != nil {
			return err
		}
	}
	if err := vm.state.Put(heightKey(0), genesisBlockID[:]); err != nil {
		return err
	}
	if err := vm.versdb.Put(genesisMarker, []byte{1}); err != nil {
		return err
	}
	return vm.versdb.Commit()
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
	vm.ciphertexts = make(map[[32]byte]*CiphertextRecord)
	vm.permits = make(map[[32]byte]*PermitRecord)
	vm.decrypts = make(map[[32]byte]*DecryptRecord)
	vm.epochs = make(map[uint64]*EpochRecord)
	vm.epoch = 0

	if err := loadInto(vm, CiphertextPrefix, vm.ciphertexts, func(r *CiphertextRecord) [32]byte { return r.Handle }); err != nil {
		return err
	}
	if err := loadInto(vm, PermitPrefix, vm.permits, func(r *PermitRecord) [32]byte { return r.PermitID }); err != nil {
		return err
	}
	if err := loadInto(vm, DecryptPrefix, vm.decrypts, func(r *DecryptRecord) [32]byte { return r.RequestID }); err != nil {
		return err
	}
	if err := loadInto(vm, EpochPrefix, vm.epochs, func(r *EpochRecord) uint64 { return r.Epoch }); err != nil {
		return err
	}
	if b, err := vm.state.Get(currentEpochKey); err == nil && len(b) == 8 {
		vm.epoch = binary.BigEndian.Uint64(b)
	}

	if b, err := vm.state.Get(lastAcceptedKey); err == nil && len(b) == 32 {
		copy(vm.lastAccepted[:], b)
		if blk, err := vm.getBlockLocked(vm.lastAccepted); err == nil {
			vm.lastBlock = blk
			vm.height = blk.height
		}
	}
	return nil
}

// loadInto reads every JSON record under prefix into dst, keyed by key(record).
// One iteration shape serves all four record types, so a new record kind cannot
// be loaded a subtly different way from the others.
func loadInto[K comparable, R any](vm *VM, prefix string, dst map[K]*R, key func(*R) K) error {
	it := vm.state.NewIteratorWithPrefix([]byte(prefix))
	defer it.Release()
	for it.Next() {
		var rec R
		if err := json.Unmarshal(it.Value(), &rec); err != nil {
			vm.log.Warn("fhevm: skip corrupt record",
				log.String("prefix", prefix),
				log.String("error", err.Error()))
			continue
		}
		r := rec
		dst[key(&r)] = &r
	}
	return it.Error()
}

// ---- PUBLIC state accessors (used by tx checkAuth/Apply, under stateLock) ----

func (vm *VM) getCiphertext(handle [32]byte) (*CiphertextRecord, bool) {
	r, ok := vm.ciphertexts[handle]
	return r, ok
}

func (vm *VM) putCiphertext(rec *CiphertextRecord) error {
	if err := writeRecord(vm, CiphertextPrefix, rec.Handle, rec); err != nil {
		return err
	}
	vm.ciphertexts[rec.Handle] = rec
	return nil
}

func (vm *VM) getPermit(id [32]byte) (*PermitRecord, bool) {
	r, ok := vm.permits[id]
	return r, ok
}

func (vm *VM) putPermit(rec *PermitRecord) error {
	if err := writeRecord(vm, PermitPrefix, rec.PermitID, rec); err != nil {
		return err
	}
	vm.permits[rec.PermitID] = rec
	return nil
}

func (vm *VM) getDecrypt(id [32]byte) (*DecryptRecord, bool) {
	r, ok := vm.decrypts[id]
	return r, ok
}

func (vm *VM) putDecrypt(rec *DecryptRecord) error {
	if err := writeRecord(vm, DecryptPrefix, rec.RequestID, rec); err != nil {
		return err
	}
	vm.decrypts[rec.RequestID] = rec
	return nil
}

func (vm *VM) getEpoch(n uint64) (*EpochRecord, bool) {
	r, ok := vm.epochs[n]
	return r, ok
}

func (vm *VM) putEpoch(rec *EpochRecord) error {
	if err := vm.writeEpoch(rec); err != nil {
		return err
	}
	vm.epochs[rec.Epoch] = rec
	return nil
}

func (vm *VM) writeEpoch(rec *EpochRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return vm.state.Put(append([]byte(EpochPrefix), encodeU64(rec.Epoch)...), data)
}

// currentEpoch returns the sitting epoch. A chain whose genesis declared no
// committee has an epoch 0 with no members, which authorizes nobody — so
// fulfilment and epoch advance are refused until a committee exists, rather
// than accepted from anyone. Caller holds stateLock.
func (vm *VM) currentEpoch() *EpochRecord {
	if r, ok := vm.epochs[vm.epoch]; ok {
		return r
	}
	return &EpochRecord{EpochInfo: fhe.EpochInfo{Epoch: vm.epoch, Status: fhe.EpochActive}}
}

func (vm *VM) setCurrentEpoch(n uint64) error {
	if err := vm.state.Put(currentEpochKey, encodeU64(n)); err != nil {
		return err
	}
	vm.epoch = n
	return nil
}

func writeRecord[R any](vm *VM, prefix string, id [32]byte, rec *R) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	return vm.state.Put(append([]byte(prefix), id[:]...), data)
}

// nonceOf returns the payer's last-used nonce (0 if the account has never
// transacted). The next valid nonce is nonceOf(payer)+1. Caller holds a lock.
func (vm *VM) nonceOf(payer fee.Account) uint64 {
	key := append(append([]byte{}, noncePrefix...), payer[:]...)
	b, err := vm.state.Get(key)
	if err != nil || len(b) != 8 {
		return 0
	}
	return binary.BigEndian.Uint64(b)
}

// setNonce records the payer's last-used nonce (writes to the versiondb, so it
// commits atomically with the block). Caller holds stateLock.
func (vm *VM) setNonce(payer fee.Account, n uint64) error {
	key := append(append([]byte{}, noncePrefix...), payer[:]...)
	return vm.state.Put(key, encodeU64(n))
}

func encodeU64(v uint64) []byte {
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], v)
	return u[:]
}

func heightKey(h uint64) []byte {
	return append(append([]byte{}, heightPrefix...), encodeU64(h)...)
}

// ---- Read-only public queries (RPC) ----

// Ciphertext returns a copy of a ciphertext record.
func (vm *VM) Ciphertext(handle [32]byte) (*CiphertextRecord, bool) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	r, ok := vm.ciphertexts[handle]
	if !ok {
		return nil, false
	}
	c := *r
	return &c, true
}

// Ciphertexts returns copies of all ciphertext records.
func (vm *VM) Ciphertexts() []*CiphertextRecord {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	out := make([]*CiphertextRecord, 0, len(vm.ciphertexts))
	for _, r := range vm.ciphertexts {
		c := *r
		out = append(out, &c)
	}
	return out
}

// Permit returns a copy of a permit record.
func (vm *VM) Permit(id [32]byte) (*PermitRecord, bool) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	r, ok := vm.permits[id]
	if !ok {
		return nil, false
	}
	c := *r
	return &c, true
}

// Decrypt returns a copy of a decryption request record.
func (vm *VM) Decrypt(id [32]byte) (*DecryptRecord, bool) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	r, ok := vm.decrypts[id]
	if !ok {
		return nil, false
	}
	c := *r
	c.Attestations = append([]Attestation(nil), r.Attestations...)
	return &c, true
}

// Epoch returns a copy of an epoch record.
func (vm *VM) Epoch(n uint64) (*EpochRecord, bool) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	r, ok := vm.epochs[n]
	if !ok {
		return nil, false
	}
	c := *r
	c.Committee = append([]fhe.CommitteeMember(nil), r.Committee...)
	c.Attestations = append([]Attestation(nil), r.Attestations...)
	return &c, true
}

// CurrentEpoch returns the sitting epoch number.
func (vm *VM) CurrentEpoch() uint64 {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	return vm.epoch
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

// SubmitTx admits a transaction to this node's mempool. Admission is a FILTER,
// not a consensus rule: it refuses what this node can already tell will not
// work, so the queue stays useful. The rules consensus actually enforces live
// in batch.admit, and the fee is SETTLED later, in block Accept — never here.
//
// The nonce rule is the same one consensus applies, counted over what is
// already queued. It used to be the looser "greater than the last committed
// one", which let a payer queue a gap: admission took it, Verify refused the
// block for it, and since a Verify-failed block is dropped rather than
// rejected, the queue behind it went with it.
func (vm *VM) SubmitTx(tx *Transaction) (ids.ID, error) {
	if err := tx.SyntacticVerify(); err != nil {
		return ids.Empty, err
	}
	if err := tx.authenticate(); err != nil {
		return ids.Empty, err
	}
	feeAmt, err := FeeFor(tx)
	if err != nil {
		return ids.Empty, err
	}

	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	vm.mempoolLock.Lock()
	defer vm.mempoolLock.Unlock()

	if len(vm.mempool) >= MaxMempool {
		return ids.Empty, ErrMempoolFull
	}
	// The replay/order guard runs BEFORE authorization, so a replayed
	// transaction is reported as replayed whatever else is true of it.
	want := vm.nonceOf(tx.Payer) + 1
	if q, ok := vm.queued[tx.Payer]; ok && q >= want {
		want = q + 1
	}
	if tx.Nonce != want {
		return ids.Empty, ErrBadNonce
	}
	// Refuse a second claim on an effect already queued. Without this a payer
	// could enqueue two transactions that each pass every check alone and
	// together spend a block on work only one of them can do.
	eff := tx.effect()
	if _, dup := vm.claims[eff]; dup {
		return ids.Empty, ErrDuplicateEffect
	}
	if err := tx.checkAuth(vm, vm.clock.Time().Unix()); err != nil {
		return ids.Empty, err
	}
	if err := fee.CanPay(vm.ledger, tx.Payer, feeAmt); err != nil {
		return ids.Empty, err
	}

	vm.claims[eff] = struct{}{}
	vm.queued[tx.Payer] = tx.Nonce
	vm.mempool = append(vm.mempool, tx)
	vm.work.Signal()
	return tx.ID(), nil
}

// WaitForEvent blocks until there are pending transactions or the VM stops.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.work.WaitForEvent(ctx)
}

// BuildBlock proposes a block from the mempool. It SELECTS rather than drains:
// a transaction stays queued until the block carrying it is accepted, so an
// engine that discards a proposal — which it may do without ever calling Reject
// — cannot take the queue with it.
//
// Selection runs the same batch.admit that Verify runs, and simply skips what
// does not fit. A proposer therefore cannot build a block its own Verify would
// reject, and one unfit transaction no longer takes the rest down with it.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	if vm.shuttingDown.Load() {
		return nil, errVMShutdown
	}

	vm.stateLock.Lock()
	defer vm.stateLock.Unlock()

	parent := vm.lastBlock
	if parent == nil {
		return nil, errNoParentBlock
	}

	// Chain time never runs backwards, so a proposer whose clock has not moved
	// since its own tip advances by the smallest step instead of proposing a
	// block its own Verify would refuse. A clock so far behind that even that
	// step lands outside the skew allowance is a broken clock: such a node
	// declines to propose rather than produce a block nobody can verify.
	ts := vm.clock.Time()
	if !ts.After(parent.timestamp) {
		ts = parent.timestamp.Add(time.Second)
	}
	if ts.After(vm.clock.Time().Add(MaxFutureSkew)) {
		return nil, errClockBehind
	}

	vm.mempoolLock.Lock()
	queued := append([]*Transaction(nil), vm.mempool...)
	vm.mempoolLock.Unlock()
	if len(queued) == 0 {
		return nil, errNoPendingTxs
	}

	batch := newBatch(vm)
	picked := make([]*Transaction, 0, len(queued))
	for _, tx := range queued {
		if len(picked) == MaxBlockTxs {
			break
		}
		if err := batch.admit(tx); err != nil {
			continue
		}
		picked = append(picked, tx)
	}
	if len(picked) == 0 {
		return nil, errNoPendingTxs
	}

	blk := &Block{
		parentID:     vm.lastAccepted,
		height:       parent.height + 1,
		timestamp:    ts,
		transactions: picked,
		vm:           vm,
	}
	blk.id = blk.computeID()
	vm.trackVerified(blk)
	return blk, nil
}

// release drops accepted transactions from the mempool and rebuilds the indexes
// from what remains, so a claim or a queued nonce cannot outlive the
// transaction that put it there. Caller holds stateLock.
func (vm *VM) release(txs []*Transaction) {
	if len(txs) == 0 {
		return
	}
	accepted := make(map[ids.ID]struct{}, len(txs))
	for _, tx := range txs {
		accepted[tx.ID()] = struct{}{}
	}

	vm.mempoolLock.Lock()
	defer vm.mempoolLock.Unlock()

	kept := vm.mempool[:0]
	for _, tx := range vm.mempool {
		if _, ok := accepted[tx.ID()]; !ok {
			kept = append(kept, tx)
		}
	}
	vm.mempool = kept
	vm.claims = make(map[[32]byte]struct{}, len(kept))
	vm.queued = make(map[fee.Account]uint64, len(kept))
	for _, tx := range kept {
		vm.claims[tx.effect()] = struct{}{}
		if n, ok := vm.queued[tx.Payer]; !ok || tx.Nonce > n {
			vm.queued[tx.Payer] = tx.Nonce
		}
	}
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

func (vm *VM) getBlockLocked(blockID ids.ID) (*Block, error) {
	if vm.pendingBlocks != nil {
		if blk, ok := vm.pendingBlocks[blockID]; ok {
			return blk, nil
		}
	}
	if vm.lastBlock != nil && vm.lastBlock.id == blockID {
		return vm.lastBlock, nil
	}
	b, err := vm.state.Get(append([]byte(BlockPrefix), blockID[:]...))
	if err != nil {
		return nil, fmt.Errorf("fhevm: block %s: %w", blockID, err)
	}
	return parseBlock(vm, b)
}

// trackVerified makes a block findable by id while it is in flight, so a child
// can resolve it as a parent. Both the block we build and a block we verify
// from a peer go through here — tracking only our own left a follower able to
// verify b1 and unable to verify b2.
//
// It also prunes, because nothing else will: the engine may drop a block it
// never accepts and never rejects, so a tracker that only ever grew would leak
// exactly the way an unreleased mempool claim did. Anything at or below the
// last accepted height is already decided or orphaned, which bounds this to the
// blocks actually in flight above it.
//
// Caller holds stateLock for writing.
func (vm *VM) trackVerified(b *Block) {
	if b.height <= vm.height {
		return
	}
	for id, blk := range vm.pendingBlocks {
		if blk.height <= vm.height {
			delete(vm.pendingBlocks, id)
		}
	}
	vm.pendingBlocks[b.id] = b
}

// ---- ChainVM lifecycle / misc ----

func (vm *VM) SetState(ctx context.Context, state uint32) error { return nil }

func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error { return nil }

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	return vm.lastAccepted, nil
}

// GetBlockIDAtHeight answers from the height index Accept writes in the same
// commit as the block itself, so the index cannot name a block the chain did
// not accept.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	b, err := vm.state.Get(heightKey(height))
	if err != nil {
		return ids.Empty, fmt.Errorf("fhevm: height %d: %w", height, err)
	}
	if len(b) != 32 {
		return ids.Empty, fmt.Errorf("fhevm: height %d: %w: %d-byte index entry", height, ErrInvalidPayload, len(b))
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
		if path == "" {
			path = "/"
		}
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
	down := vm.shuttingDown.Load()

	// Every field is read under ONE hold of the lock, including height and the
	// burned counter. Reading any of them after releasing it is the same bug as
	// two mutexes over one map: a reader racing the Accept-abort path, which
	// rewrites all of this from the database.
	vm.stateLock.RLock()
	cts := len(vm.ciphertexts)
	permits := len(vm.permits)
	decrypts := len(vm.decrypts)
	epoch := vm.currentEpoch()
	committee := len(epoch.Committee)
	threshold := epoch.Threshold
	height := vm.height
	burned, _ := vm.ledger.Burned()
	vm.stateLock.RUnlock()

	return chain.HealthResult{
		// A committee is what makes F answerable: with none seated, decryptions
		// can be requested but never fulfilled, which is a degraded chain and is
		// reported as such rather than as healthy.
		Healthy: !down && committee > 0,
		Details: map[string]string{
			"version":     Version,
			"ciphertexts": fmt.Sprintf("%d", cts),
			"permits":     fmt.Sprintf("%d", permits),
			"decrypts":    fmt.Sprintf("%d", decrypts),
			"epoch":       fmt.Sprintf("%d", epoch.Epoch),
			"committee":   fmt.Sprintf("%d", committee),
			"threshold":   fmt.Sprintf("%d", threshold),
			"height":      fmt.Sprintf("%d", height),
			"burnedNLUX":  fmt.Sprintf("%d", burned),
		},
	}, nil
}

// Shutdown stops the VM. There is no secret material to zero — by construction
// the VM never held any.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.shuttingDown.Store(true)

	if vm.cancel != nil {
		vm.cancel()
	}
	if vm.versdb != nil {
		if err := vm.versdb.Close(); err != nil {
			vm.log.Error("fhevm: close db", log.String("error", err.Error()))
		}
	}
	vm.log.Info("F-Chain shut down")
	return nil
}

func (vm *VM) initHTTP() error {
	vm.rpcServer = rpc.NewServer()
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json;charset=UTF-8")
	return vm.rpcServer.RegisterService(&Service{vm: vm}, "fchain")
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
