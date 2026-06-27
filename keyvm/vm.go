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
	"github.com/luxfi/chains/keyvm/config"
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
	// Version of the K-Chain VM.
	Version = "2.0.0"
	// VMName is the human-readable name of the K-Chain VM.
	VMName = "keyvm"

	// Database namespaces. Key/ceremony records are JSON; balances live under
	// the fee ledger's own namespace (github.com/luxfi/chains/fee).
	KeyPrefix      = "key:"
	CeremonyPrefix = "ceremony:"
	BlockPrefix    = "block:"
)

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
	config.Config

	cancel   context.CancelFunc
	log      log.Logger
	db       database.Database
	versdb   *versiondb.Database
	state    database.Database // == versdb; buffered writes commit per block
	toEngine chan<- vmcore.Message
	notify   chan struct{}

	networkID uint32
	clock     mockable.Clock

	// PUBLIC state caches (authoritative copy lives in the DB).
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
	feePolicy nodefee.Policy

	// Consensus mempool + block bookkeeping.
	mempoolLock   sync.Mutex
	mempool       []*Transaction
	pendingBlocks map[ids.ID]*Block
	lastAccepted  ids.ID
	lastBlock     *Block
	height        uint64

	rpcServer *rpc.Server

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
	vm.db = init.DB
	vm.versdb = versiondb.New(init.DB)
	vm.state = vm.versdb
	vm.toEngine = init.ToEngine
	vm.notify = make(chan struct{}, 1)

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

	cfg, err := config.ParseConfig(init.Config)
	if err != nil {
		return fmt.Errorf("keyvm: parse config: %w", err)
	}
	vm.Config = cfg
	if err := vm.Config.Validate(); err != nil {
		return fmt.Errorf("keyvm: invalid config: %w", err)
	}

	vm.stateLock.Lock()
	vm.keys = make(map[ids.ID]*KeyRecord)
	vm.keysByName = make(map[string]ids.ID)
	vm.ceremonies = make(map[ids.ID]*CeremonyRecord)
	vm.stateLock.Unlock()
	vm.pendingBlocks = make(map[ids.ID]*Block)

	if init.Runtime != nil {
		vm.networkID = init.Runtime.NetworkID
	}
	if vm.Config.NetworkID != 0 {
		vm.networkID = vm.Config.NetworkID
	}

	vm.ledger = fee.NewLedger(vm.versdb)
	vm.feePolicy = newFeePolicy(vm.networkID)
	if err := nodefee.Validate(vm.feePolicy); err != nil {
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

	if err := vm.seedGenesis(genesis); err != nil {
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

// seedGenesis credits the funding allocation once (idempotent via a marker key).
// It is the only trusted state mutation; all later mutations go through blocks.
func (vm *VM) seedGenesis(g *Genesis) error {
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
	vm.keys = make(map[ids.ID]*KeyRecord)
	vm.keysByName = make(map[string]ids.ID)
	vm.ceremonies = make(map[ids.ID]*CeremonyRecord)

	kit := vm.state.NewIteratorWithPrefix([]byte(KeyPrefix))
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

	cit := vm.state.NewIteratorWithPrefix([]byte(CeremonyPrefix))
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

	if b, err := vm.state.Get(lastAcceptedKey); err == nil && len(b) == 32 {
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

func (vm *VM) putKey(rec *KeyRecord) error {
	data, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	if err := vm.state.Put([]byte(KeyPrefix+rec.ID.String()), data); err != nil {
		return err
	}
	vm.keys[rec.ID] = rec
	vm.keysByName[rec.Name] = rec.ID
	return nil
}

func (vm *VM) putCeremony(c *CeremonyRecord) error {
	data, err := json.Marshal(c)
	if err != nil {
		return err
	}
	if err := vm.state.Put([]byte(CeremonyPrefix+c.ID.String()), data); err != nil {
		return err
	}
	vm.ceremonies[c.ID] = c
	return nil
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
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], n)
	return vm.state.Put(key, u[:])
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

// SubmitTx validates, authenticates, and admission-checks a transaction, then
// enqueues it and signals the engine to build a block. The fee is SETTLED later,
// in block Accept — never here. Returns the transaction ID.
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
	if tx.Nonce <= vm.nonceOf(tx.Payer) {
		vm.stateLock.RUnlock()
		return ids.Empty, ErrBadNonce
	}
	if err := tx.checkAuth(vm, vm.clock.Time().Unix()); err != nil {
		vm.stateLock.RUnlock()
		return ids.Empty, err
	}
	err = fee.CanPay(vm.ledger, tx.Payer, feeAmt)
	vm.stateLock.RUnlock()
	if err != nil {
		return ids.Empty, err
	}

	vm.mempoolLock.Lock()
	vm.mempool = append(vm.mempool, tx)
	vm.mempoolLock.Unlock()

	select {
	case vm.notify <- struct{}{}:
	default:
	}
	return tx.ID(), nil
}

// WaitForEvent blocks until there are pending transactions or the VM stops.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	select {
	case <-ctx.Done():
		return vmcore.Message{}, ctx.Err()
	case <-vm.notify:
		return vmcore.Message{Type: vmcore.PendingTxs}, nil
	}
}

// BuildBlock drains the mempool into a new block extending the last accepted
// block. The block is not yet verified or accepted — settlement happens in
// Verify/Accept.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.shutdownLock.RLock()
	down := vm.shuttingDown
	vm.shutdownLock.RUnlock()
	if down {
		return nil, errVMShutdown
	}

	vm.mempoolLock.Lock()
	txs := vm.mempool
	vm.mempool = nil
	vm.mempoolLock.Unlock()
	if len(txs) == 0 {
		return nil, errNoPendingTxs
	}

	vm.stateLock.RLock()
	parent := vm.lastBlock
	parentID := vm.lastAccepted
	vm.stateLock.RUnlock()
	if parent == nil {
		vm.requeue(txs)
		return nil, errNoParentBlock
	}

	blk := &Block{
		parentID:     parentID,
		height:       parent.height + 1,
		timestamp:    vm.clock.Time(),
		transactions: txs,
		vm:           vm,
	}
	blk.id = blk.computeID()

	vm.shutdownLock.Lock()
	vm.pendingBlocks[blk.id] = blk
	vm.shutdownLock.Unlock()
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
	select {
	case vm.notify <- struct{}{}:
	default:
	}
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
	vm.shutdownLock.RLock()
	defer vm.shutdownLock.RUnlock()
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
		return nil, fmt.Errorf("keyvm: block %s: %w", blockID, err)
	}
	return parseBlock(vm, b)
}

// ---- ChainVM lifecycle / misc ----

func (vm *VM) SetState(ctx context.Context, state uint32) error { return nil }

func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error { return nil }

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.stateLock.RLock()
	defer vm.stateLock.RUnlock()
	return vm.lastAccepted, nil
}

func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return ids.Empty, errors.New("keyvm: height index not implemented")
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
