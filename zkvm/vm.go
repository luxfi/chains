// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/chains/zkvm/precompiles"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	vmchain "github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/version"
)

var (
	_ vmchain.ChainVM = (*VM)(nil)
	_ vertex.DAGVM    = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}
)

// ZConfig contains VM configuration. Every field here is read; a knob that
// changes nothing reads as a control and is not one.
type ZConfig struct {
	// VerifyingKeys supplies real (non-dummy) verifying keys per circuit
	// type (keyed by the TransactionType string), in-memory at genesis.
	// When empty, loadVerifyingKeys installs all-zero dummy keys (proof
	// verification disabled, fail-closed). On a strict-PQ chain, supplying
	// a real bn254 verifying key here is REFUSED at construction
	// (errStrictPQRealVKForbidden) — shielded value uses STARK/FRI only.
	VerifyingKeys map[string][]byte `json:"verifyingKeys"`

	// StrictPQ HARD-DISABLES the classical (bn254 pairing-based) shielded
	// proof systems on this chain. When true, the shielded-tx ProofVerifier
	// REFUSES groth16/plonk/bulletproofs and accepts ONLY the post-quantum
	// STARK/FRI system (delegated to precompile/starkfri, which fails
	// closed until the prover binding exists). Loading a real (non-dummy)
	// bn254 verifying key on a strict-PQ chain is an ERROR. This is the
	// Lux primary-network posture: a CRQC that breaks bn254 cannot forge a
	// shield/unshield proof to mint or steal shielded value.
	StrictPQ bool `json:"strictPQ"`

	// MaxTxPerBlock bounds a block from either direction: what a proposer
	// assembles and what Verify accepts off the wire. One number, so a peer
	// cannot send a block larger than this node would ever build.
	MaxTxPerBlock uint32 `json:"maxTxPerBlock"`

	// ProofCacheSize bounds the verified-proof cache.
	ProofCacheSize uint32 `json:"proofCacheSize"`
}

// Defaults for a config that names no bound. Zero would mean a block of
// unbounded size and a cache of unbounded growth, which is not "no limit
// configured" but "no limit".
const (
	defaultMaxTxPerBlock  = 100
	defaultProofCacheSize = 1000
)

// VM implements the Zero-Knowledge UTXO Chain VM
type VM struct {
	rt     *runtime.Runtime
	config ZConfig

	// chain is the durable state, the blocks in flight and the tip — and the
	// one lock over all of it. The three stores below write through its view,
	// so their records commit with the decision that made them and are
	// discarded with one that fails.
	//
	// It holds chain.Block rather than *Block because Z-Chain decides in two
	// shapes: a linear block and a DAG vertex. Both change state the same way,
	// which is the whole of what the store needs to know about either.
	chain       *chain.Store[chain.Block]
	utxoDB      *UTXODB
	nullifierDB *NullifierDB
	root        *Root

	// Privacy components
	proofVerifier *ProofVerifier

	// zkPrecompiles holds the Z-Chain ZK verifier precompiles. It is
	// populated in Initialize by precompiles.RegisterZKPrecompiles, with
	// strictPQ taken from config.StrictPQ — the SAME single field that
	// gates the shielded-proof verifier. One profile bit, both switches:
	// on a strict-PQ chain the classical Groth16/PLONK verifiers (0x80/
	// 0x81) are NOT registered (fail-closed by absence) AND the shielded
	// proof verifier refuses classical systems.
	zkPrecompiles *precompiles.MapRegistry

	// Block management
	genesisBlock *Block

	// Transaction mempool
	mempool *Mempool

	// Consensus
	toEngine chan<- vmcore.Message

	// Logging
	log log.Logger

	// fee is what this chain charges to admit a shielded transaction at the
	// HTTP entry, before it reaches the mempool. Consensus-internal paths
	// bypass it.
	fee chain.Fee

	// bind is sha256(ChainID ‖ NetworkID). It is hashed into every block and
	// vertex id and into the public inputs every shielded proof is checked
	// against, and it is NOT on the wire — so a block or a proof made for
	// another chain does not name a block of this one and does not verify
	// here, rather than passing a check someone could forget to write.
	bind [32]byte
}

// Initialize initializes the VM
func (vm *VM) Initialize(
	ctx context.Context,
	init vmcore.Init,
) error {
	vm.rt = init.Runtime
	vm.toEngine = init.ToEngine
	vm.log = init.Log

	if vm.rt == nil {
		return errors.New("runtime is nil")
	}
	if init.DB == nil {
		return errors.New("database is nil")
	}
	if vm.log == nil {
		// Fallback to runtime log if available, strictly this should be set in init.Log
		if logger, ok := vm.rt.Log.(log.Logger); ok {
			vm.log = logger
		} else {
			return errors.New("invalid logger type")
		}
	}
	// Bind this chain's identity into every id and every proof preimage.
	bind := sha256.New()
	bind.Write(vm.rt.ChainID[:])
	binary.Write(bind, binary.BigEndian, vm.rt.NetworkID)
	copy(vm.bind[:], bind.Sum(nil))

	vm.chain = chain.New[chain.Block](init.DB, vm.reload)

	// Parse configuration or use defaults
	if len(init.Config) > 0 {
		if err := json.Unmarshal(init.Config, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		// Use default config. The Z-Chain is DEFINITIVELY strict-PQ (it is
		// the shielded-settlement chain pinned to the canonical Lux
		// strict-PQ security profile), so the default — used when genesis
		// carries no explicit ZConfig — pins StrictPQ=true and the only
		// accepted shielded system, STARK/FRI ("stark"). A non-strict
		// permissive deployment MUST set StrictPQ=false explicitly in
		// genesis; it is never the default for this chain.
		vm.config = ZConfig{
			StrictPQ:       true,
			MaxTxPerBlock:  defaultMaxTxPerBlock,
			ProofCacheSize: defaultProofCacheSize,
		}
	}

	if vm.config.ProofCacheSize == 0 {
		vm.config.ProofCacheSize = defaultProofCacheSize
	}
	if vm.config.MaxTxPerBlock == 0 {
		vm.config.MaxTxPerBlock = defaultMaxTxPerBlock
	}

	// Initialize UTXO database
	utxoDB, err := NewUTXODB(vm.chain.View(), vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize UTXO DB: %w", err)
	}
	vm.utxoDB = utxoDB

	// Initialize nullifier database
	nullifierDB, err := NewNullifierDB(vm.chain.View(), vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize nullifier DB: %w", err)
	}
	vm.nullifierDB = nullifierDB

	// Initialize state tree
	root, err := NewRoot(vm.chain.View(), vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize state root: %w", err)
	}
	vm.root = root

	// Initialize proof verifier
	proofVerifier, err := NewProofVerifier(vm.config, vm.bind, vm.log)
	if err != nil {
		return fmt.Errorf("failed to initialize proof verifier: %w", err)
	}
	vm.proofVerifier = proofVerifier
	if !proofVerifier.VerifyingKeysLoaded() {
		vm.log.Warn("Z-Chain running without real ZK verifying keys — proof verification disabled")
	}

	// Register the Z-Chain ZK verifier precompiles, deriving strictPQ from
	// the SAME config.StrictPQ field that gates the proof verifier above.
	// One profile bit drives both switches: a strict-PQ Z-Chain omits the
	// classical Groth16 (0x80) / PLONK (0x81) verifiers (fail-closed by
	// absence) so only the post-quantum STARK/FRI verifier (0x82) exists.
	vm.zkPrecompiles = precompiles.NewMapRegistry()
	precompiles.RegisterZKPrecompiles(vm.zkPrecompiles, vm.config.StrictPQ)
	vm.log.Info("Registered Z-Chain ZK precompiles",
		log.Bool("strictPQ", vm.config.StrictPQ),
	)

	// Initialize mempool
	vm.mempool = NewMempool(1000, vm.log) // Max 1000 pending txs

	// Z-Chain accepts user-submitted shielded txs, so it declares the floor;
	// the node's boot-time Validate refuses a zero-fee user-facing chain.
	var networkID uint32
	if init.Runtime != nil {
		networkID = init.Runtime.NetworkID
	}
	vm.fee = chain.Floor(networkID)
	if err := fee.Validate(vm.fee.Policy()); err != nil {
		return fmt.Errorf("zkvm: fee policy: %w", err)
	}

	// Initialize genesis block
	genesis, err := ParseGenesis(init.Genesis)
	if err != nil {
		return fmt.Errorf("failed to parse genesis: %w", err)
	}

	vm.genesisBlock = &Block{
		BlockHeight:    0,
		BlockTimestamp: genesis.Timestamp,
		Txs:            genesis.InitialTxs,
		vm:             vm,
	}
	vm.genesisBlock.ID_ = vm.genesisBlock.computeID()

	_, fresh, err := vm.chain.Open(vm.genesisBlock, func(raw []byte) (chain.Block, error) { return vm.parseBlock(raw) })
	if err != nil {
		return err
	}

	// The genesis allocation is the one mutation outside a block, and it is
	// committed on its own: staged, it would ride on whichever block landed
	// first and vanish from a chain that never accepted one. Seed records the
	// tip in that same commit, so a chain that has allocated says so on the
	// next boot and is not asked to allocate again — which ended in "UTXO
	// already exists", a node unable to restart until it produced a block.
	if fresh {
		if err := vm.chain.Seed(func(database.Database) error {
			return vm.processGenesisTransactions(genesis)
		}); err != nil {
			return err
		}
	}

	vm.log.Info("ZK UTXO VM initialized",
		log.String("version", Version.String()),
		log.Bool("strictPQ", vm.config.StrictPQ),
	)

	return nil
}

// ZKPrecompiles returns the registered Z-Chain ZK verifier precompiles.
// On a strict-PQ chain the classical Groth16 (0x80) / PLONK (0x81)
// addresses resolve to "no precompile" (fail-closed by absence).
func (vm *VM) ZKPrecompiles() *precompiles.MapRegistry { return vm.zkPrecompiles }

// StrictPQ reports whether this Z-Chain instance is on the strict-PQ
// security profile. It is the single bit that gates both the shielded-
// proof verifier and the classical-precompile registration.
func (vm *VM) StrictPQ() bool { return vm.config.StrictPQ }

// BuildBlock builds a new block. Reading the tip and registering the block on
// it happen in one step, so nothing can be accepted in between and leave the
// proposal hanging off a parent that is no longer the tip.
func (vm *VM) BuildBlock(ctx context.Context) (vmchain.Block, error) {
	built, err := vm.chain.Propose(func(parent chain.Block) (chain.Block, error) {
		// Get transactions from mempool
		txs := vm.mempool.GetPendingTransactions(int(vm.config.MaxTxPerBlock))
		if len(txs) == 0 {
			return nil, errNoTransactions
		}

		// Assembly runs the SAME predicate Verify runs, and drops what it
		// cannot build. It used to skip ValidateBasic, so a transaction with
		// an out-of-range Type — which the parser reads straight off the wire
		// — was assembled into every block and then refused by every node's
		// Verify, including the proposer's. Nothing evicted it, so that
		// proposer never produced another block.
		validTxs := make([]*Transaction, 0, len(txs))
		for _, tx := range txs {
			if err := vm.admit(tx, parent.Height()+1); err != nil {
				vm.log.Debug("Transaction not admitted",
					log.String("txID", tx.ID.String()),
					log.Reflect("error", err),
				)
				vm.mempool.RemoveTransaction(tx.ID)
				continue
			}
			validTxs = append(validTxs, tx)
		}

		if len(validTxs) == 0 {
			return nil, errNoTransactions
		}

		// Chain time only moves forward, and Verify refuses a block below its
		// parent. A parent may legally be up to maxClockSkew ahead of this
		// node's clock, so an unclamped time.Now() here builds a block this
		// node's own Verify then refuses.
		timestamp := time.Now().Unix()
		if parentBlock, ok := parent.(*Block); ok && timestamp < parentBlock.BlockTimestamp {
			timestamp = parentBlock.BlockTimestamp
		}

		block := &Block{
			ParentID_:      parent.ID(),
			BlockHeight:    parent.Height() + 1,
			BlockTimestamp: timestamp,
			Txs:            validTxs,
			vm:             vm,
		}
		block.StateRoot = vm.computeStateRoot(validTxs)
		block.ID_ = block.computeID()

		vm.log.Debug("Built new block",
			log.String("blockID", block.ID().String()),
			log.Uint64("height", block.BlockHeight),
			log.Int("txCount", len(validTxs)),
		)
		return block, nil
	})
	if err != nil {
		return nil, err
	}
	return built.(*Block), nil
}

// ParseBlock parses a block from bytes.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (vmchain.Block, error) {
	return vm.parseBlock(blockBytes)
}

// parseBlock decodes a block belonging to this VM. The store reads accepted
// blocks back through it, and ParseBlock hands peer bytes to it, so there is
// one decoder rather than one per caller — and one place where the id is
// derived from the content rather than read off the wire.
func (vm *VM) parseBlock(raw []byte) (*Block, error) {
	block := &Block{vm: vm}
	if err := parseBlockBytes(raw, block); err != nil {
		return nil, err
	}
	block.bytes = raw
	block.ID_ = block.computeID()
	return block, nil
}

// GetBlock retrieves a block by ID
func (vm *VM) GetBlock(ctx context.Context, blkID ids.ID) (vmchain.Block, error) {
	return vm.block(blkID)
}

// block resolves a block id to a block. It is the ONE place this chain decides
// that a decision it made is a block: a vertex is a decision too, and asking
// for one by block id is answered as a miss rather than with something the
// caller cannot use.
func (vm *VM) block(blkID ids.ID) (*Block, error) {
	if blkID == vm.genesisBlock.ID() {
		return vm.genesisBlock, nil
	}
	decided, err := vm.chain.Block(blkID, func(raw []byte) (chain.Block, error) { return vm.parseBlock(raw) })
	if err != nil {
		return nil, err
	}
	blk, ok := decided.(*Block)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a block", chain.ErrNoBlock, blkID)
	}
	return blk, nil
}

// reload rebuilds the caches the three stores keep beside the database. It runs
// after a block's writes have been discarded, so a cache that had already
// recorded that block's spends, outputs or root stops claiming them.
func (vm *VM) reload() error {
	if err := vm.nullifierDB.reload(); err != nil {
		return err
	}
	if err := vm.utxoDB.reload(); err != nil {
		return err
	}
	return vm.root.reload()
}

// SetState sets the VM state
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.log.Info("Shutting down ZK UTXO VM")

	if vm.utxoDB != nil {
		vm.utxoDB.Close()
	}

	if vm.nullifierDB != nil {
		vm.nullifierDB.Close()
	}

	if vm.root != nil {
		vm.root.Close()
	}

	if err := vm.chain.Close(); err != nil {
		return err
	}
	return vm.chain.Base().Close()
}

// Version returns the VM version
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// HealthCheck performs a health check
func (vm *VM) HealthCheck(ctx context.Context) (vmchain.HealthResult, error) {
	_, height := vm.chain.Tip()
	return vmchain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"utxoCount":       fmt.Sprintf("%d", vm.utxoDB.GetUTXOCount()),
			"nullifierCount":  fmt.Sprintf("%d", vm.nullifierDB.GetNullifierCount()),
			"lastBlockHeight": fmt.Sprintf("%d", height),
			"mempoolSize":     fmt.Sprintf("%d", vm.mempool.Size()),
			"proofCacheSize":  fmt.Sprintf("%d", vm.proofVerifier.GetCacheSize()),
		},
	}, nil
}

// CreateHandlers returns the VM handlers, one per route. See endpoints.
func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	return vm.endpoints(), nil
}

// NewHTTPHandler mounts the same routes by path.
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	mux := http.NewServeMux()
	for route, h := range vm.endpoints() {
		mux.Handle(route, h)
	}
	return mux, nil
}

// WaitForEvent blocks until there is a transaction to build a block from, or
// the VM stops. Waiting only on the context would mean BuildBlock is never
// called and the chain never leaves genesis, however many transactions the
// mempool has accepted.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.mempool.WaitForEvent(ctx)
}

// admit is the ONE predicate. Assembly (BuildBlock, BuildVertex) and consensus
// (Block.Verify, Vertex.Verify) both ask it, so a proposer cannot assemble a
// transaction its own peers refuse — which is a halt, free, for whoever sends
// the transaction.
func (vm *VM) admit(tx *Transaction, height uint64) error {
	if err := tx.ValidateBasic(); err != nil {
		return err
	}
	if tx.Expiry < height {
		return errExpired
	}
	return vm.verifyTransaction(tx)
}

// verifyTransaction verifies a transaction including ZK proofs
func (vm *VM) verifyTransaction(tx *Transaction) error {
	// Check nullifiers aren't already spent. A read that FAILED refuses the
	// transaction: reporting "not spent" for a set that could not be read is
	// how an already-spent note gets spent again.
	for _, nullifier := range tx.Nullifiers {
		_, spent, err := vm.nullifierDB.Spent(nullifier)
		if err != nil {
			return fmt.Errorf("zkvm: read spent set: %w", err)
		}
		if spent {
			return errNullifierSpent
		}
	}

	// Verify ZK proof
	if err := vm.proofVerifier.VerifyTransactionProof(tx); err != nil {
		return fmt.Errorf("proof verification failed: %w", err)
	}

	return nil
}

// computeStateRoot returns the state root a block carrying txs commits to. It
// reads the tree without mutating it, so BuildBlock and Verify agree and a
// rejected block leaves nothing behind.
func (vm *VM) computeStateRoot(txs []*Transaction) []byte {
	return vm.root.After(txs)
}

// processGenesisTransactions processes initial transactions from genesis
func (vm *VM) processGenesisTransactions(genesis *Genesis) error {
	for _, tx := range genesis.InitialTxs {
		// Add outputs to UTXO set
		for i, output := range tx.Outputs {
			utxo := &UTXO{
				TxID:        tx.ID,
				OutputIndex: uint32(i),
				Commitment:  output.Commitment,
				Ciphertext:  output.EncryptedNote,
				EphemeralPK: output.EphemeralPubKey,
				Height:      0, // Genesis height
			}
			if err := vm.utxoDB.AddUTXO(utxo); err != nil {
				return err
			}
		}
	}

	// Commit genesis to the root so block 1 builds on it, rather than leaving
	// genesis to be re-folded into every later block's root.
	return vm.root.Finalize(vm.root.After(genesis.InitialTxs))
}

// SetPreference records the block the engine wants the next one built on.
// Dropping it meant Propose always built on the accepted tip, so a node with
// two blocks in flight re-proposed a height it had already proposed.
func (vm *VM) SetPreference(ctx context.Context, blkID ids.ID) error {
	vm.chain.Prefer(blkID)
	return nil
}

func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	id, _ := vm.chain.Tip()
	return id, nil
}

func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *vmchain.VersionInfo) error {
	return nil
}

func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// Request implements the common.VM interface
func (vm *VM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	return nil
}

// Response implements the common.VM interface
func (vm *VM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return nil
}

// RequestFailed implements the common.VM interface
func (vm *VM) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// Gossip implements the common.VM interface
func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	return nil
}

// CrossChainRequest implements the common.VM interface
func (vm *VM) CrossChainRequest(ctx context.Context, chainID ids.ID, requestID uint32, deadline time.Time, request []byte) error {
	return nil
}

// CrossChainResponse implements the common.VM interface
func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	return nil
}

// CrossChainRequestFailed implements the common.VM interface
func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// GetBlockIDAtHeight answers from the height index the store writes in the
// same commit as the block itself, so the index can never name a block the
// chain did not accept.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return vm.chain.IDAtHeight(height)
}
