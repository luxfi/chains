// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/chains/internal/warpmsg"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/version"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/protocols/cmp/config"
	vmcore "github.com/luxfi/vm"
	vmchain "github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"
)

var (
	_ vmchain.ChainVM = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}
)

// minValidatorBond is the bond a bridge signer puts at risk. It is slashable,
// NOT staked, and it is declared here once: a chain that names its own
// minimum in two places eventually enforces the smaller one.
const minValidatorBond uint64 = 1_000_000 * 1e9 // 1M LUX

// BridgeConfig contains VM configuration
type BridgeConfig struct {
	// MinConfirmations is how deep a lock must be buried on its source chain
	// before this chain will carry it. It is applied where the lock is read,
	// so a lock that is not yet deep enough is left for a later pass rather
	// than admitted and held.
	MinConfirmations uint32 `json:"minConfirmations"`
	BridgeFee        uint64 `json:"bridgeFee"` // Fee in LUX for bridge operations

	// ExternalChains is the ONE declaration of which chains this bridge
	// serves. It carries endpoints, gateway + custody addresses, and KMS paths
	// for the relayer keys — never key material. A relayer node reads this and
	// calls EnableBridgeRelease with a KMS-backed KeyProvider and a Warp-backed
	// AttestationClient; every other node uses it to name the chains it will
	// carry transfers between.
	ExternalChains []ExternalChainConfig `json:"externalChains,omitempty"`

	// The spend caps. Both are declared, never defaulted: a bridge whose cap
	// is whatever the code happens to pick is a bridge nobody decided the risk
	// of.
	MaxBridgeAmount  uint64 `json:"maxBridgeAmount"`  // Maximum amount per transfer
	DailyBridgeLimit uint64 `json:"dailyBridgeLimit"` // Maximum per destination per day

	RequireValidatorBond uint64 `json:"requireValidatorBond"` // Bond required of a signer (slashable, NOT staked)

	// MaxSigners is the size the signer set freezes at (LP-333).
	MaxSigners int `json:"maxSigners"`
}

// validate refuses a configuration this chain cannot enforce. A bridge with no
// declared cap does not fail safe by accident: a zero per-transfer cap refuses
// every transfer silently at every block, which looks exactly like a bridge
// nobody is using.
func (c *BridgeConfig) validate() error {
	switch {
	case c.MinConfirmations == 0:
		return errors.New("bridgevm: minConfirmations must be at least 1")
	case c.MaxBridgeAmount == 0:
		return errors.New("bridgevm: maxBridgeAmount must be declared")
	case c.DailyBridgeLimit < c.MaxBridgeAmount:
		return fmt.Errorf("bridgevm: dailyBridgeLimit %d is below maxBridgeAmount %d",
			c.DailyBridgeLimit, c.MaxBridgeAmount)
	case c.RequireValidatorBond < minValidatorBond:
		return fmt.Errorf("bridgevm: requireValidatorBond %d is below the %d minimum",
			c.RequireValidatorBond, minValidatorBond)
	}
	return nil
}

// SignerSet tracks the current MPC signer set (LP-333)
// First MaxSigners validators opt-in without reshare. Reshare ONLY on slot
// replacement.
type SignerSet struct {
	Signers      []*SignerInfo `json:"signers"`      // Active signers
	Waitlist     []ids.NodeID  `json:"waitlist"`     // Validators waiting for a slot
	CurrentEpoch uint64        `json:"currentEpoch"` // Increments ONLY on reshare (slot replacement)
	SetFrozen    bool          `json:"setFrozen"`    // True when len(Signers) >= MaxSigners
	ThresholdT   int           `json:"thresholdT"`   // t, where t+1 signers are required
	PublicKey    []byte        `json:"publicKey"`    // Combined threshold public key
}

// quorum is how many of n signers must agree, and it is the only definition of
// that number.
//
// ⌈2n/3⌉, in integers. The float it replaced read int(n*0.67), which at n=3
// asked for all three: a set with no fault tolerance at all, where one signer
// going away stops the bridge. At n=1 it asked for two of one, which nothing
// can satisfy. Rounding a security threshold through a configurable float also
// left the number a matter of taste; it is not.
func quorum(n int) int {
	if n <= 0 {
		return 0
	}
	return (2*n + 2) / 3
}

// SignerInfo contains information about a signer in the set
type SignerInfo struct {
	NodeID     ids.NodeID `json:"nodeId"`
	PartyID    party.ID   `json:"partyId"`
	BondAmount uint64     `json:"bondAmount"` // Slashable bond, NOT stake
	MPCPubKey  []byte     `json:"mpcPubKey"`
	Active     bool       `json:"active"`
	JoinedAt   time.Time  `json:"joinedAt"`
	SlotIndex  int        `json:"slotIndex"`
	Slashed    bool       `json:"slashed"`    // True if this signer has been slashed
	SlashCount int        `json:"slashCount"` // Number of times slashed
}

// RegisterValidatorInput is the input for registering as a bridge signer
type RegisterValidatorInput struct {
	NodeID     string `json:"nodeId"`
	BondAmount string `json:"bondAmount,omitempty"`
	MPCPubKey  string `json:"mpcPubKey,omitempty"`
}

// RegisterValidatorResult is the result of registering as a bridge signer
type RegisterValidatorResult struct {
	Success        bool   `json:"success"`
	NodeID         string `json:"nodeId"`
	Registered     bool   `json:"registered"`
	Waitlisted     bool   `json:"waitlisted"`
	SignerIndex    int    `json:"signerIndex"`
	WaitlistIndex  int    `json:"waitlistIndex,omitempty"`
	TotalSigners   int    `json:"totalSigners"`
	Threshold      int    `json:"threshold"`
	ReshareNeeded  bool   `json:"reshareNeeded"` // Always false for opt-in (LP-333)
	CurrentEpoch   uint64 `json:"currentEpoch"`
	SetFrozen      bool   `json:"setFrozen"`
	RemainingSlots int    `json:"remainingSlots"`
	Message        string `json:"message"`
}

// SignerSetInfo is the result of getting signer set information
type SignerSetInfo struct {
	TotalSigners   int           `json:"totalSigners"`
	Threshold      int           `json:"threshold"`
	MaxSigners     int           `json:"maxSigners"`
	CurrentEpoch   uint64        `json:"currentEpoch"`
	SetFrozen      bool          `json:"setFrozen"`
	RemainingSlots int           `json:"remainingSlots"`
	WaitlistSize   int           `json:"waitlistSize"`
	Signers        []*SignerInfo `json:"signers"`
	PublicKey      string        `json:"publicKey,omitempty"`
}

// SignerReplacementResult is the result of replacing a failed signer
type SignerReplacementResult struct {
	Success           bool   `json:"success"`
	RemovedNodeID     string `json:"removedNodeId,omitempty"`
	ReplacementNodeID string `json:"replacementNodeId,omitempty"`
	ReshareSession    string `json:"reshareSession,omitempty"`
	NewEpoch          uint64 `json:"newEpoch"`
	ActiveSigners     int    `json:"activeSigners"`
	Threshold         int    `json:"threshold"`
	Message           string `json:"message"`
}

// CrossChainMPCRequest represents a cross-chain request to ThresholdVM for MPC operations
type CrossChainMPCRequest struct {
	Type          MPCRequestType `json:"type"`
	SessionID     string         `json:"sessionId"`
	Epoch         uint64         `json:"epoch"`
	OldPartyIDs   []party.ID     `json:"oldPartyIds"`
	NewPartyIDs   []party.ID     `json:"newPartyIds"`
	Threshold     int            `json:"threshold"`
	SourceChainID []byte         `json:"sourceChainId"`
	Timestamp     int64          `json:"timestamp"`
}

// MPCRequestType defines the type of MPC cross-chain request
type MPCRequestType uint8

const (
	// MPCRequestReshare triggers a key reshare protocol
	MPCRequestReshare MPCRequestType = iota
	// MPCRequestSign triggers a threshold signing operation
	MPCRequestSign
	// MPCRequestRefresh triggers a proactive key refresh
	MPCRequestRefresh
)

// maxRequestsPerBlock caps how many bridge requests one block carries. Applied
// to the id-sorted candidate list, so the cap is a deterministic prefix.
const maxRequestsPerBlock = 100

// VM implements the Bridge VM for cross-chain interoperability
type VM struct {
	rt     *runtime.Runtime
	config BridgeConfig
	log    log.Logger

	// chainID is the chain this VM is running, hashed into every block id so a
	// block of one chain is not a block of another.
	chainID ids.ID

	// Custody threshold signing runs on M-Chain (mpcvm) via dealerless
	// CGGMP21/FROST DKG — no trusted dealer, secret never assembled by any
	// validator. B-Chain requests keygen/reshare/sign from M-Chain over
	// Warp (CrossChainMPCRequest) and VERIFIES the resulting attestations
	// against this config. B-Chain never holds a custody key.
	mpcConfig *config.Config

	// LP-333: Signer Set Management (opt-in model)
	signerSet *SignerSet

	// pendingBridges holds the transfers waiting for a block, keyed by the
	// digest that identifies them.
	pendingBridges map[ids.ID]*BridgeRequest

	// Permissionless settlement: authoritative quote engine + swap
	// state, exposed via bridge_estimateFee / bridge_submitRequest /
	// bridge_getStatus (see rpc.go).
	quoteEngine *QuoteEngine
	swapStore   SwapStore

	// evmByChainID routes a transfer to the client for its chain. Populated by
	// EnableBridgeRelease on relayer nodes and empty everywhere else.
	evmByChainID map[uint32]ChainClient

	// EVM release plumbing (injected via EnableBridgeRelease; nil until a
	// relayer node wires it). attestClient is B's boundary to M-Chain; releaser
	// drives broadcasts off the consensus path.
	attestClient AttestationClient
	releaser     *releaser
	watcher      *watcher

	// work tells consensus a block can be built. The watcher signals it when a
	// source chain reports a lock.
	work vmcore.Latch

	// chain is the durable state, the blocks in flight and the tip, under its
	// own lock. What a block decides is written and committed there.
	chain        *chain.Store[*Block]
	genesisBlock *Block

	// fee is what this chain charges to admit a user-submitted transfer, before
	// any M-Chain signing capacity is consumed.
	fee chain.Fee

	// mu guards the bridge's own state above — the transfers in flight, the
	// signer set, the chain clients, the release plumbing. That is not the
	// chain's state and does not share the chain's lock.
	//
	// LOCK ORDER, without exception: the chain's lock, then this one. A block
	// publishes under the chain's lock and clears its transfers inside it, so
	// any path taking them the other way round would deadlock.
	mu sync.RWMutex
}

// BridgeRequest is one cross-chain transfer this chain has been asked to
// settle.
//
// ID is the transfer's digest — the same value M signs and the destination
// gateway keys its replay guard by — so the request's name IS its contents.
// Every field but SourceTxID is covered by it, and SourceTxID is a source-chain
// fact every node reads the same.
type BridgeRequest struct {
	ID         ids.ID `json:"id"`
	SrcChainID uint32 `json:"srcChainId"`
	DstChainID uint32 `json:"dstChainId"`
	Nonce      uint64 `json:"nonce"`
	Asset      ids.ID `json:"asset"`
	Amount     uint64 `json:"amount"`
	Recipient  []byte `json:"recipient"`
	SourceTxID ids.ID `json:"sourceTxId"`
}

// ChainClient interface for interacting with different chains
type ChainClient interface {
	GetTransaction(ctx context.Context, txID ids.ID) (interface{}, error)
	GetConfirmations(ctx context.Context, txID ids.ID) (uint32, error)
	SendTransaction(ctx context.Context, tx interface{}) (ids.ID, error)
	ValidateAddress(address []byte) error
	// IsProcessed asks the destination gateway whether it already released this
	// transfer. The release path calls it before requesting an attestation, so it
	// belongs to the contract that path depends on.
	IsProcessed(ctx context.Context, transfer bridgeattest.BridgeTransfer) (bool, error)
}

// Initialize implements the chain.ChainVM interface
func (vm *VM) Initialize(
	ctx context.Context,
	vmInit vmcore.Init,
) error {
	vm.rt = vmInit.Runtime
	if vm.rt == nil {
		return errors.New("bridgevm: no runtime")
	}
	if vmInit.DB == nil {
		return errors.New("bridgevm: no database")
	}

	logger, ok := vm.rt.Log.(log.Logger)
	if !ok {
		return errors.New("bridgevm: invalid logger type")
	}
	vm.log = logger
	vm.chainID = vm.rt.ChainID

	vm.pendingBridges = make(map[ids.ID]*BridgeRequest)
	vm.evmByChainID = make(map[uint32]ChainClient)

	// B-Chain accepts user-submitted bridge transfers, so it declares the
	// floor; the node's boot-time Validate refuses a zero-fee user-facing chain.
	vm.fee = chain.Floor(vm.rt.NetworkID)
	if err := fee.Validate(vm.fee.Policy()); err != nil {
		return fmt.Errorf("bridgevm: fee policy: %w", err)
	}

	if len(vmInit.Config) > 0 {
		if err := json.Unmarshal(vmInit.Config, &vm.config); err != nil {
			return fmt.Errorf("bridgevm: parse config: %w", err)
		}
	}
	if vm.config.MaxSigners == 0 {
		vm.config.MaxSigners = 100 // LP-333: the set freezes here
	}
	if err := vm.config.validate(); err != nil {
		return err
	}

	vm.signerSet = &SignerSet{
		Signers:  make([]*SignerInfo, 0, vm.config.MaxSigners),
		Waitlist: make([]ids.NodeID, 0),
	}

	// Authoritative quote engine + swap store. The price feed default
	// seeds the assets the bridge handles at genesis.
	vm.quoteEngine = &QuoteEngine{Feed: defaultPriceFeed()}
	vm.swapStore = newInMemorySwapStore()

	// EVM chain clients are wired by EnableBridgeRelease (relayer nodes only),
	// which needs the KMS-backed KeyProvider and the Warp-backed
	// AttestationClient — runtime deps not available at consensus boot. Config
	// carries the chain list; a relayer reads vm.config.ExternalChains and calls
	// EnableBridgeRelease. Non-relayer nodes never broadcast.

	genesis := &Genesis{}
	if len(vmInit.Genesis) > 0 {
		if err := json.Unmarshal(vmInit.Genesis, genesis); err != nil {
			return fmt.Errorf("bridgevm: parse genesis: %w", err)
		}
	}

	vm.chain = chain.New[*Block](vmInit.DB, nil)

	genesisBlock := &Block{
		BlockHeight:    0,
		BlockTimestamp: genesis.Timestamp,
		ParentID_:      ids.Empty,
		BridgeRequests: []*BridgeRequest{},
		vm:             vm,
	}
	genesisBlock.ID_ = genesisBlock.computeID()
	vm.genesisBlock = genesisBlock

	_, fresh, err := vm.chain.Open(genesisBlock, vm.parseBlock)
	if err != nil {
		return err
	}
	// A chain that reports no tip while its own settlement records are on disk
	// did not find a fresh database — it failed to read one. Starting from
	// genesis there would commit a new chain over a live one and re-open a
	// daily cap that has already been spent, durably and without a word.
	if fresh {
		settled, err := hasAny(vmInit.DB, settledPrefix)
		if err != nil {
			return fmt.Errorf("bridgevm: read settlement records: %w", err)
		}
		if settled {
			return errors.New("bridgevm: no tip recorded, but this database holds settled transfers — refusing to restart the chain over it")
		}
	}
	return nil
}

// hasAny reports whether the database holds even one key under prefix.
func hasAny(db database.Database, prefix []byte) (bool, error) {
	it := db.NewIteratorWithPrefix(prefix)
	defer it.Release()
	found := it.Next()
	return found, it.Error()
}

// parseBlock decodes a block belonging to this VM. The store reads accepted
// blocks back through it, so there is one decoder rather than one per caller.
func (vm *VM) parseBlock(raw []byte) (*Block, error) {
	blk := &Block{vm: vm}
	if err := parseBlockBytes(raw, blk); err != nil {
		return nil, err
	}
	blk.ID_ = blk.computeID()
	return blk, nil
}

// BuildBlock implements the chain.ChainVM interface.
//
// The candidates are ordered by id and admitted by the SAME rule Verify
// applies, over the state as of the same parent. A builder with its own
// looser rule proposes a block every node refuses, and since a refused
// transfer goes straight back into the pending set, it proposes it again:
// block production stops and does not resume.
func (vm *VM) BuildBlock(ctx context.Context) (vmchain.Block, error) {
	return vm.chain.Propose(func(parent *Block) (*Block, error) {
		state := vm.spendAt(parent)

		// Chain time only moves forward, so a block is never stamped before
		// its parent even when this node's clock disagrees.
		at := time.Now().Unix()
		if at < parent.BlockTimestamp {
			at = parent.BlockTimestamp
		}
		day := at / dayLength

		// pendingBridges is a map and Go randomises map iteration, so the
		// candidate list is sorted before anything is chosen from it: the
		// order is hashed into the block id, and the cap has to be a defined
		// prefix rather than a random draw that can starve a transfer forever.
		vm.mu.RLock()
		candidates := make([]*BridgeRequest, 0, len(vm.pendingBridges))
		for _, req := range vm.pendingBridges {
			candidates = append(candidates, req)
		}
		vm.mu.RUnlock()

		sort.Slice(candidates, func(i, j int) bool {
			return bytes.Compare(candidates[i].ID[:], candidates[j].ID[:]) < 0
		})

		requests := make([]*BridgeRequest, 0, maxRequestsPerBlock)
		for _, req := range candidates {
			if len(requests) == maxRequestsPerBlock {
				break
			}
			if err := state.admit(&vm.config, day, req); err != nil {
				vm.log.Debug("bridgevm: transfer not carried",
					log.Stringer("requestID", req.ID), log.String("reason", err.Error()))
				continue
			}
			requests = append(requests, req)
		}
		if len(requests) == 0 {
			return nil, errors.New("bridgevm: no transfer is ready to be carried")
		}

		blk := &Block{
			ParentID_:      parent.ID(),
			BlockHeight:    parent.Height() + 1,
			BlockTimestamp: at,
			BridgeRequests: requests,
			vm:             vm,
			spend:          state,
		}
		blk.ID_ = blk.computeID()

		vm.log.Info("bridgevm: block built",
			log.Stringer("blockID", blk.ID()),
			log.Int("transfers", len(requests)),
		)
		return blk, nil
	})
}

// GetBlock implements the chain.ChainVM interface
func (vm *VM) GetBlock(ctx context.Context, id ids.ID) (vmchain.Block, error) {
	if vm.genesisBlock != nil && id == vm.genesisBlock.ID() {
		return vm.genesisBlock, nil
	}
	return vm.chain.Block(id, vm.parseBlock)
}

// ParseBlock implements the chain.ChainVM interface
func (vm *VM) ParseBlock(ctx context.Context, raw []byte) (vmchain.Block, error) {
	return vm.parseBlock(raw)
}

// SetPreference implements the chain.ChainVM interface
func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error {
	vm.chain.Prefer(id)
	return nil
}

// LastAccepted implements the chain.ChainVM interface
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	id, _ := vm.chain.Tip()
	return id, nil
}

// CreateHandlers implements the common.VM interface. The bridge's API is the
// JSON-RPC service in rpc.go: estimate a fee, submit a request, ask after one,
// read the signer set.
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return vm.CreateRPCHandlers()
}

// readiness reports whether this node can do what it is configured to do, and
// says what is missing when it cannot.
func (vm *VM) readiness() (ready bool, reason string, chains int) {
	vm.mu.RLock()
	chains = len(vm.evmByChainID)
	watching := vm.watcher != nil
	vm.mu.RUnlock()

	// No chains wired means this node is not a relayer, which is a
	// configuration and not a fault: it validates like any other node and has
	// nothing to release.
	if chains == 0 {
		return true, "healthy", 0
	}
	// A relayer needs a threshold key to attest with and has to be reading the
	// chains it relays from. Answering healthy without either routes transfers
	// at a node that cannot carry them.
	switch {
	case len(vm.mpcGroupPublicKey()) == 0:
		return false, "no threshold signing key", chains
	case !watching:
		return false, "not watching for locks", chains
	default:
		return true, "healthy", chains
	}
}

// HealthCheck implements the common.VM interface, reporting what this node can
// do so traffic reaches one that can bridge.
func (vm *VM) HealthCheck(ctx context.Context) (vmchain.HealthResult, error) {
	ready, reason, chains := vm.readiness()
	return vmchain.HealthResult{
		Healthy: ready,
		Details: map[string]string{
			"status": reason,
			"chains": strconv.Itoa(chains),
		},
	}, nil
}

// Shutdown implements the common.VM interface
func (vm *VM) Shutdown(ctx context.Context) error {
	// Stop the release worker first (it takes vm.mu internally); do NOT hold the
	// lock across stop() or the worker's own vm.mu use would deadlock.
	vm.stopReleaser()
	return nil
}

// CreateStaticHandlers implements the common.VM interface
func (vm *VM) CreateStaticHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return nil, nil
}

// Connected implements the common.VM interface
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *vmchain.VersionInfo) error {
	return nil
}

// Disconnected implements the common.VM interface
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

// Version implements the common.VM interface
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
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

// SetState implements the common.VM interface
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// NewHTTPHandler returns HTTP handlers for the VM
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	handlers, err := vm.CreateHandlers(ctx)
	if err != nil {
		return nil, err
	}

	mux := http.NewServeMux()
	for path, handler := range handlers {
		if path == "" {
			path = "/"
		}
		mux.Handle(path, handler)
	}
	return mux, nil
}

// WaitForEvent blocks until there is a bridge request to build a block from, or
// the VM stops. Waiting only on the context would mean BuildBlock is never
// called, so no lock the watcher found would ever reach a block.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.work.WaitForEvent(ctx)
}

// Genesis represents the genesis state
type Genesis struct {
	Timestamp int64 `json:"timestamp"`
}

// =============================================================================
// LP-333: Opt-In Signer Set Management
// First MaxSigners validators opt-in without reshare. Reshare ONLY on slot
// replacement.
// =============================================================================

// renumber makes each signer's slot its position in the set. The slot was
// stored and left alone through removals, so after the first one it named a
// position the signer no longer held.
func (s *SignerSet) renumber() {
	for i, signer := range s.Signers {
		signer.SlotIndex = i
	}
	s.ThresholdT = quorum(len(s.Signers)) - 1
	if s.ThresholdT < 0 {
		s.ThresholdT = 0
	}
}

// RegisterValidator registers a new validator as a bridge signer (opt-in model)
// LP-333: the first MaxSigners validators are accepted directly - NO reshare on
// join. After that, new validators go to the waitlist until a slot opens.
func (vm *VM) RegisterValidator(input *RegisterValidatorInput) (*RegisterValidatorResult, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	nodeID, err := ids.NodeIDFromString(input.NodeID)
	if err != nil {
		return nil, fmt.Errorf("bridgevm: invalid node ID: %w", err)
	}

	for _, signer := range vm.signerSet.Signers {
		if signer.NodeID == nodeID {
			return &RegisterValidatorResult{
				Success:      false,
				NodeID:       input.NodeID,
				Message:      "already registered as signer",
				TotalSigners: len(vm.signerSet.Signers),
				Threshold:    vm.signerSet.ThresholdT,
				CurrentEpoch: vm.signerSet.CurrentEpoch,
				SetFrozen:    vm.signerSet.SetFrozen,
			}, nil
		}
	}

	for _, wl := range vm.signerSet.Waitlist {
		if wl == nodeID {
			return &RegisterValidatorResult{
				Success:    false,
				NodeID:     input.NodeID,
				Message:    "already on waitlist",
				Waitlisted: true,
			}, nil
		}
	}

	// The bond is the whole of a signer's accountability, and the chain
	// declares what it must be. Reading the field and admitting whatever it
	// said left the requirement documented and unapplied.
	bondAmount, err := strconv.ParseUint(input.BondAmount, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("bridgevm: bond amount %q is not a number", input.BondAmount)
	}
	if bondAmount < vm.config.RequireValidatorBond {
		return nil, fmt.Errorf("bridgevm: bond %d is below the required %d",
			bondAmount, vm.config.RequireValidatorBond)
	}

	if !vm.signerSet.SetFrozen && len(vm.signerSet.Signers) < vm.config.MaxSigners {
		signerInfo := &SignerInfo{
			NodeID:     nodeID,
			PartyID:    party.ID(nodeID.String()),
			BondAmount: bondAmount,
			Active:     true,
			JoinedAt:   time.Now(),
		}
		if input.MPCPubKey != "" {
			signerInfo.MPCPubKey = []byte(input.MPCPubKey)
		}

		vm.signerSet.Signers = append(vm.signerSet.Signers, signerInfo)
		vm.signerSet.renumber()
		if len(vm.signerSet.Signers) >= vm.config.MaxSigners {
			vm.signerSet.SetFrozen = true
		}

		vm.logInfo("bridgevm: validator registered as signer",
			log.Stringer("nodeID", nodeID),
			log.Int("slot", signerInfo.SlotIndex),
			log.Int("signers", len(vm.signerSet.Signers)),
			log.Int("threshold", vm.signerSet.ThresholdT),
			log.Bool("frozen", vm.signerSet.SetFrozen),
		)

		return &RegisterValidatorResult{
			Success:        true,
			NodeID:         input.NodeID,
			Registered:     true,
			SignerIndex:    signerInfo.SlotIndex,
			TotalSigners:   len(vm.signerSet.Signers),
			Threshold:      vm.signerSet.ThresholdT,
			CurrentEpoch:   vm.signerSet.CurrentEpoch,
			SetFrozen:      vm.signerSet.SetFrozen,
			RemainingSlots: vm.config.MaxSigners - len(vm.signerSet.Signers),
			Message:        "registered as bridge signer",
		}, nil
	}

	vm.signerSet.Waitlist = append(vm.signerSet.Waitlist, nodeID)
	waitlistIndex := len(vm.signerSet.Waitlist) - 1

	vm.logInfo("bridgevm: validator waitlisted, signer set frozen",
		log.Stringer("nodeID", nodeID),
		log.Int("waitlistIndex", waitlistIndex),
		log.Int("signers", len(vm.signerSet.Signers)),
	)

	return &RegisterValidatorResult{
		Success:       true,
		NodeID:        input.NodeID,
		Waitlisted:    true,
		WaitlistIndex: waitlistIndex,
		TotalSigners:  len(vm.signerSet.Signers),
		Threshold:     vm.signerSet.ThresholdT,
		CurrentEpoch:  vm.signerSet.CurrentEpoch,
		SetFrozen:     vm.signerSet.SetFrozen,
		Message:       "added to waitlist (signer set frozen)",
	}, nil
}

// logInfo writes a line when this VM has a logger. A VM assembled for a unit
// test has none, and a log call is not a reason for a chain to panic.
func (vm *VM) logInfo(msg string, fields ...interface{}) {
	if vm.log != nil && !vm.log.IsZero() {
		vm.log.Info(msg, fields...)
	}
}

func (vm *VM) logWarn(msg string, fields ...interface{}) {
	if vm.log != nil && !vm.log.IsZero() {
		vm.log.Warn(msg, fields...)
	}
}

// GetSignerSetInfo returns information about the current signer set
func (vm *VM) GetSignerSetInfo() *SignerSetInfo {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	remainingSlots := vm.config.MaxSigners - len(vm.signerSet.Signers)
	if remainingSlots < 0 {
		remainingSlots = 0
	}

	info := &SignerSetInfo{
		TotalSigners:   len(vm.signerSet.Signers),
		Threshold:      vm.signerSet.ThresholdT,
		MaxSigners:     vm.config.MaxSigners,
		CurrentEpoch:   vm.signerSet.CurrentEpoch,
		SetFrozen:      vm.signerSet.SetFrozen,
		RemainingSlots: remainingSlots,
		WaitlistSize:   len(vm.signerSet.Waitlist),
		Signers:        vm.signerSet.Signers,
	}

	if len(vm.signerSet.PublicKey) > 0 {
		info.PublicKey = fmt.Sprintf("%x", vm.signerSet.PublicKey)
	}

	return info
}

// RemoveSigner removes a failed/stopped signer and triggers replacement.
// LP-333: this is the ONLY operation that triggers a reshare, and the epoch
// increments only here.
func (vm *VM) RemoveSigner(nodeID ids.NodeID, replacementNodeID *ids.NodeID) (*SignerReplacementResult, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	slot := -1
	for i, signer := range vm.signerSet.Signers {
		if signer.NodeID == nodeID {
			slot = i
			break
		}
	}
	if slot < 0 {
		return &SignerReplacementResult{
			Success: false,
			Message: fmt.Sprintf("signer %s not found in active set", nodeID),
		}, nil
	}

	var replacement ids.NodeID
	var replacementSource string
	if replacementNodeID != nil && *replacementNodeID != ids.EmptyNodeID {
		replacement = *replacementNodeID
		replacementSource = "explicit"
	} else if len(vm.signerSet.Waitlist) > 0 {
		replacement = vm.signerSet.Waitlist[0]
		vm.signerSet.Waitlist = vm.signerSet.Waitlist[1:]
		replacementSource = "waitlist"
	}

	if replacement == ids.EmptyNodeID {
		vm.signerSet.Signers = append(vm.signerSet.Signers[:slot], vm.signerSet.Signers[slot+1:]...)
	} else {
		// The replacement takes the vacated slot. Splicing the old signer out
		// and appending the new one moved every signer above it, which is a
		// reshuffle of the set rather than the one-slot replacement LP-333
		// describes.
		vm.signerSet.Signers[slot] = &SignerInfo{
			NodeID:  replacement,
			PartyID: party.ID(replacement.String()),
			// The bond is verified during the reshare, not asserted here.
			Active:   true,
			JoinedAt: time.Now(),
		}
	}
	vm.signerSet.renumber()
	vm.signerSet.CurrentEpoch++

	reshareSession := fmt.Sprintf("reshare-epoch-%d-%s", vm.signerSet.CurrentEpoch, time.Now().Format("20060102150405"))

	vm.logInfo("bridgevm: signer removed, reshare triggered",
		log.Stringer("removedNodeID", nodeID),
		log.Stringer("replacementNodeID", replacement),
		log.String("replacementSource", replacementSource),
		log.Uint64("newEpoch", vm.signerSet.CurrentEpoch),
		log.Int("activeSigners", len(vm.signerSet.Signers)),
		log.String("reshareSession", reshareSession),
	)

	// Trigger the reshare on M-Chain (LP-134) over warp. A failure here is
	// retryable and does not undo the removal: the signer is out either way.
	if err := vm.triggerReshareProtocol(reshareSession, nodeID, replacement); err != nil {
		vm.logWarn("bridgevm: reshare protocol not triggered",
			log.String("reshareSession", reshareSession),
			log.String("error", err.Error()),
		)
	}

	result := &SignerReplacementResult{
		Success:       true,
		RemovedNodeID: nodeID.String(),
		NewEpoch:      vm.signerSet.CurrentEpoch,
		ActiveSigners: len(vm.signerSet.Signers),
		Threshold:     vm.signerSet.ThresholdT,
		Message:       "signer removed, reshare initiated",
	}
	if replacement != ids.EmptyNodeID {
		result.ReplacementNodeID = replacement.String()
		result.ReshareSession = reshareSession
		result.Message = fmt.Sprintf("signer replaced from %s, reshare initiated", replacementSource)
	}
	return result, nil
}

// HasSigner checks if a node ID is in the active signer set
func (vm *VM) HasSigner(nodeID ids.NodeID) bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	for _, signer := range vm.signerSet.Signers {
		if signer.NodeID == nodeID {
			return true
		}
	}
	return false
}

// triggerReshareProtocol sends a cross-chain request to M-Chain to initiate the
// MPC key reshare protocol. Called when a signer is replaced; the caller holds
// vm.mu.
func (vm *VM) triggerReshareProtocol(sessionID string, removedNodeID ids.NodeID, newNodeID ids.NodeID) error {
	if vm.rt == nil || vm.rt.WarpSigner == nil || vm.rt.Sender == nil {
		// Not a node with warp plumbing (a unit test, or a node that does not
		// relay). Nothing to send, and nothing wrong.
		return nil
	}

	oldPartyIDs := make([]party.ID, 0, len(vm.signerSet.Signers))
	newPartyIDs := make([]party.ID, 0, len(vm.signerSet.Signers))
	for _, signer := range vm.signerSet.Signers {
		if signer.NodeID != removedNodeID && signer.NodeID != newNodeID {
			oldPartyIDs = append(oldPartyIDs, signer.PartyID)
		}
		newPartyIDs = append(newPartyIDs, signer.PartyID)
	}

	requestBytes, err := json.Marshal(&CrossChainMPCRequest{
		Type:          MPCRequestReshare,
		SessionID:     sessionID,
		Epoch:         vm.signerSet.CurrentEpoch,
		OldPartyIDs:   oldPartyIDs,
		NewPartyIDs:   newPartyIDs,
		Threshold:     vm.signerSet.ThresholdT,
		SourceChainID: vm.rt.ChainID[:],
		Timestamp:     time.Now().Unix(),
	})
	if err != nil {
		return fmt.Errorf("bridgevm: marshal MPC request: %w", err)
	}

	// Build, sign, and wrap the reshare request as a single-signer Warp
	// envelope. The node signs with its BLS key over the Beam domain; the
	// receiving M-Chain nodes aggregate and verify the signature against
	// the canonical validator set. warpmsg.BuildSigned is the one place that
	// performs this build→sign→wrap sequence.
	env, err := warpmsg.BuildSigned(vm.rt.WarpSigner, vm.rt.NetworkID, vm.rt.ChainID, requestBytes)
	if err != nil {
		return fmt.Errorf("bridgevm: build signed warp message: %w", err)
	}
	msgBytes, err := env.Bytes()
	if err != nil {
		return fmt.Errorf("bridgevm: encode warp envelope: %w", err)
	}

	if err := vm.rt.Sender.SendGossip(context.Background(), warp.SendConfig{
		Validators: len(vm.signerSet.Signers),
	}, msgBytes); err != nil {
		return fmt.Errorf("bridgevm: broadcast reshare request: %w", err)
	}

	vm.logInfo("bridgevm: reshare protocol triggered",
		log.String("sessionID", sessionID),
		log.Uint64("epoch", vm.signerSet.CurrentEpoch),
		log.Int("oldParties", len(oldPartyIDs)),
		log.Int("newParties", len(newPartyIDs)),
		log.Int("threshold", vm.signerSet.ThresholdT),
	)
	return nil
}

// SlashSignerInput is the input for slashing a bridge signer
type SlashSignerInput struct {
	NodeID       ids.NodeID `json:"nodeId"`
	Reason       string     `json:"reason"`
	SlashPercent int        `json:"slashPercent"` // Percentage of bond to slash (1-100)
	Evidence     []byte     `json:"evidence"`     // Proof of misbehavior
}

// SlashSignerResult is the result of slashing a bridge signer
type SlashSignerResult struct {
	Success         bool   `json:"success"`
	NodeID          string `json:"nodeId"`
	SlashedAmount   uint64 `json:"slashedAmount"`
	RemainingBond   uint64 `json:"remainingBond"`
	TotalSlashCount int    `json:"totalSlashCount"`
	RemovedFromSet  bool   `json:"removedFromSet"`
	Message         string `json:"message"`
}

// SlashSigner slashes a misbehaving bridge signer's bond. The bond is NOT
// stake — it is a slashable deposit that can be partially or fully seized.
func (vm *VM) SlashSigner(input *SlashSignerInput) (*SlashSignerResult, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if input.SlashPercent < 1 || input.SlashPercent > 100 {
		return nil, errors.New("bridgevm: slash percent must be between 1 and 100")
	}

	var signer *SignerInfo
	signerIndex := -1
	for i, s := range vm.signerSet.Signers {
		if s.NodeID == input.NodeID {
			signer, signerIndex = s, i
			break
		}
	}
	if signer == nil {
		return &SlashSignerResult{
			Success: false,
			NodeID:  input.NodeID.String(),
			Message: "signer not found in active set",
		}, nil
	}

	slashAmount := (signer.BondAmount * uint64(input.SlashPercent)) / 100
	remainingBond := signer.BondAmount - slashAmount

	signer.BondAmount = remainingBond
	signer.Slashed = true
	signer.SlashCount++

	vm.logWarn("bridgevm: signer slashed",
		log.Stringer("nodeID", input.NodeID),
		log.String("reason", input.Reason),
		log.Int("slashPercent", input.SlashPercent),
		log.Uint64("slashedAmount", slashAmount),
		log.Uint64("remainingBond", remainingBond),
		log.Int("slashCount", signer.SlashCount),
	)

	result := &SlashSignerResult{
		Success:         true,
		NodeID:          input.NodeID.String(),
		SlashedAmount:   slashAmount,
		RemainingBond:   remainingBond,
		TotalSlashCount: signer.SlashCount,
		Message:         fmt.Sprintf("slashed %d%% of bond (%d)", input.SlashPercent, slashAmount),
	}

	// A signer whose bond no longer meets what the chain requires is not a
	// signer. The requirement is read from the same declaration registration
	// applies, so the two cannot drift apart.
	if remainingBond < vm.config.RequireValidatorBond {
		vm.signerSet.Signers = append(vm.signerSet.Signers[:signerIndex], vm.signerSet.Signers[signerIndex+1:]...)
		vm.signerSet.renumber()
		vm.signerSet.CurrentEpoch++

		result.RemovedFromSet = true
		result.Message = fmt.Sprintf("slashed %d%% of bond, signer removed (bond below the required minimum)", input.SlashPercent)

		vm.logWarn("bridgevm: signer removed, bond below the required minimum",
			log.Stringer("nodeID", input.NodeID),
			log.Uint64("remainingBond", remainingBond),
			log.Uint64("newEpoch", vm.signerSet.CurrentEpoch),
		)
	}

	return result, nil
}
