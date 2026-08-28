// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package mpcvm implements the shared threshold VM substrate — a LIBRARY,
// not a chain — consumed by M-Chain (MPC: CGGMP21/FROST/Pulsar-general threshold
// signing for bridge custody of external wallets, LP-7100) and F-Chain (FHE:
// TFHE compute / threshold decrypt, LP-8200). Per LP-134 / LP-7050 there is NO
// T-Chain and NO teleportvm; teleport IS bridgevm (B-Chain, LP-6000). Any live
// identifier still naming "T-Chain" or "ThresholdVM-as-a-chain" is stale.
// See ../README.md.
package mpcvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/constants"
	luxcrypto "github.com/luxfi/crypto"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/version"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/threshold/pkg/quorum"
	vmcore "github.com/luxfi/vm"
	vmchain "github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"
)

// maxStagedCeremonies bounds the queue of completed ceremonies waiting for a
// block. Staging is driven by ceremonies this node took part in, so the bound
// is generous, but a queue with no bound at all is whatever a long outage makes
// it.
const maxStagedCeremonies = 4096

var (
	_ vmchain.ChainVM = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	// Errors this VM owns. Everything about a KEY (unknown, already registered,
	// share not held) is state.go's vocabulary and is not restated here: two
	// spellings of "no such key" is one spelling too many.
	ErrInvalidThreshold  = errors.New("mpcvm: invalid threshold configuration")
	ErrUnauthorizedChain = errors.New("mpcvm: unauthorized chain")
	ErrQuotaExceeded     = errors.New("mpcvm: signing quota exceeded")
)

// ThresholdConfig contains VM configuration.
type ThresholdConfig struct {
	// Policy is the default signing policy for keys created on this chain,
	// written the way operators say it: "7-of-10" — seven of ten parties must
	// cooperate to produce one signature.
	//
	// It is deliberately NOT a bare number. A field called `threshold: 7` is
	// read as the signer count by operators and as the polynomial degree by
	// every threshold library, and those differ by one; a config that meant
	// 7-of-10 and was read as a degree produces an 8-of-10 key, silently. The
	// operator form cannot be misread, and the degree is derived from it at one
	// place (quorum.Policy.Degree) at the keygen boundary.
	Policy quorum.Policy `json:"policy"`

	// Session Configuration
	SessionTimeout      time.Duration `json:"sessionTimeout"`      // Max wall-clock for one ceremony
	MaxActiveSessions   int           `json:"maxActiveSessions"`   // Max concurrent ceremonies
	MaxSessionsPerChain int           `json:"maxSessionsPerChain"` // Max concurrent ceremonies per requesting chain
	MaxOpsPerBlock      int           `json:"maxOpsPerBlock"`      // Max operations in one block

	// Quota Configuration (daily limits)
	DailySigningQuota map[string]uint64 `json:"dailySigningQuota"` // ChainID -> daily signing limit

	// Authorized Chains that can request MPC services
	AuthorizedChains map[string]*ChainPermissions `json:"authorizedChains"`

	// Key Management
	KeyRotationPeriod time.Duration `json:"keyRotationPeriod"` // How often to rotate keys
	MaxKeyAge         time.Duration `json:"maxKeyAge"`         // Maximum age of a key before forced rotation
}

// ChainPermissions defines what a chain can do with MPC services
type ChainPermissions struct {
	ChainID           string   `json:"chainId"`
	ChainName         string   `json:"chainName"`
	CanSign           bool     `json:"canSign"`           // Can request signatures
	CanKeygen         bool     `json:"canKeygen"`         // Can request new key generation
	CanReshare        bool     `json:"canReshare"`        // Can request key resharing
	AllowedKeyTypes   []string `json:"allowedKeyTypes"`   // secp256k1, ed25519, etc.
	MaxSigningSize    int      `json:"maxSigningSize"`    // Max message size to sign
	RequirePreHash    bool     `json:"requirePreHash"`    // Require pre-hashed messages
	DailySigningLimit uint64   `json:"dailySigningLimit"` // Override global quota
}

// VM implements the Threshold VM for MPC-as-a-service
type VM struct {
	rt       *runtime.Runtime
	db       database.Database
	config   ThresholdConfig
	toEngine chan<- vmcore.Message
	log      log.Logger

	// protocolExecutor drives one threshold protocol to completion over a
	// router. It is the only part of this VM that knows the threshold library
	// exists; everything above it speaks in ceremonies.
	protocolExecutor *ProtocolExecutor

	// Cross-validator MPC transport.
	//   sender           — the node's canonical warp sender (block.Init.Sender);
	//                      nil on a node with no p2p (single-process dev/test).
	//   sessionRouters   — per-ceremony gossip routers, keyed by ceremony id, so
	//                      the Gossip handler can demultiplex an incoming envelope
	//                      to the ceremony it belongs to.
	//   pendingBySession — envelopes that arrived before our own router for that
	//                      ceremony was registered (the peer started the round a
	//                      hair before us); drained into the router on register so
	//                      no round-one broadcast is ever dropped. Bounded.
	sender           warp.Sender
	routerMu         sync.Mutex
	sessionRouters   map[string]*gossipRouter
	pendingBySession map[string][]*protocol.Message

	// Identity within the MPC committee. party.ID is the NodeID string, so the
	// committee and the peer set are the same value in two spellings, with no
	// side table to drift.
	partyID party.ID
	netID   ids.ID     // network whose validator set forms the committee
	pool    *pool.Pool // worker pool for MPC operations

	// chain is the durable state, the blocks in flight and the tip, under the
	// one lock the rest of the VM shares. State writes through its view, so a
	// key registration and the block that made it land together or not at all.
	chain        *chain.Store[*Block]
	genesisBlock *Block

	// state is the persisted, replicated chain state: the custody-key registry,
	// the ceremony log and the state root. It is the authority on what M-Chain
	// knows — there is no second in-memory copy that could disagree with it or
	// vanish on restart.
	state *State

	// shares is this node's secret key material, keyed by key id. Loaded from
	// node-private state at Initialize. NOT replicated and NOT in the state
	// root; another validator legitimately holds different bytes.
	shares map[string]*heldShare

	// Completed ceremonies awaiting inclusion in a block, in staging order.
	// Every participant stages the same operations, so whichever node proposes
	// produces a block the others can verify. LOCK ORDER: the chain's lock,
	// then the pool's.
	staged *chain.Pool[*Operation, string]

	// localMesh is the in-process ceremony transport used when the VM has no
	// p2p sender (single-process dev and tests). Nil on a networked node.
	localMesh *localMesh

	// Quota Tracking
	dailySigningCount map[string]uint64 // ChainID -> count today
	quotaResetTime    time.Time         // When to reset quotas

	// Network Stats
	stats *vmStats

	// Fee policy. M-Chain is service-only (committee-driven, no
	// user mempool) so this is the NoUserTxPolicy sentinel.
	feePolicy fee.Policy

	// mu guards State and the VM's own maps. State is deliberately not safe for
	// concurrent use — a state machine with its own locking invites callers to
	// interleave reads and writes across a transition and observe a half-applied
	// block — so this is the lock that stands in for it.
	//
	// LOCK ORDER, without exception: the chain's lock, then this one. Accept
	// holds the chain's and reaches State inside it, so any path holding this
	// one while resolving a block would deadlock. Verify resolves its parent
	// before taking this lock for that reason.
	mu sync.RWMutex
}

// vmStats counts what this node actually did. Every field here is incremented
// at the moment the thing happens; a counter that is only ever reported and
// never written is a number that reads as evidence and is not.
type vmStats struct {
	TotalSignatures   uint64
	TotalKeygens      uint64
	SignaturesByChain map[string]uint64
	mu                sync.RWMutex
}

// Initialize implements the chain.ChainVM interface
func (vm *VM) Initialize(
	ctx context.Context,
	init vmcore.Init,
) error {
	vm.rt = init.Runtime
	vm.db = init.DB
	vm.toEngine = init.ToEngine
	vm.sender = init.Sender
	// Use init.Log if provided, otherwise fallback to Runtime.Log
	if init.Log != nil {
		vm.log = init.Log
	} else if init.Runtime != nil {
		if logger, ok := init.Runtime.Log.(log.Logger); ok {
			vm.log = logger
		}
	}

	// Initialize maps
	vm.shares = make(map[string]*heldShare)
	vm.staged = chain.NewPool(maxStagedCeremonies,
		func(op *Operation) string { return op.CeremonyID })
	vm.sessionRouters = make(map[string]*gossipRouter)
	vm.pendingBySession = make(map[string][]*protocol.Message)
	vm.dailySigningCount = make(map[string]uint64)
	vm.quotaResetTime = time.Now().Add(24 * time.Hour)
	vm.netID = constants.PrimaryNetworkID
	vm.stats = &vmStats{
		SignaturesByChain: make(map[string]uint64),
	}

	// Pin fee policy. M-Chain is service-only (committee-driven, no
	// user mempool) so attach the NoUserTxPolicy sentinel.
	// fee.Validate passes for the sentinel even with zero MinTxFee.
	vm.feePolicy = newFeePolicy()
	if err := fee.Validate(vm.feePolicy); err != nil {
		return fmt.Errorf("mpcvm: fee policy: %w", err)
	}

	// Parse configuration
	if err := vm.parseConfig(init.Config); err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// Initialize party ID from node ID
	vm.partyID = party.ID(vm.rt.NodeID.String())

	// Create worker pool for MPC operations
	vm.pool = pool.NewPool(16) // 16 workers for parallel MPC

	// Initialize protocol executor for handling protocol execution with proper timeouts
	vm.protocolExecutor = NewProtocolExecutor(vm.pool, vm.log)

	// Parse genesis - use JSON for simple genesis configuration
	genesis := &Genesis{}
	if len(init.Genesis) > 0 {
		if err := json.Unmarshal(init.Genesis, genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}
	// A genesis policy overrides the config default, so the chain's quorum is
	// fixed by the thing every validator agrees on rather than by each node's
	// local config file.
	if genesis.Policy.Valid() {
		vm.config.Policy = genesis.Policy
	}

	// Open persisted state, resuming whatever this node already knows. State
	// writes through the chain's view, so a key registration and the block that
	// made it commit together or not at all.
	vm.chain = chain.New[*Block](vm.db, vm.reloadRoot)
	state, err := NewState(vm.chain.View(), vm.rt.ChainID)
	if err != nil {
		return err
	}
	vm.state = state

	// Resume from the accepted tip, or install genesis on a fresh database.
	// This is the difference between a chain and a cache: a node that restarts
	// comes back at the height it left, not at zero. Recomputing genesis
	// unconditionally would discard every accepted block and re-run history
	// from an empty registry.
	root := vm.state.Root()
	genesisBlock := &Block{
		BlockHeight:    0,
		BlockTimestamp: genesis.Timestamp,
		ParentID_:      ids.Empty,
		StateRoot:      root,
		vm:             vm,
	}
	genesisBlock.ID_ = genesisBlock.computeID()
	vm.genesisBlock = genesisBlock

	at, fresh, err := vm.chain.Open(genesisBlock, vm.parseBlock)
	if err != nil {
		return fmt.Errorf("mpcvm: open chain state: %w", err)
	}
	if fresh {
		// NewState seeded the genesis root through the view; commit it, so a
		// node that accepts no block still comes back to the same root.
		if err := vm.chain.Seed(func(database.Database) error { return nil }); err != nil {
			return err
		}
		vm.log.Info("M-Chain genesis installed",
			log.Stringer("blockID", genesisBlock.ID()),
			log.String("stateRoot", fmt.Sprintf("%x", root[:8])),
		)
	} else {
		vm.log.Info("M-Chain resumed",
			log.Stringer("tip", at.ID()),
			log.Uint64("height", at.Height()),
			log.String("stateRoot", fmt.Sprintf("%x", root[:8])),
		)
	}

	// Load this node's own key shares. Without them a restarted validator is a
	// registry reader that cannot sign — it would still be counted as a
	// committee member while being unable to contribute a partial signature.
	if err := vm.loadShares(); err != nil {
		return fmt.Errorf("mpcvm: load key shares: %w", err)
	}

	bound, unbound := 0, make([]string, 0, len(vm.config.AuthorizedChains))
	for name, p := range vm.config.AuthorizedChains {
		// A chainId that is not a chain id binds to nothing. The stock entries carry
		// labels ("B-Chain"), which never equal a node's base58 chain id, so counting
		// them as bound reported five authorized chains on a node where none were —
		// the exact reading this warning exists to prevent.
		if p != nil && p.ChainID != "" {
			if _, err := ids.FromString(p.ChainID); err == nil {
				bound++
				continue
			}
		}
		unbound = append(unbound, name)
	}
	sort.Strings(unbound)

	vm.log.Info("M-Chain initialized",
		log.String("policy", vm.config.Policy.String()),
		log.String("party", string(vm.partyID)),
		log.Int("sharesHeld", len(vm.shares)),
		log.Int("authorizedChains", bound),
	)
	if len(unbound) > 0 {
		// Say it plainly. A permission entry names a chain by label, and a label
		// is not an identity — until an operator sets chainId, the entry grants
		// custody to nobody. Silence here would read as "custody is configured"
		// right up until the first release fails.
		vm.log.Warn("custody entries bind to no chain id — set chainId to a real chain id on each to grant it",
			log.Strings("chains", unbound),
		)
	}

	return nil
}

// loadShares repopulates this node's secret shares from node-private state for
// every custody key it participates in.
func (vm *VM) loadShares() error {
	keys, err := vm.state.Keys()
	if err != nil {
		return err
	}
	for _, rec := range keys {
		raw, err := vm.state.GetShare(rec.KeyID)
		if errors.Is(err, ErrShareNotHeld) {
			continue // not a participant in this key; normal
		}
		if err != nil {
			return err
		}
		share, err := parseHeldShare(rec.Kind, raw)
		if err != nil {
			return fmt.Errorf("mpcvm: share for %s: %w", rec.KeyID, err)
		}
		// A share that does not match the registry it is filed under is a
		// corrupted store, not a recoverable state: signing with it would
		// produce signatures that fail against the registered group key.
		pub, degree, err := share.groupKeyAndDegree()
		if err != nil {
			return err
		}
		if string(pub) != string(rec.GroupPublicKey) {
			return fmt.Errorf("mpcvm: stored share for %s belongs to a different group key", rec.KeyID)
		}
		if degree != rec.Degree() {
			return fmt.Errorf("mpcvm: stored share for %s has degree %d, registry says policy %s (degree %d)",
				rec.KeyID, degree, rec.Policy, rec.Degree())
		}
		vm.shares[rec.KeyID] = share
	}
	return nil
}

func (vm *VM) parseConfig(configBytes []byte) error {
	if len(configBytes) == 0 {
		// Default configuration
		vm.config = ThresholdConfig{
			// 3-of-5. Two seats no longer reach a quorum, which matters because
			// seats are held by validators and validator entry is permissionless:
			// under 2-of-3 an adversary that got two seats held a quorum of every
			// key on the chain and could sign locally, off-chain, with nothing
			// on-chain to observe. At 3-of-5 it must hold a majority of the custody
			// set, and seats are allocated by stake (custodySet), so that costs
			// what attacking consensus costs.
			//
			// Degree 2: two parties may be corrupt or offline. 2K > N holds, so the
			// quorum is unique — two disjoint quorums cannot both sign.
			Policy:              quorum.MustNew(3, 5),
			SessionTimeout:      5 * time.Minute,
			MaxActiveSessions:   100,
			MaxSessionsPerChain: 10,
			MaxOpsPerBlock:      64,
			KeyRotationPeriod:   30 * 24 * time.Hour,
			MaxKeyAge:           90 * 24 * time.Hour,
			DailySigningQuota:   make(map[string]uint64),
			AuthorizedChains:    make(map[string]*ChainPermissions),
		}

		// Default authorized chains (all internal Lux chains)
		vm.config.AuthorizedChains["X-Chain"] = &ChainPermissions{
			ChainID:           "X-Chain",
			ChainName:         "UTXO Chain",
			CanSign:           true,
			CanKeygen:         false,
			CanReshare:        false,
			AllowedKeyTypes:   []string{"secp256k1"},
			MaxSigningSize:    256,
			DailySigningLimit: 10000,
		}
		vm.config.AuthorizedChains["B-Chain"] = &ChainPermissions{
			ChainID:           "B-Chain",
			ChainName:         "Bridge Chain",
			CanSign:           true,
			CanKeygen:         true,
			CanReshare:        true,
			AllowedKeyTypes:   []string{"secp256k1"},
			MaxSigningSize:    1024,
			DailySigningLimit: 100000,
		}
		vm.config.AuthorizedChains["C-Chain"] = &ChainPermissions{
			ChainID:           "C-Chain",
			ChainName:         "Contract Chain",
			CanSign:           true,
			CanKeygen:         false,
			CanReshare:        false,
			AllowedKeyTypes:   []string{"secp256k1"},
			MaxSigningSize:    256,
			DailySigningLimit: 50000,
		}
		vm.config.AuthorizedChains["P-Chain"] = &ChainPermissions{
			ChainID:           "P-Chain",
			ChainName:         "Platform Chain",
			CanSign:           true,
			CanKeygen:         true,
			CanReshare:        true,
			AllowedKeyTypes:   []string{"secp256k1", "bls"},
			MaxSigningSize:    512,
			DailySigningLimit: 10000,
		}
		vm.config.AuthorizedChains["Q-Chain"] = &ChainPermissions{
			ChainID:           "Q-Chain",
			ChainName:         "Quantum Chain",
			CanSign:           true,
			CanKeygen:         true,
			CanReshare:        true,
			AllowedKeyTypes:   []string{"secp256k1", "dilithium"},
			MaxSigningSize:    512,
			DailySigningLimit: 10000,
		}

		return nil
	}

	if err := json.Unmarshal(configBytes, &vm.config); err != nil {
		return err
	}

	// A policy that does not decode is a hard failure, not a default. Falling
	// back to a built-in quorum for a chain that holds bridged funds would mean
	// the operator's intent and the deployed key silently differ.
	if !vm.config.Policy.Valid() {
		return fmt.Errorf("%w: %q is not a deployable policy (want the form \"3-of-5\")",
			ErrInvalidThreshold, vm.config.Policy)
	}
	if vm.config.MaxOpsPerBlock <= 0 {
		vm.config.MaxOpsPerBlock = 64
	}
	return nil
}

// =============================================================================
// Custody API — the one way in
// =============================================================================
//
// Every entry point below delegates to the ceremony lifecycle in custody.go.
// There is no second path that reaches a key or a signature, and no in-memory
// session state beside the chain: a parallel copy of who holds what would be
// unreplicated, and two answers to that question is one too many.

// StartKeygen generates a custody key using the chain's default policy.
func (vm *VM) StartKeygen(ctx context.Context, keyID string, by Caller) (*Operation, error) {
	return vm.StartKeygenWithPolicy(ctx, keyID, vm.Policy(), by)
}

// StartKeygenWithPolicy generates a custody key under an explicit k-of-n policy.
//
// The policy is a quorum.Policy, not a pair of ints, so a caller cannot express
// the quorum ambiguously: "3-of-5" is the only spelling, and the polynomial
// degree is derived from it inside RunKeygen.
func (vm *VM) StartKeygenWithPolicy(ctx context.Context, keyID string, policy quorum.Policy, by Caller) (*Operation, error) {
	if by.perms == nil || !by.perms.CanKeygen {
		return nil, fmt.Errorf("%w: %s may not request key generation", ErrUnauthorizedChain, by.name)
	}
	requestedBy := by.name
	ctx, cancel := context.WithTimeout(ctx, vm.sessionTimeout())
	defer cancel()
	op, err := vm.runKeygen(ctx, keyID, policy, requestedBy)
	if err != nil {
		return nil, err
	}
	vm.stats.mu.Lock()
	vm.stats.TotalKeygens++
	vm.stats.mu.Unlock()
	return op, nil
}

// RequestSignature produces a threshold signature over messageHash with a
// registered custody key and stages it for the next block.
func (vm *VM) RequestSignature(ctx context.Context, by Caller, keyID string, messageHash []byte) (*Operation, error) {
	perms := by.perms
	if perms == nil || !perms.CanSign {
		return nil, fmt.Errorf("%w: %s may not request signatures", ErrUnauthorizedChain, by.name)
	}
	requestingChain := by.name
	if perms.MaxSigningSize > 0 && len(messageHash) > perms.MaxSigningSize {
		return nil, fmt.Errorf("message too large: %d > %d", len(messageHash), perms.MaxSigningSize)
	}

	vm.mu.Lock()
	vm.checkQuotaReset()
	limit := perms.DailySigningLimit
	if override := vm.config.DailySigningQuota[requestingChain]; override > 0 {
		limit = override
	}
	if limit > 0 && vm.dailySigningCount[requestingChain] >= limit {
		vm.mu.Unlock()
		return nil, ErrQuotaExceeded
	}
	vm.mu.Unlock()

	ctx, cancel := context.WithTimeout(ctx, vm.sessionTimeout())
	defer cancel()
	op, err := vm.runSign(ctx, keyID, messageHash, requestingChain)
	if err != nil {
		return nil, err
	}

	vm.mu.Lock()
	vm.dailySigningCount[requestingChain]++
	vm.stats.mu.Lock()
	vm.stats.TotalSignatures++
	vm.stats.SignaturesByChain[requestingChain]++
	vm.stats.mu.Unlock()
	vm.mu.Unlock()
	return op, nil
}

// Policy returns the chain's default signing policy.
func (vm *VM) Policy() quorum.Policy {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.config.Policy
}

// Key returns a registered custody key's public record.
func (vm *VM) Key(keyID string) (*KeyRecord, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.state.GetKey(keyID)
}

// Keys returns every registered custody key.
func (vm *VM) Keys() ([]*KeyRecord, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.state.Keys()
}

// Ceremony returns a recorded ceremony — the durable, replicated evidence that
// a signature was produced, including the signature itself.
func (vm *VM) Ceremony(id string) (*CeremonyRecord, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.state.GetCeremony(id)
}

// Ceremonies returns the whole ceremony log.
func (vm *VM) Ceremonies() ([]*CeremonyRecord, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.state.Ceremonies()
}

// StateRoot returns the current state root — the value two validators compare
// to know whether they agree about custody.
func (vm *VM) StateRoot() [32]byte {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.state.Root()
}

// PublicKey returns a custody key's compressed group public key.
func (vm *VM) PublicKey(keyID string) ([]byte, error) {
	rec, err := vm.Key(keyID)
	if err != nil {
		return nil, err
	}
	return rec.GroupPublicKey, nil
}

// Address returns a custody key's external-chain address.
func (vm *VM) Address(keyID string) ([]byte, error) {
	rec, err := vm.Key(keyID)
	if err != nil {
		return nil, err
	}
	return rec.Address, nil
}

// permissions resolves a requesting chain's permissions.
func (vm *VM) permissions(chain string) (*ChainPermissions, bool) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	p, ok := vm.config.AuthorizedChains[chain]
	return p, ok
}

func (vm *VM) sessionTimeout() time.Duration {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	if vm.config.SessionTimeout <= 0 {
		return 5 * time.Minute
	}
	return vm.config.SessionTimeout
}

// checkQuotaReset rolls the daily signing counters over. Caller holds vm.mu.
func (vm *VM) checkQuotaReset() {
	if time.Now().Before(vm.quotaResetTime) {
		return
	}
	vm.dailySigningCount = make(map[string]uint64)
	vm.quotaResetTime = time.Now().Add(24 * time.Hour)
}

// BuildBlock implements the chain.ChainVM interface
func (vm *VM) BuildBlock(ctx context.Context) (vmchain.Block, error) {
	built, err := vm.chain.Propose(func(parent *Block) (*Block, error) {
		staged := vm.staged.Take(vm.config.MaxOpsPerBlock)
		if len(staged) == 0 {
			return nil, errors.New("mpcvm: no completed ceremonies to include")
		}

		// Only include operations that still verify against current state. A
		// ceremony can be staged and then invalidated by a block that landed first
		// (the same key registered, the same ceremony recorded); proposing it
		// anyway would build a block every peer rejects.
		vm.mu.RLock()
		defer vm.mu.RUnlock()

		root := vm.state.Root()
		pending := make(map[string]*KeyRecord, len(staged))
		operations := make([]*Operation, 0, len(staged))
		var invalid []*Operation
		for _, op := range staged {
			if err := vm.verifyOperation(op, pending); err != nil {
				vm.log.Debug("dropping staged ceremony",
					log.String("ceremony", op.CeremonyID),
					log.String("reason", err.Error()),
				)
				invalid = append(invalid, op)
				continue
			}
			if op.Type == OpTypeKeygen {
				pending[op.Key.KeyID] = op.Key
			}
			operations = append(operations, op)
			root = advance(root, op.digest())
		}
		vm.staged.Drop(invalid)
		if len(operations) == 0 {
			return nil, errors.New("mpcvm: no completed ceremonies to include")
		}

		// The block timestamp never precedes its parent's; Verify enforces the
		// same bound, so a clock that ran backwards must not produce an
		// unverifiable block on the proposer's own machine.
		ts := time.Now().Unix()
		if ts < parent.BlockTimestamp {
			ts = parent.BlockTimestamp
		}

		blk := &Block{
			ParentID_:      parent.ID(),
			BlockHeight:    parent.Height() + 1,
			BlockTimestamp: ts,
			StateRoot:      root,
			Operations:     operations,
			vm:             vm,
		}
		blk.ID_ = blk.computeID()

		vm.log.Info("built M-Chain block",
			log.Stringer("blockID", blk.ID()),
			log.Uint64("height", blk.BlockHeight),
			log.Int("operations", len(operations)),
			log.String("stateRoot", fmt.Sprintf("%x", root[:8])),
		)
		return blk, nil
	})
	if err != nil {
		return nil, err
	}
	return built, nil
}

// GetBlock implements the chain.ChainVM interface
func (vm *VM) GetBlock(ctx context.Context, id ids.ID) (vmchain.Block, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.loadBlock(id)
}

// ParseBlock implements the chain.ChainVM interface
func (vm *VM) ParseBlock(ctx context.Context, bytes []byte) (vmchain.Block, error) {
	return vm.parseBlock(bytes)
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

// reloadRoot puts the committed state root back after a block's writes have
// been discarded, so the root this node reports is one that is on disk. It runs
// inside Accept, under the chain's lock, and takes the VM's in that order.
func (vm *VM) reloadRoot() error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	return vm.state.ReadRoot()
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

// CreateHandlers implements the common.VM interface
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	handlers := map[string]http.Handler{
		"/rpc":    vm.createRPCHandler(),
		"/health": http.HandlerFunc(vm.handleHealth),
	}
	return handlers, nil
}

// HealthCheck implements the common.VM interface.
//
// Health is "can this node read its own state", not "does this node hold a
// key". M-Chain is a custody REGISTRY first and a signer second: a validator
// that holds no share still serves reads and still verifies every block, so
// gating health on key material would take healthy nodes out of rotation for
// doing their job correctly. What a share-less node cannot do — contribute a
// partial signature — is visible in sharesHeld.
func (vm *VM) HealthCheck(ctx context.Context) (vmchain.HealthResult, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	keys, err := vm.state.Keys()
	if err != nil {
		return vmchain.HealthResult{}, fmt.Errorf("mpcvm: read custody registry: %w", err)
	}
	root := vm.state.Root()
	return vmchain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"custodyKeys":      fmt.Sprintf("%d", len(keys)),
			"sharesHeld":       fmt.Sprintf("%d", len(vm.shares)),
			"stagedCeremonies": fmt.Sprintf("%d", vm.staged.Len()),
			"stateRoot":        hex.EncodeToString(root[:]),
		},
	}, nil
}

// Shutdown implements the common.VM interface.
//
// Nothing is flushed here. Every durable fact — registered keys, recorded
// ceremonies, key shares, the accepted tip — is written at the moment it
// becomes true, not at shutdown. A VM that persists its registry only on a
// clean shutdown loses it to any crash, kill or power cut, which for a custody
// chain means losing the record of who holds the funds.
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()
	if vm.pool != nil {
		vm.pool.TearDown()
	}
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
	// Handle MPC protocol messages
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

// Gossip implements the common.VM interface. It is the single receive path for
// cross-validator MPC: every ceremony message (broadcast or directed) arrives
// here as app-gossip, is decoded to (sessionID, protocol.Message) and handed to
// the ceremony's router. Messages that arrive before our own router for that
// ceremony is registered are buffered and drained on register, so no round-one
// broadcast is lost to a start-order race.
func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error {
	sessionID, ceremonyMsg, err := unmarshalEnvelope(msg)
	if err != nil {
		// Not an MPC ceremony envelope (or corrupt) — ignore, never fault
		// consensus on a peer's malformed gossip.
		return nil
	}
	vm.deliverCeremonyMessage(sessionID, ceremonyMsg)
	return nil
}

// Version implements the common.VM interface
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// CrossChainRequest implements the common.VM interface. This is how another
// chain (B-Chain for bridge custody) asks M-Chain for a ceremony.
//
// The ceremony runs to completion here and its result is staged for the next
// block; the requester reads the outcome from the ceremony log, which is
// replicated, rather than from a reply that only this node would remember.
func (vm *VM) CrossChainRequest(ctx context.Context, chainID ids.ID, requestID uint32, deadline time.Time, request []byte) error {
	var req CrossChainMPCRequest
	if err := parseCrossChainMPCRequest(request, &req); err != nil {
		return err
	}

	// Authorize from the chain id the TRANSPORT authenticated, never from
	// req.RequestingChain. That field is written by the sender about itself, so
	// reading it here would let any peer that can reach this method claim any
	// chain's custody rights; it survives only as attribution on the recorded
	// operation, where it is set from the authenticated name below.
	by, err := vm.caller(chainID)
	if err != nil {
		return err
	}

	switch req.Type {
	case "sign":
		_, err := vm.RequestSignature(ctx, by, req.KeyID, req.MessageHash)
		return err
	case "keygen":
		_, err := vm.StartKeygen(ctx, req.KeyID, by)
		return err
	default:
		return fmt.Errorf("mpcvm: unknown cross-chain request type %q", req.Type)
	}
}

// CrossChainResponse implements the common.VM interface
func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	return nil
}

// CrossChainRequestFailed implements the common.VM interface
func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// GetBlockIDAtHeight implements the chain.HeightIndexedChainVM interface. The
// index is persisted, so it survives a restart — a purely in-memory height map
// answers "not found" for every accepted block after a reboot.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return vm.chain.IDAtHeight(height)
}

// SetState implements the common.VM interface
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// NewHTTPHandler returns HTTP handlers for the VM
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	return vm.createRPCHandler(), nil
}

// WaitForEvent blocks until this VM has work for the engine.
//
// M-Chain is demand-driven: it builds a block only when a ceremony has
// completed and staged an operation. Returning eagerly would spin the engine
// (the flood loop in chains/manager.go); blocking forever would mean a
// completed ceremony never reaches a block unless some other chain happened to
// wake the builder.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.staged.Wait(ctx)
}

// Helper methods

// loadBlock reads a block in flight or one read back from committed state, so
// an accepted ancestor is found after a restart rather than only while it
// happens to be in memory.
func (vm *VM) loadBlock(id ids.ID) (*Block, error) {
	if vm.genesisBlock != nil && id == vm.genesisBlock.ID() {
		return vm.genesisBlock, nil
	}
	return vm.chain.Block(id, vm.parseBlock)
}

// handleHealth serves the same result HealthCheck reports to the engine. One
// source of truth: an HTTP probe that computed health separately could say
// "healthy" while the engine was being told otherwise.
func (vm *VM) handleHealth(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	health, err := vm.HealthCheck(r.Context())
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
		return
	}
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(struct {
		Healthy bool              `json:"healthy"`
		Details map[string]string `json:"details"`
	}{health.Healthy, health.Details})
}

// CrossChainMPCRequest is the request format for cross-chain MPC operations
type CrossChainMPCRequest struct {
	Type            string `json:"type"` // sign, keygen, reshare
	RequestingChain string `json:"requestingChain"`
	KeyID           string `json:"keyId"`
	KeyType         string `json:"keyType,omitempty"`
	MessageHash     []byte `json:"messageHash,omitempty"`
	MessageType     string `json:"messageType,omitempty"`
}

// Genesis represents the genesis state.
//
// Policy is here rather than only in each node's config file because the
// chain's quorum must be the same value on every validator: a policy that
// lives per-node can differ per-node, and the first symptom is a key whose
// declared quorum is not the quorum it was generated with. An absent or
// malformed policy leaves the config default in place (see Initialize).
type Genesis struct {
	Timestamp int64         `json:"timestamp"`
	Policy    quorum.Policy `json:"policy,omitempty"`
}

// Helper functions

// publicKeyToAddress derives the 20-byte external-chain custody address of a
// secp256k1 group key: keccak256(uncompressed X‖Y)[12:].
//
// This MUST be Keccak-256, not SHA-256. It is the address that actually holds
// bridged funds on Ethereum and every EVM chain, and it is what an external
// `ecrecover` produces from a signature by this key. Deriving it with SHA-256
// yields an address that no external chain associates with the group key: funds
// sent to it are unspendable, and a withdrawal signed by the group key appears
// to come from a different account than the one M-Chain published. There is no
// recovery from publishing the wrong custody address.
//
// Returns nil for an unparseable key; callers must treat nil as a hard failure
// rather than registering an empty address.
func publicKeyToAddress(pubKey []byte) []byte {
	uncompressed := uncompressedXY(pubKey)
	if uncompressed == nil {
		return nil
	}
	return luxcrypto.Keccak256(uncompressed)[12:]
}

// uncompressedXY normalises any accepted secp256k1 public-key encoding to the
// bare 64-byte X‖Y form that address derivation hashes.
func uncompressedXY(pubKey []byte) []byte {
	if x, y := secp256k1.DecompressPubkey(pubKey); x != nil && y != nil {
		xb, yb := x.Bytes(), y.Bytes()
		out := make([]byte, 64)
		copy(out[32-len(xb):32], xb)
		copy(out[64-len(yb):64], yb)
		return out
	}
	switch len(pubKey) {
	case 65:
		if pubKey[0] != 0x04 {
			return nil
		}
		return pubKey[1:]
	case 64:
		return pubKey
	default:
		return nil
	}
}

// =============================================================================
// Session-Ready: Attestation Domains
// =============================================================================
// QuantumVM threshold attests to:
// - Oracle observation commitments (oracle/write, oracle/read)
// - Session completion (session/complete)
// - Epoch beacon signatures (epoch/beacon)
// Domain separators prevent cross-protocol replay attacks.

// AttestationDomain defines the domain for a threshold attestation
type AttestationDomain string

const (
	// DomainOracleWrite attests to external write request commitments
	DomainOracleWrite AttestationDomain = "oracle/write"
	// DomainOracleRead attests to external read request commitments
	DomainOracleRead AttestationDomain = "oracle/read"
	// DomainSessionComplete attests to session completion (output hash + oracle obs + receipts root)
	DomainSessionComplete AttestationDomain = "session/complete"
	// DomainEpochBeacon attests to epoch beacon signatures for randomness
	DomainEpochBeacon AttestationDomain = "epoch/beacon"
)

// domainSeparators maps domains to their cryptographic separators
var domainSeparators = map[AttestationDomain][]byte{
	DomainOracleWrite:     []byte("LUX:QuantumAttest:oracle/write:v1"),
	DomainOracleRead:      []byte("LUX:QuantumAttest:oracle/read:v1"),
	DomainSessionComplete: []byte("LUX:QuantumAttest:session/complete:v1"),
	DomainEpochBeacon:     []byte("LUX:QuantumAttest:epoch/beacon:v1"),
}

// QuantumAttestation represents a threshold attestation over a commitment.
type QuantumAttestation struct {
	// Domain specifies what is being attested (oracle/write, session/complete, etc.)
	Domain AttestationDomain `json:"domain"`

	// AttestationID is a unique identifier for this attestation
	AttestationID [32]byte `json:"attestationId"`

	// SubjectID is the ID of what is being attested (request_id, session_id, epoch number)
	SubjectID [32]byte `json:"subjectId"`

	// CommitmentRoot is the Merkle root being attested
	CommitmentRoot [32]byte `json:"commitmentRoot"`

	// Epoch in which this attestation was created
	Epoch uint64 `json:"epoch"`

	// Timestamp when attestation was created
	Timestamp time.Time `json:"timestamp"`

	// KeyID of the custody key that signed.
	KeyID string `json:"keyId"`

	// CeremonyID is the ceremony that produced Signature — the primary key of
	// the replicated ceremony log, so an attestation handed to another chain
	// can be looked up and re-checked against M-Chain state.
	CeremonyID string `json:"ceremonyId"`

	// Policy is the key's quorum in operator form ("3-of-5"). It is what
	// VerifyAttestation checks Signers against; a bare threshold number would
	// be ambiguous between signer count and polynomial degree.
	Policy quorum.Policy `json:"policy"`

	// Signers are the parties that participated, canonically ordered.
	Signers []party.ID `json:"signers"`

	// Signature is the 65-byte r‖s‖v threshold signature over the attestation
	// payload — the same encoding every ceremony artifact uses.
	Signature []byte `json:"signature"`
}

// OracleCommitAttestation contains details for oracle commit attestations
type OracleCommitAttestation struct {
	RequestID   [32]byte `json:"requestId"`
	Kind        uint8    `json:"kind"` // 0 = write, 1 = read
	Root        [32]byte `json:"root"`
	RecordCount uint32   `json:"recordCount"`
}

// SessionCompleteAttestation contains details for session completion attestations
type SessionCompleteAttestation struct {
	SessionID    [32]byte `json:"sessionId"`
	OutputHash   [32]byte `json:"outputHash"`
	OracleRoot   [32]byte `json:"oracleRoot"`
	ReceiptsRoot [32]byte `json:"receiptsRoot"`
	StepCount    uint32   `json:"stepCount"`
}

// EpochBeaconAttestation contains details for epoch beacon attestations
type EpochBeaconAttestation struct {
	Epoch       uint64   `json:"epoch"`
	Randomness  [32]byte `json:"randomness"`
	PreviousRef [32]byte `json:"previousRef"`
}

// ComputeAttestationPayload computes the payload to be signed for an attestation
func ComputeAttestationPayload(domain AttestationDomain, subjectID, commitmentRoot [32]byte, epoch uint64) [32]byte {
	h := sha256.New()

	// Domain separator
	separator, ok := domainSeparators[domain]
	if !ok {
		separator = []byte("LUX:QuantumAttest:unknown:v1")
	}
	h.Write(separator)

	// Subject ID (request_id, session_id, etc.)
	h.Write(subjectID[:])

	// Commitment root being attested
	h.Write(commitmentRoot[:])

	// Epoch for temporal binding
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)
	h.Write(epochBytes[:])

	var result [32]byte
	copy(result[:], h.Sum(nil))
	return result
}

// attest is the ONE path from a domain-bound payload to an attestation: run
// the ceremony, then describe what it produced.
//
// There is no polling here and no "status" to interpret. RequestSignature
// returns when the ceremony has finished and the signature is in hand, so the
// three Attest* entry points below differ only in how they compute their
// subject and commitment — which is the only thing that actually differs
// between an oracle commit, a session completion and an epoch beacon.
func (vm *VM) attest(
	ctx context.Context,
	by Caller,
	keyID string,
	domain AttestationDomain,
	subjectID [32]byte,
	commitRoot [32]byte,
	epoch uint64,
) (*QuantumAttestation, error) {
	payload := ComputeAttestationPayload(domain, subjectID, commitRoot, epoch)

	op, err := vm.RequestSignature(ctx, by, keyID, payload[:])
	if err != nil {
		return nil, fmt.Errorf("mpcvm: attest %s: %w", domain, err)
	}
	rec, err := vm.Key(keyID)
	if err != nil {
		return nil, err
	}

	vm.log.Info("created attestation",
		log.String("domain", string(domain)),
		log.String("subject", hex.EncodeToString(subjectID[:])),
		log.Uint64("epoch", epoch),
		log.String("ceremony", op.CeremonyID),
	)
	return &QuantumAttestation{
		Domain: domain,
		// The id binds the payload to the ceremony that signed it, so two
		// attestations over the same payload by different quorums are
		// distinguishable.
		AttestationID:  sha256.Sum256(append(payload[:], op.CeremonyID...)),
		SubjectID:      subjectID,
		CommitmentRoot: commitRoot,
		Epoch:          epoch,
		Timestamp:      time.Now(),
		KeyID:          keyID,
		CeremonyID:     op.CeremonyID,
		Policy:         rec.Policy,
		Signers:        op.Signers,
		Signature:      op.Artifact,
	}, nil
}

// AttestOracleCommit creates a threshold attestation for an oracle commitment.
func (vm *VM) AttestOracleCommit(
	ctx context.Context,
	by Caller,
	keyID string,
	requestID [32]byte,
	kind uint8, // 0 = write, 1 = read
	commitRoot [32]byte,
	epoch uint64,
) (*QuantumAttestation, error) {
	domain := DomainOracleWrite
	if kind != 0 {
		domain = DomainOracleRead
	}
	return vm.attest(ctx, by, keyID, domain, requestID, commitRoot, epoch)
}

// AttestSessionComplete creates a threshold attestation for session completion.
func (vm *VM) AttestSessionComplete(
	ctx context.Context,
	by Caller,
	keyID string,
	sessionID [32]byte,
	outputHash [32]byte,
	oracleRoot [32]byte,
	receiptsRoot [32]byte,
	epoch uint64,
) (*QuantumAttestation, error) {
	h := sha256.New()
	h.Write(outputHash[:])
	h.Write(oracleRoot[:])
	h.Write(receiptsRoot[:])
	var commitRoot [32]byte
	copy(commitRoot[:], h.Sum(nil))

	return vm.attest(ctx, by, keyID, DomainSessionComplete, sessionID, commitRoot, epoch)
}

// AttestEpochBeacon creates a threshold attestation for epoch beacon randomness.
func (vm *VM) AttestEpochBeacon(
	ctx context.Context,
	by Caller,
	keyID string,
	epoch uint64,
	previousRef [32]byte,
) (*QuantumAttestation, error) {
	var epochBytes [8]byte
	binary.BigEndian.PutUint64(epochBytes[:], epoch)

	h := sha256.New()
	h.Write([]byte("LUX:EpochBeacon:"))
	h.Write(epochBytes[:])
	var subjectID [32]byte
	copy(subjectID[:], h.Sum(nil))

	// Chaining each beacon to its predecessor is what makes the sequence
	// unforgeable as a sequence rather than as isolated signatures.
	h2 := sha256.New()
	h2.Write(previousRef[:])
	h2.Write(epochBytes[:])
	var commitRoot [32]byte
	copy(commitRoot[:], h2.Sum(nil))

	return vm.attest(ctx, by, keyID, DomainEpochBeacon, subjectID, commitRoot, epoch)
}

// VerifyAttestation checks an attestation against this node's registry: the
// domain is one M-Chain issues, the quorum satisfies the key's policy, and the
// signature verifies under the registered group key over the recomputed
// payload.
//
// It uses the same verifyGroupSignature that block.go uses to admit a ceremony
// to state, so an attestation cannot pass here under a rule that a block would
// have rejected.
func (vm *VM) VerifyAttestation(a *QuantumAttestation) error {
	if a == nil {
		return errors.New("mpcvm: nil attestation")
	}
	if _, ok := domainSeparators[a.Domain]; !ok {
		return fmt.Errorf("mpcvm: unknown attestation domain %q", a.Domain)
	}
	// K signers, not K-1: a set the size of the polynomial degree cannot
	// produce a signature, so a claim that it did is a wrong-degree key.
	if len(a.Signers) < a.Policy.K {
		return fmt.Errorf("%w: %d signers for policy %s", ErrQuorumTooSmall, len(a.Signers), a.Policy)
	}
	pubKey, err := vm.PublicKey(a.KeyID)
	if err != nil {
		return err
	}
	payload := ComputeAttestationPayload(a.Domain, a.SubjectID, a.CommitmentRoot, a.Epoch)
	if err := verifyGroupSignature(pubKey, payload[:], a.Signature); err != nil {
		return fmt.Errorf("%w: %w", ErrBadArtifact, err)
	}
	return nil
}

// DetectEquivocation checks if two attestations represent equivocation (slashable)
// Two attestations are equivocating if they have the same domain, subject, and epoch
// but different commitment roots
func DetectEquivocation(a, b *QuantumAttestation) bool {
	if a == nil || b == nil {
		return false
	}

	// Must be same domain
	if a.Domain != b.Domain {
		return false
	}

	// Must be same subject
	if a.SubjectID != b.SubjectID {
		return false
	}

	// Must be same epoch
	if a.Epoch != b.Epoch {
		return false
	}

	// Equivocation if commitment roots differ
	return a.CommitmentRoot != b.CommitmentRoot
}
