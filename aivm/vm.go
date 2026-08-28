// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package aivm provides the AI Virtual Machine for the Lux network.
//
// AIVM is the AI compute coordination layer. It works on ANY Lux L1/L2
// (mainnet primary network, testnet, devnet, white-label chains) with
// NO trusted dealer, NO TEE requirement, and NO single point of trust.
//
// Verification model (per VerificationMode):
//
//   - ModeOptimistic (DEFAULT, public-BFT-safe): providers post results
//     with hash-commitment + bond; N-block challenge period; uncontested
//     results finalise; challenged results enter fraud-proof flow with
//     slashing of the losing side. No TEE assumption. Works on any
//     L1/L2 that has Pulsar/Corona for finality.
//
//   - ModeMultiPartyRedundant: M-of-N validators run the same inference
//     and consensus on the output hash. No single provider needs trust;
//     malicious providers diverge from the majority and are slashed.
//     Public-BFT-safe. Cost: M× compute per task.
//
//   - ModeTEEAttested: when a provider has SGX/SEV-SNP/TDX/nvtrust
//     available, the attestation is FOLDED INTO the trust score as
//     an accelerator (skip the challenge period for high-trust-score
//     providers). TEE never CHANGES the trust root — only reduces
//     latency-to-finality for already-bonded providers.
//
// The TEE path (luxfi/ai/pkg/attestation) is OPTIONAL across all modes.
// Setting RequireTEEAttestation=true is a deployment policy choice for
// permissioned/regulated deployments; the public-chain default is
// VerificationMode=ModeOptimistic + RequireTEEAttestation=false.
//
// Other features:
//   - Task submission and assignment (chain-agnostic)
//   - Mining rewards (paid in the host chain's native token)
//   - Optional anchoring to Q-Chain for cross-chain settlement
//     (controlled by HostChainID: when "primary", anchor to Q-Chain;
//     otherwise anchor to the host chain's own finality)
package aivm

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/luxfi/accel"
	"github.com/luxfi/database"
	"github.com/luxfi/database/versiondb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	"github.com/luxfi/timer/mockable"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"

	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/node/version"
	"github.com/luxfi/node/vms/types/fee"

	"github.com/luxfi/ai/pkg/aivm"
	"github.com/luxfi/ai/pkg/attestation"
)

var (
	_ chain.ChainVM = (*VM)(nil)
	_ vertex.DAGVM  = (*VM)(nil)

	Version = &version.Semantic{
		Major: 1,
		Minor: 0,
		Patch: 0,
	}

	ErrNotInitialized   = errors.New("vm not initialized")
	ErrInvalidTask      = errors.New("invalid task")
	ErrProviderNotFound = errors.New("provider not found")
)

// VerificationMode selects the AIVM result-verification strategy.
//
// Public chains MUST use ModeOptimistic or ModeMultiPartyRedundant —
// these are public-BFT-safe and do not require any single trusted
// party. ModeTEEAttested is permitted but the TEE is treated as
// acceleration, never as the trust root.
type VerificationMode uint8

const (
	// ModeOptimistic is the default for public chains.
	// Providers post results with bond. N-block challenge period.
	// Public-BFT-safe — anyone can submit a fraud proof.
	ModeOptimistic VerificationMode = 0

	// ModeMultiPartyRedundant has M-of-N providers run the same task;
	// consensus on the result hash. Divergent providers are slashed.
	// Public-BFT-safe — no single provider can corrupt the result.
	ModeMultiPartyRedundant VerificationMode = 1

	// ModeTEEAttested is OPT-IN. Providers with valid TEE attestation
	// can shortcut the challenge period. TEE never changes the trust
	// root; it accelerates settlement for high-trust providers.
	// Use only on permissioned/regulated deployments where TEE-vendor
	// trust is acceptable; not the default for public mainnet.
	ModeTEEAttested VerificationMode = 2
)

// Config contains AIVM configuration
type Config struct {
	// Network settings
	MaxProvidersPerNode int `json:"maxProvidersPerNode"`
	MaxTasksPerProvider int `json:"maxTasksPerProvider"`

	// HostChainID identifies which Lux L1/L2 this AIVM instance runs on.
	// "primary" = primary network (mainnet/testnet/devnet); anchor to
	// Q-Chain for cross-chain settlement. Any other value = white-label
	// L1/L2 (Hanzo, Zoo, Pars, Liquidity); anchor to the host chain's
	// own finality. AIVM is chain-agnostic — same code runs everywhere.
	HostChainID string `json:"hostChainID"`

	// VerificationMode selects the result-verification strategy.
	// Default: ModeOptimistic (public-BFT-safe).
	VerificationMode VerificationMode `json:"verificationMode"`

	// ChallengeWindowBlocks is the number of L1/L2 blocks during which
	// any party can submit a fraud proof against a posted result. Only
	// used by ModeOptimistic. Default 100 blocks (~5-10 minutes on
	// most Lux L1/L2 instances).
	ChallengeWindowBlocks uint64 `json:"challengeWindowBlocks"`

	// RedundancyFactor is M (signatures required) for
	// ModeMultiPartyRedundant. Total providers N is committed in the
	// task spec; M-of-N must produce the same result hash for
	// acceptance. Default 3-of-5.
	RedundancyFactor int `json:"redundancyFactor"`

	// MinProviderBond is the minimum stake (in host-chain native tokens,
	// wei-equivalent) a provider must lock to register. Forfeited on
	// successful fraud proof or majority-divergence. Default 1000 LUX.
	MinProviderBond uint64 `json:"minProviderBond"`

	// Attestation settings — TEE is OPT-IN, NOT required by default.
	// On public chains keep RequireTEEAttestation=false; setting it true
	// restricts the provider set to TEE-equipped operators only, which
	// is a permissioned-deployment policy choice.
	RequireTEEAttestation bool   `json:"requireTEEAttestation"`
	MinTrustScore         uint8  `json:"minTrustScore"`
	AttestationTimeout    string `json:"attestationTimeout"`

	// Task settings
	MaxTaskQueueSize int    `json:"maxTaskQueueSize"`
	TaskTimeout      string `json:"taskTimeout"`

	// Reward settings
	BaseReward       uint64 `json:"baseReward"`
	EpochDuration    string `json:"epochDuration"`
	MerkleAnchorFreq int    `json:"merkleAnchorFreq"` // Blocks between Q-Chain anchors
}

// DefaultConfig returns default AIVM configuration suitable for ANY
// public Lux L1/L2 (no trusted dealer, no TEE requirement). The
// public-BFT-safe defaults are:
//   - VerificationMode = ModeOptimistic (fraud-proof flow)
//   - RequireTEEAttestation = false (TEE is optional acceleration)
//   - HostChainID = "primary" (override per L1/L2 instance)
//
// Permissioned/regulated deployments can opt into ModeTEEAttested +
// RequireTEEAttestation=true as a policy choice.
func DefaultConfig() Config {
	return Config{
		MaxProvidersPerNode:   100,
		MaxTasksPerProvider:   10,
		HostChainID:           "primary",
		VerificationMode:      ModeOptimistic,
		ChallengeWindowBlocks: 100,
		RedundancyFactor:      3,
		MinProviderBond:       1000_000_000_000_000_000, // 1000 LUX in wei
		RequireTEEAttestation: false,
		MinTrustScore:         50,
		AttestationTimeout:    "30s",
		MaxTaskQueueSize:      1000,
		TaskTimeout:           "5m",
		BaseReward:            1000000000, // 1 LUX in wei
		EpochDuration:         "1h",
		MerkleAnchorFreq:      100,
	}
}

// DefaultPermissionedConfig returns AIVM config for a permissioned
// chain (regulated AI compute, KYC'd provider set). Sets
// RequireTEEAttestation=true and VerificationMode=ModeTEEAttested.
// NOT for public mainnet use.
func DefaultPermissionedConfig() Config {
	c := DefaultConfig()
	c.VerificationMode = ModeTEEAttested
	c.RequireTEEAttestation = true
	c.MinTrustScore = 70
	return c
}

// VM implements the AI Virtual Machine
type VM struct {
	rt     *runtime.Runtime
	config Config

	// Database
	db database.Database

	// Per-VM GPU acceleration session. Reserved for future batch
	// attestation verification and tensor proof checks. Allocated by
	// the factory; safe to be nil in tests.
	accel *accel.VMSession

	// Core AI VM from luxfi/ai package
	core *aivm.VM

	// view is what an ACCEPTING block writes through: a versiondb over db,
	// committed exactly once per block together with the block itself, its
	// height entry and the tip pointer. It is empty at every other moment, which
	// is what stops one block's writes riding out on another block's commit.
	view *versiondb.Database

	// A-Chain-native quorum settlement engine (the AI task quorum-settlement
	// state machine: provider registry, stake/slash, selection, commit-reveal,
	// settlement, receipts, and the cross-chain seam). qstate is COMMITTED
	// engine state; custody is in qledger. quorum is the stateless handle bound
	// to the deployment's chain ids.
	quorum         *Engine
	qstate         QuorumState
	qledger        QuorumLedger
	ccv            CCommitVerifier // proves a C intent is committed before it can create a task
	pendingIntents []CIntent       // committed intents buffered for consensus-gated import

	// Attestation verifier (local nvtrust - no cloud dependency)
	verifier *attestation.Verifier

	// The chain: the accepted tip and the blocks verified above it. The tip is
	// the ONE in-memory answer to "where is this chain" — it is read back from
	// the same commit that wrote it, so a restart resumes rather than replaying
	// from genesis.
	lastAccepted *Block
	flight       map[ids.ID]*Block

	// chainID names this chain. Block ids are derived under it and it never
	// travels on the wire, so a block cannot be carried between chains.
	chainID ids.ID

	// clock is chain time as this node sees it. Mockable so a test can state
	// what "now" is rather than racing it.
	clock mockable.Clock

	// Consensus
	toEngine chan<- vmcore.Message
	// work wakes WaitForEvent when there is something to build. A burst of
	// submissions coalesces into one signal, so the engine is told that there
	// is work rather than how much.
	work vmcore.Latch

	// Logging
	log log.Logger

	// Fee policy gating user-submitted task admission. user-tx-
	// accepting (HTTP /tasks -> SubmitTask) so attach a FlatPolicy at
	// MinTxFeeFloor; consensus-internal paths bypass.
	feePolicy fee.Policy
	networkID uint32

	mu      sync.RWMutex
	running bool
}

// Keys. Blocks, the height index and the tip pointer are the chain's own;
// engine slots live under av/state/ and cannot collide with these.
var (
	tipKey       = []byte("av/tip")
	blockPrefix  = []byte("av/block/")
	heightPrefix = []byte("av/height/")
	vertexPrefix = []byte("av/vertex/")
)

func blockKey(id ids.ID) []byte {
	return append(append([]byte(nil), blockPrefix...), id[:]...)
}

func heightKey(h uint64) []byte {
	var u [8]byte
	binary.BigEndian.PutUint64(u[:], h)
	return append(append([]byte(nil), heightPrefix...), u[:]...)
}

func vertexKey(id ids.ID) []byte {
	return append(append([]byte(nil), vertexPrefix...), id[:]...)
}

// Initialize initializes the VM with the unified Init struct
// errRuntimeRequired is returned by Initialize when the consensus runtime is
// absent. Every later method assumes it.
var (
	errRuntimeRequired = errors.New("aivm: Initialize requires a runtime")
	errChainIDRequired = errors.New("aivm: Initialize requires a chain id")
)

func (vm *VM) Initialize(ctx context.Context, init vmcore.Init) error {
	vm.rt = init.Runtime
	vm.db = init.DB
	vm.toEngine = init.ToEngine
	// A VM with no runtime has no logger, no network and no node identity.
	// Guarding networkID and then dereferencing rt.Log on the next line meant
	// the guard read as defensive while the panic happened anyway.
	if vm.rt == nil {
		return errRuntimeRequired
	}
	vm.networkID = vm.rt.NetworkID
	// Block ids are derived under the chain id. Without one every A-Chain
	// deployment names its blocks identically and a block built on one is
	// resolvable on the next.
	vm.chainID = vm.rt.ChainID
	if vm.chainID == ids.Empty {
		return errChainIDRequired
	}

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		vm.log = logger
	} else {
		return errors.New("invalid logger type")
	}

	vm.flight = make(map[ids.ID]*Block)

	// Parse configuration
	if len(init.Config) > 0 {
		if err := json.Unmarshal(init.Config, &vm.config); err != nil {
			return fmt.Errorf("failed to parse config: %w", err)
		}
	} else {
		vm.config = DefaultConfig()
	}

	// Parse genesis (JSON format)
	genesis := &Genesis{}
	if len(init.Genesis) > 0 {
		if err := json.Unmarshal(init.Genesis, genesis); err != nil {
			return fmt.Errorf("failed to parse genesis: %w", err)
		}
	}

	// Initialize core AI VM
	vm.core = aivm.NewVM()

	// Initialize the A-Chain quorum settlement engine: DB-backed state (commits
	// under consensus), native ledger, and chain ids from the deployment. The
	// inbound C-intent seam defaults to a FAIL-CLOSED verifier — until a real
	// CCommitVerifier is installed (SetCommitVerifier), NO intent is treated as
	// committed and no task can be created from the boundary.
	vm.initQuorum()
	if vm.ccv == nil {
		vm.ccv = VerifierFunc(func(CIntent) error { return ErrIntentNotCommitted })
	}

	// Initialize attestation verifier (local nvtrust - no cloud dependency)
	vm.verifier = attestation.NewVerifier()

	// Pin fee policy. A-Chain accepts user inference tasks so attach
	// the canonical FlatPolicy at MinTxFeeFloor; fee.Validate refuses
	// zero-fee user-facing chains at boot.
	vm.feePolicy = newFeePolicy(vm.networkID)
	if err := fee.Validate(vm.feePolicy); err != nil {
		return fmt.Errorf("aivm: fee policy: %w", err)
	}

	// Start core VM
	if err := vm.core.Start(ctx); err != nil {
		return fmt.Errorf("failed to start core AI VM: %w", err)
	}

	// Where this chain is. A fresh chain starts at genesis; one that has run
	// before resumes at the tip its last Accept committed.
	genesisBlock := &Block{
		ParentID_:  ids.Empty,
		Height_:    0,
		Timestamp_: time.Unix(genesis.Timestamp, 0),
		vm:         vm,
	}
	if err := genesisBlock.name(); err != nil {
		return fmt.Errorf("aivm: encode genesis: %w", err)
	}
	tip, err := vm.openTip(genesisBlock)
	if err != nil {
		return err
	}
	vm.lastAccepted = tip

	vm.running = true
	if !vm.log.IsZero() {
		vm.log.Info("AIVM initialized",
			log.Bool("requireTEE", vm.config.RequireTEEAttestation),
			log.Uint8("minTrustScore", vm.config.MinTrustScore),
		)
	}

	return nil
}

// Genesis represents the genesis state
type Genesis struct {
	Version   int    `json:"version"`
	Message   string `json:"message"`
	Timestamp int64  `json:"timestamp"`
}

// live reports whether the VM is running.
//
// It is a METHOD because `running` is written under vm.mu by Shutdown, and a
// read of it that does not take the lock is a data race — one the race detector
// reports on the first concurrent request. Eight read paths took that shortcut,
// so the fix is one reader that all of them use. The paths that already hold the
// lock read the field directly; taking it twice would deadlock.
func (vm *VM) live() bool {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	return vm.running
}

// Shutdown shuts down the VM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil
	}

	vm.running = false

	if vm.core != nil {
		return vm.core.Stop()
	}

	return nil
}

// CreateHandlers returns one entry per endpoint.
//
// The node mounts each KEY as a route and delivers the request on the path it
// arrived on, so a handler that dispatches on r.URL.Path never matches: it is
// asked for /v1/bc/<chainID>/rpc and looks for /stats. A flat map of endpoints to
// handlers that answer AT their mount is the simplest shape that works, and it is
// what this VM uses.
//
// It is not the only shape. An endpoint also owns the paths beneath it, and a VM
// that wants a subtree may mount one handler and read the remainder — the node
// strips the mount before handing it over (node server/http/router.go,
// serveBelowMount). Both are served; a VM picks whichever matches its surface.
func (vm *VM) CreateHandlers(context.Context) (map[string]http.Handler, error) {
	return Routes(vm), nil
}

// Connected notifies the VM about connected nodes
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *chain.VersionInfo) error {
	return nil
}

// Disconnected notifies the VM about disconnected nodes
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	return nil
}

// RegisterProvider registers a new AI compute provider.
//
// Public-BFT-safe path (VerificationMode=ModeOptimistic, default):
//   - Provider locks MinProviderBond in the host chain's escrow
//   - TEE attestation is OPTIONAL — providers without TEE register
//     under the optimistic-verification flow (challenge period +
//     fraud proofs handle correctness without trusting the provider)
//
// Permissioned path (RequireTEEAttestation=true, opt-in):
//   - Provider MUST present valid TEE attestation
//   - TrustScore must meet MinTrustScore
//   - Used on permissioned chains where the validator set vets
//     hardware operators by policy
func (vm *VM) RegisterProvider(provider *aivm.Provider) error {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return ErrNotInitialized
	}

	// Registration is open: the default policy (RequireTEEAttestation=false) is
	// that anyone may register and submit results, with the provider's bond and
	// the challenge flow carrying correctness rather than an admission list.
	//
	// When RequireTEEAttestation=true (permissioned deployment policy):
	// every provider MUST present TEE attestation and meet the
	// trust-score threshold. This is a deployment-policy gate,
	// independent of the protocol's public-BFT-safety contract.
	if vm.config.RequireTEEAttestation {
		if provider.GPUAttestation == nil && provider.CPUAttestation == nil {
			return fmt.Errorf("permissioned policy requires TEE attestation but provider supplied none; set RequireTEEAttestation=false for the public-chain path")
		}
		if provider.GPUAttestation != nil {
			status, err := vm.verifier.VerifyGPUAttestation(provider.GPUAttestation)
			if err != nil {
				return fmt.Errorf("GPU attestation failed: %w", err)
			}
			if status.TrustScore < vm.config.MinTrustScore {
				return fmt.Errorf("trust score %d below minimum %d", status.TrustScore, vm.config.MinTrustScore)
			}
		}
	}
	// On the public-BFT path (RequireTEEAttestation=false) the provider's
	// bond + the optimistic-challenge flow handle correctness. TEE
	// attestation, if supplied, is folded into a trust-score multiplier
	// that can REDUCE (but never bypass) the challenge window — verified
	// at result-submission time, not here.

	return vm.core.RegisterProvider(provider)
}

// VerifyGPUAttestation verifies GPU attestation (local nvtrust - no cloud)
func (vm *VM) VerifyGPUAttestation(att *attestation.GPUAttestation) (*attestation.DeviceStatus, error) {
	if !vm.live() {
		return nil, ErrNotInitialized
	}
	return vm.verifier.VerifyGPUAttestation(att)
}

// SubmitTask submits a new AI task. This is the canonical user-task
// admission point on A-Chain — the HTTP /tasks handler routes through
// here. The FeePolicy gate refuses zero-fee tasks before they touch
// the core queue. Internal callers (consensus replay) bypass by
// reaching vm.core.SubmitTask directly.
func (vm *VM) SubmitTask(task *aivm.Task) error {
	vm.mu.Lock()
	running := vm.running
	vm.mu.Unlock()

	if !running {
		return ErrNotInitialized
	}

	if err := vm.gateUserTask(task); err != nil {
		return err
	}

	vm.mu.Lock()
	err := vm.core.SubmitTask(task)
	vm.mu.Unlock()
	if err != nil {
		return err
	}
	vm.work.Signal()
	return nil
}

// GetTask returns a task by ID
func (vm *VM) GetTask(taskID string) (*aivm.Task, error) {
	if !vm.live() {
		return nil, ErrNotInitialized
	}
	return vm.core.GetTask(taskID)
}

// SubmitResult submits a task result
func (vm *VM) SubmitResult(result *aivm.TaskResult) error {
	vm.mu.Lock()
	if !vm.running {
		vm.mu.Unlock()
		return ErrNotInitialized
	}
	err := vm.core.SubmitResult(result)
	vm.mu.Unlock()
	if err != nil {
		return err
	}
	vm.work.Signal()
	return nil
}

// GetProviders returns all registered providers
func (vm *VM) GetProviders() []*aivm.Provider {
	if !vm.live() {
		return nil
	}
	return vm.core.GetProviders()
}

// GetModels returns available AI models
func (vm *VM) GetModels() []*aivm.ModelInfo {
	if !vm.live() {
		return nil
	}
	return vm.core.GetModels()
}

// GetStats returns VM statistics
func (vm *VM) GetStats() map[string]interface{} {
	if !vm.live() {
		return nil
	}
	return vm.core.GetStats()
}

// GetMerkleRoot returns merkle root for Q-Chain anchoring
func (vm *VM) GetMerkleRoot() [32]byte {
	if !vm.live() {
		return [32]byte{}
	}
	return vm.core.GetMerkleRoot()
}

// ClaimRewards claims pending rewards for a provider
func (vm *VM) ClaimRewards(providerID string) (string, error) {
	if !vm.live() {
		return "", ErrNotInitialized
	}
	return vm.core.ClaimRewards(providerID)
}

// GetRewardStats returns reward statistics for a provider
func (vm *VM) GetRewardStats(providerID string) (map[string]interface{}, error) {
	if !vm.live() {
		return nil, ErrNotInitialized
	}
	return vm.core.GetRewardStats(providerID)
}

// =============================================================================
// ChainVM Interface Methods
// =============================================================================

// SetState implements chain.ChainVM interface
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	// Handle state transitions (bootstrapping -> normal operation)
	return nil
}

// BuildBlock proposes the next block. It DECIDES what the block carries and
// changes nothing: the candidate intents are applied to an overlay over
// committed state and a clone of the ledger, both discarded here, and what
// survives is the list of intents that imported cleanly plus the receipt root
// they reach. Every validator, including this one at Accept, re-derives that
// root from the same inputs.
//
// The buffered intents are NOT drained. A proposal that loses the round has
// consumed nothing, so the next proposer can still carry the same work; draining
// at build time destroyed it.
func (vm *VM) BuildBlock(ctx context.Context) (chain.Block, error) {
	vm.mu.Lock()
	defer vm.mu.Unlock()

	if !vm.running {
		return nil, ErrNotInitialized
	}
	parent := vm.lastAccepted
	if parent == nil {
		return nil, errors.New("aivm: no parent block")
	}

	// Chain time never runs backwards, so a proposer whose clock has not moved
	// past its parent stamps the parent's time rather than building a block its
	// own Verify would refuse.
	stamp := vm.clock.Time()
	if !stamp.After(parent.Timestamp_) {
		stamp = parent.Timestamp_
	}

	height := parent.Height_ + 1
	scratch := newOverlay(vm.qstate)
	carried, root := vm.pick(scratch, newStateLedger(scratch), height)

	blk := &Block{
		ParentID_:       parent.ID_,
		Height_:         height,
		Timestamp_:      stamp,
		ImportedIntents: carried,
		ReceiptRoot:     root,
		vm:              vm,
	}
	if err := blk.name(); err != nil {
		return nil, err
	}
	// A block this node builds is held to the size a block off the wire is held
	// to, so a proposer cannot produce one its own peers refuse to parse.
	if n := len(blk.bytes); n > MaxBlockSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d", ErrInvalidBlock, n, MaxBlockSize)
	}
	vm.track(blk)
	return blk, nil
}

// ParseBlock decodes a block off the wire. The size bound is checked BEFORE the
// decode, so the work a peer can make this node do is bounded by a number rather
// than by the peer.
func (vm *VM) ParseBlock(ctx context.Context, wire []byte) (chain.Block, error) {
	if n := len(wire); n > MaxBlockSize {
		return nil, fmt.Errorf("%w: %d bytes exceeds %d", ErrInvalidBlock, n, MaxBlockSize)
	}
	return vm.parseBlock(wire)
}

// parseBlock decodes wire into a Block belonging to this chain, and names it.
// The name is derived from the block's own canonical encoding rather than from
// the bytes handed over, so a buffer carrying padding the decoder ignores can
// never be stored under the id of the canonical one.
func (vm *VM) parseBlock(wire []byte) (*Block, error) {
	blk := &Block{vm: vm}
	if err := parseBlock(wire, blk); err != nil {
		return nil, err
	}
	if err := blk.name(); err != nil {
		return nil, err
	}
	return blk, nil
}

// GetBlock returns a block by id: one in flight, the tip, or one read back from
// committed state.
func (vm *VM) GetBlock(ctx context.Context, id ids.ID) (chain.Block, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()

	if blk, ok := vm.flight[id]; ok {
		return blk, nil
	}
	if vm.lastAccepted != nil && vm.lastAccepted.ID_ == id {
		return vm.lastAccepted, nil
	}
	wire, err := vm.db.Get(blockKey(id))
	if err != nil {
		return nil, err
	}
	return vm.parseBlock(wire)
}

// SetPreference implements chain.ChainVM interface
func (vm *VM) SetPreference(ctx context.Context, id ids.ID) error {
	// For AIVM, we just track this but don't need to do anything special
	return nil
}

// LastAccepted implements chain.ChainVM interface
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	if vm.lastAccepted == nil {
		return ids.Empty, ErrNotInitialized
	}
	return vm.lastAccepted.ID_, nil
}

// GetBlockIDAtHeight answers from the height index Accept writes in the same
// commit as the block itself, so the index cannot name a block the chain did not
// accept.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	vm.mu.RLock()
	defer vm.mu.RUnlock()
	raw, err := vm.db.Get(heightKey(height))
	if err != nil {
		return ids.Empty, fmt.Errorf("aivm: height %d: %w", height, err)
	}
	return ids.ToID(raw)
}

// openTip reads back where this chain got to.
//
// Only an ABSENT tip means a fresh chain. Reading any other failure that way — a
// closed database, an unreadable volume, a short read — starts a live chain over
// at genesis and lets it build height 1 on top of state it cannot see, durably.
// A chain that cannot read its own tip does not know where it is, and the honest
// answer is to refuse to open.
func (vm *VM) openTip(genesis *Block) (*Block, error) {
	raw, err := vm.db.Get(tipKey)
	switch {
	case errors.Is(err, database.ErrNotFound):
		return genesis, nil
	case err != nil:
		return nil, fmt.Errorf("aivm: read tip: %w", err)
	}
	// ToID refuses anything that is not an id, which is the whole of what can be
	// wrong with these bytes — checking the length first and then converting made
	// the conversion's own error a branch nothing could take.
	id, err := ids.ToID(raw)
	if err != nil {
		return nil, fmt.Errorf("aivm: tip: %w", err)
	}
	if id == genesis.ID_ {
		return genesis, nil
	}
	wire, err := vm.db.Get(blockKey(id))
	if err != nil {
		return nil, fmt.Errorf("aivm: tip %s: %w", id, err)
	}
	blk, err := vm.parseBlock(wire)
	if err != nil {
		return nil, err
	}
	// The tip was named under this chain id when it was written. A different id
	// here means the database belongs to another chain, which is not a chain to
	// resume — it is one to refuse.
	if blk.ID_ != id {
		return nil, fmt.Errorf("aivm: stored tip names %s, its bytes name %s", id, blk.ID_)
	}
	return blk, nil
}

// NewHTTPHandler implements chain.ChainVM interface
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

// Version implements chain.ChainVM interface
func (vm *VM) Version(ctx context.Context) (string, error) {
	return Version.String(), nil
}

// WaitForEvent blocks until there is work to build a block from, or the VM
// stops. Returning only on ctx.Done() would mean BuildBlock is never called and
// the chain can never leave genesis.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.work.WaitForEvent(ctx)
}

// HealthCheck implements chain.ChainVM interface
func (vm *VM) HealthCheck(ctx context.Context) (chain.HealthResult, error) {
	return chain.HealthResult{
		Healthy: vm.live(),
		Details: map[string]string{"status": "operational"},
	}, nil
}
