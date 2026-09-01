// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package identityvm implements the I-Chain: decentralized identifiers, the
// issuers the chain trusts, the credentials they issue, and the revocations
// that withdraw them.
package identityvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/gorilla/rpc/v2"
	grjson "github.com/gorilla/rpc/v2/json2"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	vmchain "github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"
)

const (
	Name = "identityvm"

	// Defaults for a config that names no bound. Zero would be no bound.
	defaultCredentialTTL      = int64(365 * 24 * 60 * 60) // one year, in seconds
	defaultMaxClaims          = 100
	defaultMaxRecordsPerBlock = 256

	// MaxPendingChanges bounds the queue of changes waiting for a block.
	// Submitting is open to anyone who can pay, so without a bound the queue is
	// whatever they choose to make it.
	MaxPendingChanges = 4096
)

var (
	_ vmchain.ChainVM = (*VM)(nil)

	errNothingToBuild = errors.New("identityvm: nothing to build a block from")
	errNoAppProtocol  = errors.New("identityvm: this chain has no app protocol")
)

// Config holds IdentityVM configuration. Every field here is read.
type Config struct {
	// CredentialTTL is how long a credential lasts when its issuer names no
	// lifetime, in seconds.
	CredentialTTL int64 `json:"credentialTTL"`

	// MaxClaims bounds one credential's claims.
	MaxClaims int `json:"maxClaims"`

	// MaxRecordsPerBlock bounds a block from either direction: what a proposer
	// assembles and what Verify accepts off the wire.
	MaxRecordsPerBlock int `json:"maxRecordsPerBlock"`

	// TrustedIssuers names the issuers this chain admits, by id. An empty list
	// admits any issuer that proves it holds its key. It used to be loaded and
	// never read, which is an allowlist that allows everything.
	TrustedIssuers []ids.ID `json:"trustedIssuers"`

	// AllowSelfIssue lets a credential name an issuer this chain has no record
	// of, provided the signature is by the subject's own key: an identity
	// making a claim about itself.
	AllowSelfIssue bool `json:"allowSelfIssue"`
}

// Change is one state change waiting for a block: exactly one of the four.
type Change struct {
	Identity   *Identity
	Issuer     *Issuer
	Credential *Credential
	Revocation *Revocation
}

// subject is what the change claims, and how the pool finds it again. Two
// changes claiming the same thing cannot both be right, and the pool keeps the
// first.
func (c *Change) subject() ids.ID {
	switch {
	case c.Identity != nil:
		return c.Identity.ID
	case c.Issuer != nil:
		return c.Issuer.ID
	case c.Credential != nil:
		return c.Credential.ID
	default:
		return c.Revocation.CredentialID
	}
}

// VM implements the IdentityVM for decentralized identity
type VM struct {
	rt     *runtime.Runtime
	config Config
	log    log.Logger

	// chain is the durable state, the blocks in flight and the tip — and the
	// one lock over all of it, which the record caches below share. Take it
	// with chain.Lock or chain.RLock.
	chain *chain.Store[*Block]

	// Record caches, under the chain's lock. They are rebuilt from the records
	// at boot: everything here is also on disk, written by the block that
	// decided it.
	identities  map[ids.ID]*Identity
	credentials map[ids.ID]*Credential
	issuers     map[ids.ID]*Issuer
	revocations map[ids.ID]*Revocation

	// pending holds the changes waiting for a block, and tells consensus there
	// is one to build. LOCK ORDER: the chain's lock, then the pool's.
	pending *chain.Pool[*Change, ids.ID]

	// bind is sha256(ChainID ‖ NetworkID). It is hashed into every block id and
	// is the signing context every record's signature is checked under, and it
	// is NOT on the wire — so a block or an authorization made for another
	// chain does not name a block of this one and does not authorize anything
	// here, rather than passing a check someone could forget to write.
	bind [32]byte

	// fee is what this chain charges to admit a mutating RPC.
	fee chain.Fee

	rpcServer *rpc.Server
}

// Initialize implements chain.ChainVM
func (vm *VM) Initialize(ctx context.Context, vmInit vmcore.Init) error {
	vm.rt = vmInit.Runtime
	if vm.rt == nil {
		return errors.New("identityvm: runtime is nil")
	}

	logger, ok := vm.rt.Log.(log.Logger)
	if !ok {
		return errors.New("identityvm: invalid logger type")
	}
	vm.log = logger

	bind := sha256.New()
	bind.Write(vm.rt.ChainID[:])
	binary.Write(bind, binary.BigEndian, vm.rt.NetworkID)
	copy(vm.bind[:], bind.Sum(nil))

	vm.chain = chain.New[*Block](vmInit.DB, vm.reload)
	vm.identities = make(map[ids.ID]*Identity)
	vm.credentials = make(map[ids.ID]*Credential)
	vm.issuers = make(map[ids.ID]*Issuer)
	vm.revocations = make(map[ids.ID]*Revocation)
	vm.pending = chain.NewPool(MaxPendingChanges, (*Change).subject)

	genesis, err := ParseGenesis(vmInit.Genesis)
	if err != nil {
		return fmt.Errorf("identityvm: parse genesis: %w", err)
	}

	vm.config = Config{
		CredentialTTL:      defaultCredentialTTL,
		MaxClaims:          defaultMaxClaims,
		MaxRecordsPerBlock: defaultMaxRecordsPerBlock,
	}
	if genesis.Config != nil {
		vm.config = *genesis.Config
		if vm.config.CredentialTTL <= 0 {
			vm.config.CredentialTTL = defaultCredentialTTL
		}
		if vm.config.MaxClaims <= 0 {
			vm.config.MaxClaims = defaultMaxClaims
		}
		if vm.config.MaxRecordsPerBlock <= 0 {
			vm.config.MaxRecordsPerBlock = defaultMaxRecordsPerBlock
		}
	}

	vm.rpcServer = rpc.NewServer()
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json;charset=UTF-8")
	if err := vm.rpcServer.RegisterService(&Service{vm: vm}, "identity"); err != nil {
		return fmt.Errorf("identityvm: register service: %w", err)
	}

	// I-Chain accepts user mutating RPCs, so it declares the floor; the node's
	// boot-time Validate refuses a zero-fee user-facing chain.
	vm.fee = chain.Floor(vm.rt.NetworkID)
	if err := fee.Validate(vm.fee.Policy()); err != nil {
		return fmt.Errorf("identityvm: fee policy: %w", err)
	}

	// Genesis is at height 0, stamped with the time genesis itself declares.
	// Reading the wall clock here would give every node a different genesis id
	// for the same chain, since the id is the hash of the block's own fields —
	// which is what ParseGenesis did, contradicting this comment, for a genesis
	// that named no timestamp.
	genesisBlock := &Block{
		BlockTimestamp: genesis.Timestamp,
		vm:             vm,
		status:         choices.Accepted,
	}
	if _, _, err := vm.chain.Open(genesisBlock, vm.parseBlock); err != nil {
		return err
	}

	// The caches hold what the records hold. Filling them only from genesis
	// meant every identity, credential, issuer and revocation the chain had
	// accepted was invisible after a restart: GetIdentity answered "unknown"
	// for an identity on disk, and a block naming it failed to verify.
	if err := vm.reload(); err != nil {
		return err
	}
	for _, identity := range genesis.Identities {
		vm.identities[identity.ID] = identity
	}
	for _, issuer := range genesis.Issuers {
		vm.issuers[issuer.ID] = issuer
	}

	vm.log.Info("IdentityVM initialized",
		log.Int("issuers", len(vm.issuers)),
		log.Int("identities", len(vm.identities)),
		log.Int("credentials", len(vm.credentials)),
	)

	return nil
}

// parseBlock decodes a block belonging to this VM. The store reads accepted
// blocks back through it, and ParseBlock hands peer bytes to it, so there is
// one decoder rather than one per call site.
func (vm *VM) parseBlock(raw []byte) (*Block, error) {
	block := &Block{vm: vm, bytes: raw}
	if err := parseBlock(raw, block); err != nil {
		return nil, err
	}
	block.ID_ = block.computeID()
	return block, nil
}

// SetState implements chain.ChainVM
func (vm *VM) SetState(ctx context.Context, state uint32) error { return nil }

// CreateHandlers implements chain.ChainVM
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{"/rpc": vm.rpcServer}, nil
}

// NewHTTPHandler mounts the same route by path.
func (vm *VM) NewHTTPHandler(ctx context.Context) (http.Handler, error) {
	mux := http.NewServeMux()
	mux.Handle("/rpc", vm.rpcServer)
	return mux, nil
}

// Shutdown implements chain.ChainVM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.log.Info("IdentityVM shutting down")
	return vm.chain.Close()
}

// HealthCheck implements chain.ChainVM
func (vm *VM) HealthCheck(ctx context.Context) (vmchain.HealthResult, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	_, height := vm.chain.Tip()
	return vmchain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"identities":  fmt.Sprintf("%d", len(vm.identities)),
			"credentials": fmt.Sprintf("%d", len(vm.credentials)),
			"issuers":     fmt.Sprintf("%d", len(vm.issuers)),
			"revocations": fmt.Sprintf("%d", len(vm.revocations)),
			"height":      fmt.Sprintf("%d", height),
		},
	}, nil
}

// Version implements chain.ChainVM
func (vm *VM) Version(ctx context.Context) (string, error) { return "1.0.0", nil }

// Connected implements chain.ChainVM
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *vmchain.VersionInfo) error {
	return nil
}

// Disconnected implements chain.ChainVM
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error { return nil }

// Request implements the app protocol, of which this chain has none.
func (vm *VM) Request(ctx context.Context, nodeID ids.NodeID, requestID uint32, deadline time.Time, request []byte) error {
	return errNoAppProtocol
}

func (vm *VM) Response(ctx context.Context, nodeID ids.NodeID, requestID uint32, response []byte) error {
	return nil
}

func (vm *VM) RequestFailed(ctx context.Context, nodeID ids.NodeID, requestID uint32, appErr *warp.Error) error {
	return nil
}

func (vm *VM) Gossip(ctx context.Context, nodeID ids.NodeID, msg []byte) error { return nil }

func (vm *VM) CrossChainRequest(ctx context.Context, chainID ids.ID, requestID uint32, deadline time.Time, request []byte) error {
	return nil
}

func (vm *VM) CrossChainResponse(ctx context.Context, chainID ids.ID, requestID uint32, response []byte) error {
	return nil
}

func (vm *VM) CrossChainRequestFailed(ctx context.Context, chainID ids.ID, requestID uint32, appErr *warp.Error) error {
	return nil
}

// BuildBlock implements chain.ChainVM. Reading the tip and registering the
// block on it happen in one step, so nothing can be accepted in between and
// leave the proposal hanging off a parent that is no longer the tip.
func (vm *VM) BuildBlock(ctx context.Context) (vmchain.Block, error) {
	built, err := vm.chain.Propose(func(parent *Block) (*Block, error) {
		// Assembly takes a BOUNDED window and runs the predicate Verify runs,
		// dropping what it cannot build. Taking everything and skipping the
		// check meant one unbuildable change rode in every block this node
		// proposed, was refused by every node including this one, and stayed
		// queued — a permanent halt for whoever submitted it.
		block := &Block{
			ParentID_:      parent.ID(),
			BlockHeight:    parent.Height() + 1,
			BlockTimestamp: buildTimestamp(parent),
			vm:             vm,
			status:         choices.Processing,
		}

		for _, change := range vm.pending.Take(vm.config.MaxRecordsPerBlock) {
			block.add(change)
			if err := vm.check(block); err != nil {
				vm.log.Debug("change not admitted", log.Reflect("error", err))
				block.drop(change)
				vm.pending.Drop([]*Change{change})
			}
		}
		if block.records() == 0 {
			return nil, errNothingToBuild
		}
		return block, nil
	})
	if err != nil {
		return nil, err
	}
	return built, nil
}

// buildTimestamp is now, never behind the parent. Chain time only moves
// forward and a parent may legally be up to maxClockSkew ahead of this node's
// clock, so an unclamped now builds a block this node's own Verify refuses.
func buildTimestamp(parent *Block) int64 {
	now := time.Now().Unix()
	if now < parent.BlockTimestamp {
		return parent.BlockTimestamp
	}
	return now
}

func (b *Block) add(c *Change) {
	switch {
	case c.Identity != nil:
		b.Identities = append(b.Identities, c.Identity)
	case c.Issuer != nil:
		b.Issuers = append(b.Issuers, c.Issuer)
	case c.Credential != nil:
		b.Credentials = append(b.Credentials, c.Credential)
	default:
		b.Revocations = append(b.Revocations, c.Revocation)
	}
	b.bytes, b.ID_ = nil, ids.Empty
}

func (b *Block) drop(c *Change) {
	switch {
	case c.Identity != nil:
		b.Identities = b.Identities[:len(b.Identities)-1]
	case c.Issuer != nil:
		b.Issuers = b.Issuers[:len(b.Issuers)-1]
	case c.Credential != nil:
		b.Credentials = b.Credentials[:len(b.Credentials)-1]
	default:
		b.Revocations = b.Revocations[:len(b.Revocations)-1]
	}
	b.bytes, b.ID_ = nil, ids.Empty
}

// ParseBlock implements chain.ChainVM.
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (vmchain.Block, error) {
	block, err := vm.parseBlock(blockBytes)
	if err != nil {
		return nil, err
	}
	// A block the engine may build on has to be findable by id, including one
	// parsed from a peer. Tracking only self-built blocks leaves a follower
	// able to verify the first block of a run and not the second.
	block.status = choices.Processing
	vm.chain.Track(block)
	return block, nil
}

// GetBlock implements chain.ChainVM
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (vmchain.Block, error) {
	return vm.chain.Block(blockID, vm.parseBlock)
}

// SetPreference records the block the engine wants the next one built on.
// Dropping it meant Propose always built on the accepted tip, so a node with
// two blocks in flight re-proposed a height it had already proposed.
func (vm *VM) SetPreference(ctx context.Context, blockID ids.ID) error {
	vm.chain.Prefer(blockID)
	return nil
}

// LastAccepted implements chain.ChainVM
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	id, _ := vm.chain.Tip()
	return id, nil
}

// GetBlockIDAtHeight answers from the height index the store writes in the
// same commit as the block itself, so the index can never name a block the
// chain did not accept.
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	return vm.chain.IDAtHeight(height)
}

// WaitForEvent blocks until there is a change to build a block from, or the VM
// stops. Waiting only on the context would mean BuildBlock is never called and
// the chain never leaves genesis, however much is submitted.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.pending.Wait(ctx)
}

// FeePolicy exposes the chain's declared fee policy for diagnostics and the
// boot-time Validate gate.
func (vm *VM) FeePolicy() fee.Policy { return vm.fee.Policy() }

// gateUserTx admits a user-submitted mutation iff its fee satisfies the floor.
func (vm *VM) gateUserTx(paid uint64) error { return vm.fee.Admit(paid) }

// ======== Genesis ========

// Genesis represents genesis data for IdentityVM
type Genesis struct {
	Timestamp  int64       `json:"timestamp"`
	Config     *Config     `json:"config,omitempty"`
	Issuers    []*Issuer   `json:"issuers,omitempty"`
	Identities []*Identity `json:"identities,omitempty"`
	Message    string      `json:"message,omitempty"`
}

// ParseGenesis parses genesis bytes. A genesis that names no timestamp is
// stamped 0, not "now": the timestamp is hashed into the genesis block id, so
// reading the wall clock here gave every node a different genesis id — a
// different chain — for the same genesis file, and a different one again after
// each restart.
func ParseGenesis(genesisBytes []byte) (*Genesis, error) {
	var genesis Genesis
	if len(genesisBytes) > 0 {
		if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
			return nil, err
		}
	}
	return &genesis, nil
}
