// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

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
	grjson "github.com/gorilla/rpc/v2/json"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/artifacts"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	vmchain "github.com/luxfi/vm/chain"
)

const (
	Name = "identityvm"

	// Credential states
	CredentialActive  = "active"
	CredentialRevoked = "revoked"
	CredentialExpired = "expired"
	CredentialPending = "pending"

	// Default configuration
	defaultCredentialTTL = 365 * 24 * time.Hour // 1 year
	defaultMaxClaims     = 100
)

var (
	_ vmchain.ChainVM = (*VM)(nil)

	identityPrefix   = []byte("id:")
	credentialPrefix = []byte("cred:")
	issuerPrefix     = []byte("issuer:")
	revocationPrefix = []byte("revoke:")

	errUnknownIdentity   = errors.New("unknown identity")
	errUnknownCredential = errors.New("unknown credential")
	errCredentialRevoked = errors.New("credential revoked")
	errCredentialExpired = errors.New("credential expired")
	errNotIssuer         = errors.New("not authorized issuer")
	errNothingToBuild    = errors.New("no credentials to build a block from")
	errInvalidProof      = errors.New("invalid zero-knowledge proof")
)

// Config holds IdentityVM configuration
type Config struct {
	CredentialTTL   int64    `json:"credentialTTL"` // Seconds
	MaxClaims       int      `json:"maxClaims"`
	TrustedIssuers  []string `json:"trustedIssuers"`
	AllowSelfIssue  bool     `json:"allowSelfIssue"`
	RequireZKProofs bool     `json:"requireZKProofs"`
}

// Identity represents a decentralized identity
type Identity struct {
	ID          ids.ID            `json:"id"`
	DID         string            `json:"did"`         // Decentralized Identifier (e.g., did:lux:xyz)
	PublicKey   []byte            `json:"publicKey"`   // Primary public key
	Controllers []ids.ID          `json:"controllers"` // Controlling identities
	Services    []ServiceEndpoint `json:"services"`
	Created     time.Time         `json:"created"`
	Updated     time.Time         `json:"updated"`
	Metadata    map[string]string `json:"metadata"`
}

// ServiceEndpoint represents a service associated with an identity
type ServiceEndpoint struct {
	ID              string `json:"id"`
	Type            string `json:"type"`
	ServiceEndpoint string `json:"serviceEndpoint"`
}

// Credential represents a verifiable credential
type Credential struct {
	ID              ids.ID                 `json:"id"`
	Type            []string               `json:"type"`
	Issuer          ids.ID                 `json:"issuer"`
	Subject         ids.ID                 `json:"subject"`
	IssuanceDate    time.Time              `json:"issuanceDate"`
	ExpirationDate  time.Time              `json:"expirationDate"`
	Claims          map[string]interface{} `json:"claims"`
	Proof           *CredentialProof       `json:"proof,omitempty"`
	Status          string                 `json:"status"`
	RevocationIndex uint64                 `json:"revocationIndex,omitempty"`
}

// CredentialProof represents a proof for a credential
type CredentialProof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         []byte `json:"proofValue"`
	ZKProof            []byte `json:"zkProof,omitempty"` // Zero-knowledge proof
}

// Issuer represents a trusted credential issuer
type Issuer struct {
	ID         ids.ID    `json:"id"`
	Name       string    `json:"name"`
	PublicKey  []byte    `json:"publicKey"`
	Types      []string  `json:"types"` // Types of credentials they can issue
	TrustLevel int       `json:"trustLevel"`
	CreatedAt  time.Time `json:"createdAt"`
	Status     string    `json:"status"`
}

// RevocationEntry represents a credential revocation
type RevocationEntry struct {
	CredentialID ids.ID    `json:"credentialId"`
	RevokedBy    ids.ID    `json:"revokedBy"`
	RevokedAt    time.Time `json:"revokedAt"`
	Reason       string    `json:"reason"`
}

// MaxPendingCredentials bounds the queue of credentials waiting for a block.
// Issuing is open to any authorized issuer, so without a bound the queue is
// whatever they choose to make it.
const MaxPendingCredentials = 4096

// VM implements the IdentityVM for decentralized identity
type VM struct {
	rt     *runtime.Runtime
	config Config
	log    log.Logger

	// chain is the durable state, the blocks in flight and the tip — and the
	// one lock over all of it, which the record caches below share. Take it
	// with chain.Lock or chain.RLock.
	chain *chain.Store[*Block]

	// Record caches, under the chain's lock.
	identities  map[ids.ID]*Identity
	credentials map[ids.ID]*Credential
	issuers     map[ids.ID]*Issuer
	revocations map[ids.ID]*RevocationEntry

	// pending holds the credentials waiting for a block, and tells consensus
	// there is one to build. LOCK ORDER: the chain's lock, then the pool's.
	pending *chain.Pool[*Credential, ids.ID]

	// fee is what this chain charges to admit a mutating RPC. I-Chain accepts
	// user-submitted DID and credential calls that produce on-chain effects,
	// so it declares the floor rather than admitting free work.
	fee chain.Fee

	// RPC
	rpcServer *rpc.Server
}

// Initialize implements chain.ChainVM
func (vm *VM) Initialize(
	ctx context.Context,
	vmInit vmcore.Init,
) error {
	vm.rt = vmInit.Runtime

	if logger, ok := vm.rt.Log.(log.Logger); ok {
		vm.log = logger
	} else {
		return errors.New("invalid logger type")
	}

	// The caches are rebuilt only here: a block publishes its records after its
	// writes have committed, so a block that fails leaves them untouched and
	// there is nothing to roll back.
	vm.chain = chain.New[*Block](vmInit.DB, nil)
	vm.identities = make(map[ids.ID]*Identity)
	vm.credentials = make(map[ids.ID]*Credential)
	vm.issuers = make(map[ids.ID]*Issuer)
	vm.revocations = make(map[ids.ID]*RevocationEntry)
	vm.pending = chain.NewPool(MaxPendingCredentials, func(c *Credential) ids.ID { return c.ID })

	// Parse genesis
	genesis, err := ParseGenesis(vmInit.Genesis)
	if err != nil {
		return fmt.Errorf("failed to parse genesis: %w", err)
	}

	// Apply configuration
	vm.config = Config{
		CredentialTTL:   int64(defaultCredentialTTL.Seconds()),
		MaxClaims:       defaultMaxClaims,
		AllowSelfIssue:  false,
		RequireZKProofs: false,
	}

	if genesis.Config != nil {
		if genesis.Config.CredentialTTL > 0 {
			vm.config.CredentialTTL = genesis.Config.CredentialTTL
		}
		if genesis.Config.MaxClaims > 0 {
			vm.config.MaxClaims = genesis.Config.MaxClaims
		}
		vm.config.TrustedIssuers = genesis.Config.TrustedIssuers
		vm.config.AllowSelfIssue = genesis.Config.AllowSelfIssue
		vm.config.RequireZKProofs = genesis.Config.RequireZKProofs
	}

	// Initialize RPC server
	vm.rpcServer = rpc.NewServer()
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json")
	vm.rpcServer.RegisterCodec(grjson.NewCodec(), "application/json;charset=UTF-8")
	vm.rpcServer.RegisterService(&Service{vm: vm}, "identity")

	// I-Chain accepts user mutating RPCs, so it declares the floor; the node's
	// boot-time Validate refuses a zero-fee user-facing chain.
	var networkID uint32
	if vm.rt != nil {
		networkID = vm.rt.NetworkID
	}
	vm.fee = chain.Floor(networkID)
	if err := fee.Validate(vm.fee.Policy()); err != nil {
		return fmt.Errorf("identityvm: fee policy: %w", err)
	}

	// Genesis is at height 0, stamped with the time genesis itself declares.
	// Reading the wall clock here would give every node a different genesis id
	// for the same chain, since the id is the hash of the block's own fields.
	genesisBlock := &Block{
		BlockTimestamp: genesis.Timestamp,
		vm:             vm,
		status:         choices.Accepted,
	}
	if _, _, err := vm.chain.Open(genesisBlock, vm.parseBlock); err != nil {
		return err
	}

	// Initialize genesis issuers
	for _, issuer := range genesis.Issuers {
		vm.issuers[issuer.ID] = issuer
	}

	// Initialize genesis identities
	for _, identity := range genesis.Identities {
		vm.identities[identity.ID] = identity
	}

	vm.log.Info("IdentityVM initialized",
		log.Int("issuers", len(vm.issuers)),
		log.Int("identities", len(vm.identities)),
	)

	return nil
}

// parseBlock decodes a block belonging to this VM. The store uses it to read
// back the tip and any accepted block, so there is one decoder rather than one
// per call site.
func (vm *VM) parseBlock(raw []byte) (*Block, error) {
	var block Block
	if err := parseBlock(raw, &block); err != nil {
		return nil, err
	}
	block.vm = vm
	block.bytes = raw
	block.status = choices.Accepted
	return &block, nil
}

// credentialKey is where a credential is recorded.
func credentialKey(id ids.ID) []byte {
	return append(append([]byte(nil), credentialPrefix...), id[:]...)
}

// SetState implements chain.ChainVM
func (vm *VM) SetState(ctx context.Context, state uint32) error {
	return nil
}

// NewHTTPHandler implements chain.ChainVM
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

// Shutdown implements chain.ChainVM
func (vm *VM) Shutdown(ctx context.Context) error {
	vm.log.Info("IdentityVM shutting down")
	return nil
}

// CreateHandlers implements chain.ChainVM
func (vm *VM) CreateHandlers(ctx context.Context) (map[string]http.Handler, error) {
	return map[string]http.Handler{
		"/rpc": vm.rpcServer,
	}, nil
}

// HealthCheck implements chain.ChainVM
func (vm *VM) HealthCheck(ctx context.Context) (vmchain.HealthResult, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	return vmchain.HealthResult{
		Healthy: true,
		Details: map[string]string{
			"identities":  fmt.Sprintf("%d", len(vm.identities)),
			"credentials": fmt.Sprintf("%d", len(vm.credentials)),
			"issuers":     fmt.Sprintf("%d", len(vm.issuers)),
		},
	}, nil
}

// Version implements chain.ChainVM
func (vm *VM) Version(ctx context.Context) (string, error) {
	return "1.0.0", nil
}

// Connected implements chain.ChainVM
func (vm *VM) Connected(ctx context.Context, nodeID ids.NodeID, nodeVersion *vmchain.VersionInfo) error {
	vm.log.Debug("Node connected", log.String("nodeID", nodeID.String()))
	return nil
}

// Disconnected implements chain.ChainVM
func (vm *VM) Disconnected(ctx context.Context, nodeID ids.NodeID) error {
	vm.log.Debug("Node disconnected", log.String("nodeID", nodeID.String()))
	return nil
}

// BuildBlock implements chain.ChainVM. Reading the tip and registering the
// block on it happen in one step, so nothing can be accepted in between and
// leave the proposal hanging off a parent that is no longer the tip.
func (vm *VM) BuildBlock(ctx context.Context) (vmchain.Block, error) {
	built, err := vm.chain.Propose(func(parent *Block) (*Block, error) {
		// A block with nothing in it says nothing and still has to be voted on.
		creds := vm.pending.Take(0)
		if len(creds) == 0 {
			return nil, errNothingToBuild
		}
		return &Block{
			ParentID_:      parent.ID(),
			BlockHeight:    parent.Height() + 1,
			BlockTimestamp: time.Now().Unix(),
			Credentials:    creds,
			vm:             vm,
			status:         choices.Processing,
		}, nil
	})
	if err != nil {
		return nil, err
	}
	return built, nil
}

// ParseBlock implements chain.ChainVM
func (vm *VM) ParseBlock(ctx context.Context, blockBytes []byte) (vmchain.Block, error) {
	var block Block
	if err := parseBlock(blockBytes, &block); err != nil {
		return nil, err
	}

	block.vm = vm
	block.bytes = blockBytes

	return &block, nil
}

// GetBlock implements chain.ChainVM
func (vm *VM) GetBlock(ctx context.Context, blockID ids.ID) (vmchain.Block, error) {
	return vm.chain.Block(blockID, vm.parseBlock)
}

// SetPreference implements chain.ChainVM
func (vm *VM) SetPreference(ctx context.Context, blockID ids.ID) error {
	return nil
}

// LastAccepted implements chain.ChainVM
func (vm *VM) LastAccepted(ctx context.Context) (ids.ID, error) {
	id, _ := vm.chain.Tip()
	return id, nil
}

// ======== Identity Management ========

// CreateIdentity creates a new decentralized identity
func (vm *VM) CreateIdentity(publicKey []byte, metadata map[string]string) (*Identity, error) {
	vm.chain.Lock()
	defer vm.chain.Unlock()

	// Generate identity ID from public key
	h := sha256.New()
	h.Write(publicKey)
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())
	identityID := ids.ID(h.Sum(nil))

	// Generate DID
	did := fmt.Sprintf("did:lux:%s", identityID.String()[:16])

	identity := &Identity{
		ID:        identityID,
		DID:       did,
		PublicKey: publicKey,
		Created:   time.Now(),
		Updated:   time.Now(),
		Metadata:  metadata,
		Services:  make([]ServiceEndpoint, 0),
	}

	vm.identities[identityID] = identity

	// Persist (native ZAP wire)
	identityBytes := marshalIdentity(identity)
	key := append(identityPrefix, identityID[:]...)
	if err := vm.chain.Base().Put(key, identityBytes); err != nil {
		return nil, err
	}

	return identity, nil
}

// GetIdentity returns an identity by ID
func (vm *VM) GetIdentity(identityID ids.ID) (*Identity, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	identity, ok := vm.identities[identityID]
	if !ok {
		return nil, errUnknownIdentity
	}
	return identity, nil
}

// ResolveIdentity resolves an identity by DID
func (vm *VM) ResolveIdentity(did string) (*Identity, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	for _, identity := range vm.identities {
		if identity.DID == did {
			return identity, nil
		}
	}
	return nil, errUnknownIdentity
}

// ======== Credential Management ========

// IssueCredential issues a new verifiable credential
func (vm *VM) IssueCredential(issuerID, subjectID ids.ID, credType []string, claims map[string]interface{}, ttl time.Duration) (*Credential, error) {
	vm.chain.Lock()
	defer vm.chain.Unlock()

	// Verify issuer exists and is authorized
	issuer, ok := vm.issuers[issuerID]
	if !ok && !vm.config.AllowSelfIssue {
		return nil, errNotIssuer
	}

	if issuer != nil && issuer.Status != "active" {
		return nil, errNotIssuer
	}

	// Verify subject exists
	if _, ok := vm.identities[subjectID]; !ok {
		return nil, errUnknownIdentity
	}

	// Verify claims count
	if len(claims) > vm.config.MaxClaims {
		return nil, errors.New("too many claims")
	}

	// Generate credential ID
	h := sha256.New()
	h.Write(issuerID[:])
	h.Write(subjectID[:])
	binary.Write(h, binary.BigEndian, time.Now().UnixNano())
	credID := ids.ID(h.Sum(nil))

	// Calculate expiration
	expiration := time.Now().Add(ttl)
	if ttl == 0 {
		expiration = time.Now().Add(time.Duration(vm.config.CredentialTTL) * time.Second)
	}

	cred := &Credential{
		ID:             credID,
		Type:           credType,
		Issuer:         issuerID,
		Subject:        subjectID,
		IssuanceDate:   time.Now(),
		ExpirationDate: expiration,
		Claims:         claims,
		Status:         CredentialActive,
	}

	vm.credentials[credID] = cred

	// Queueing tells consensus there is a block to build; a chain builds
	// nothing until it is told.
	if err := vm.pending.Add(cred); err != nil {
		delete(vm.credentials, credID)
		return nil, err
	}

	return cred, nil
}

// GetCredential returns a credential by ID
func (vm *VM) GetCredential(credID ids.ID) (*Credential, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	cred, ok := vm.credentials[credID]
	if !ok {
		return nil, errUnknownCredential
	}

	// Check expiration
	if time.Now().After(cred.ExpirationDate) {
		cred.Status = CredentialExpired
	}

	// Check revocation
	if _, revoked := vm.revocations[credID]; revoked {
		cred.Status = CredentialRevoked
	}

	return cred, nil
}

// RevokeCredential revokes a credential
func (vm *VM) RevokeCredential(credID ids.ID, revokerID ids.ID, reason string) error {
	vm.chain.Lock()
	defer vm.chain.Unlock()

	cred, ok := vm.credentials[credID]
	if !ok {
		return errUnknownCredential
	}

	// Verify revoker is issuer or subject
	if cred.Issuer != revokerID && cred.Subject != revokerID {
		return errors.New("not authorized to revoke")
	}

	cred.Status = CredentialRevoked

	revocation := &RevocationEntry{
		CredentialID: credID,
		RevokedBy:    revokerID,
		RevokedAt:    time.Now(),
		Reason:       reason,
	}

	vm.revocations[credID] = revocation

	// Persist revocation (native ZAP wire)
	revBytes := marshalRevocation(revocation)
	key := append(revocationPrefix, credID[:]...)
	return vm.chain.Base().Put(key, revBytes)
}

// VerifyCredential verifies a credential is valid
func (vm *VM) VerifyCredential(credID ids.ID) (bool, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	cred, ok := vm.credentials[credID]
	if !ok {
		return false, errUnknownCredential
	}

	// Check status
	if cred.Status == CredentialRevoked {
		return false, errCredentialRevoked
	}

	// Check expiration
	if time.Now().After(cred.ExpirationDate) {
		return false, errCredentialExpired
	}

	// Check revocation registry
	if _, revoked := vm.revocations[credID]; revoked {
		return false, errCredentialRevoked
	}

	// When the chain requires ZK proofs, a credential must carry one. Gating the
	// requirement on cred.Proof != nil made the requirement optional: a credential
	// with no proof object at all skipped the check and verified.
	if vm.config.RequireZKProofs {
		if cred.Proof == nil || len(cred.Proof.ZKProof) == 0 {
			return false, errInvalidProof
		}
	}

	return true, nil
}

// CreateCredentialProof creates a CredentialProof artifact
func (vm *VM) CreateCredentialProof(credID ids.ID, zkProof []byte, selectiveDisclosure []string) (*artifacts.CredentialProof, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	cred, ok := vm.credentials[credID]
	if !ok {
		return nil, errUnknownCredential
	}

	// Get issuer and subject DIDs
	issuer, ok := vm.identities[cred.Issuer]
	issuerDID := ""
	if ok {
		issuerDID = issuer.DID
	}

	subject, ok := vm.identities[cred.Subject]
	subjectDID := ""
	if ok {
		subjectDID = subject.DID
	}

	// Create claims commitment
	claimsBytes, _ := json.Marshal(cred.Claims)
	claimsCommitment := sha256.Sum256(claimsBytes)

	// Determine credential type
	credType := ""
	if len(cred.Type) > 0 {
		credType = cred.Type[0]
	}

	proof := &artifacts.CredentialProof{
		Version_:         1,
		SigSuite_:        artifacts.SuitePQOnly,
		CredentialID:     credID,
		IssuerDID:        issuerDID,
		SubjectDID:       subjectDID,
		CredType:         credType,
		ClaimsCommitment: claimsCommitment,
		SelectiveProof:   zkProof,
		IssuedAt:         cred.IssuanceDate,
		ExpiresAt:        cred.ExpirationDate,
		RevocationEpoch:  cred.RevocationIndex,
	}

	return proof, nil
}

// GetBlockIDAtHeight returns the block ID at a given height
func (vm *VM) GetBlockIDAtHeight(ctx context.Context, height uint64) (ids.ID, error) {
	// Height index not implemented - return error
	return ids.Empty, errors.New("height index not implemented")
}

// WaitForEvent implements chain.ChainVM
// WaitForEvent blocks until there is a credential to build a block from, or the
// VM stops. Waiting only on the context would mean BuildBlock is never called
// and the chain never leaves genesis, however many credentials are issued.
func (vm *VM) WaitForEvent(ctx context.Context) (vmcore.Message, error) {
	return vm.pending.Wait(ctx)
}

// ======== Issuer Management ========

// RegisterIssuer registers a new credential issuer
func (vm *VM) RegisterIssuer(name string, publicKey []byte, types []string, trustLevel int) (*Issuer, error) {
	vm.chain.Lock()
	defer vm.chain.Unlock()

	// Generate issuer ID
	h := sha256.New()
	h.Write(publicKey)
	issuerID := ids.ID(h.Sum(nil))

	issuer := &Issuer{
		ID:         issuerID,
		Name:       name,
		PublicKey:  publicKey,
		Types:      types,
		TrustLevel: trustLevel,
		CreatedAt:  time.Now(),
		Status:     "active",
	}

	vm.issuers[issuerID] = issuer

	// Persist
	issuerBytes, _ := json.Marshal(issuer)
	key := append(issuerPrefix, issuerID[:]...)
	if err := vm.chain.Base().Put(key, issuerBytes); err != nil {
		return nil, err
	}

	return issuer, nil
}

// GetIssuer returns an issuer by ID
func (vm *VM) GetIssuer(issuerID ids.ID) (*Issuer, error) {
	vm.chain.RLock()
	defer vm.chain.RUnlock()

	issuer, ok := vm.issuers[issuerID]
	if !ok {
		return nil, errors.New("unknown issuer")
	}
	return issuer, nil
}

// ======== Genesis ========

// Genesis represents genesis data for IdentityVM
type Genesis struct {
	Timestamp  int64       `json:"timestamp"`
	Config     *Config     `json:"config,omitempty"`
	Issuers    []*Issuer   `json:"issuers,omitempty"`
	Identities []*Identity `json:"identities,omitempty"`
	Message    string      `json:"message,omitempty"`
}

// ParseGenesis parses genesis bytes
func ParseGenesis(genesisBytes []byte) (*Genesis, error) {
	var genesis Genesis
	if len(genesisBytes) > 0 {
		if err := json.Unmarshal(genesisBytes, &genesis); err != nil {
			return nil, err
		}
	}

	if genesis.Timestamp == 0 {
		genesis.Timestamp = time.Now().Unix()
	}

	return &genesis, nil
}
