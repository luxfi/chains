// Copyright (c) 2019-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco

// Package artifacts defines canonical artifact types for cross-chain settlement
// per the v1.1 Unified Quantum-Safe PoS Ecosystem specification.
//
// Each chain emits exactly one artifact type that X-Chain accepts:
//   - C → CReceipt
//   - D → DSettlementReceipt
//   - O → OracleAttestation
//   - R → VerifiedMessage
//   - I → CredentialProof
//   - T → Cert (OracleCert, RelayCert, DACert)
//   - Z → ZKProofCommitment
package artifacts

import (
	"crypto/sha256"
	"encoding/binary"
	"time"

	"github.com/luxfi/ids"
)

// VerificationMode defines how an artifact is verified
type VerificationMode uint8

const (
	// LCMode uses light-client verified headers + inclusion proofs (preferred)
	LCMode VerificationMode = iota
	// ValidityMode uses ZK validity proofs
	ValidityMode
	// AttestedMode uses threshold certificate (compatibility fallback)
	AttestedMode
)

// SignatureSuite defines the cryptographic suite used
type SignatureSuite uint8

const (
	// SuitePQOnly uses post-quantum signatures only
	SuitePQOnly SignatureSuite = iota
	// SuiteHybrid uses hybrid PQ+classical signatures
	SuiteHybrid
	// SuiteClassic uses classical signatures (legacy)
	SuiteClassic
)

// =============================================================================
// Base Artifact Interface
// =============================================================================

// Artifact is the base interface for all cross-chain artifacts
type Artifact interface {
	// ArtifactID returns the unique identifier for this artifact
	ArtifactID() ids.ID
	// DomainID returns the source domain/chain identifier
	DomainID() ids.ID
	// SchemaVersion returns the artifact schema version
	SchemaVersion() uint32
	// SignatureSuite returns the cryptographic suite used
	SignatureSuite() SignatureSuite
	// Expiry returns when this artifact expires
	Expiry() time.Time
	// Bytes returns the serialized artifact
	Bytes() []byte
}

// =============================================================================
// Domain Separators (prevent cross-domain replay)
// =============================================================================

var (
	DomainSepCReceipt           = []byte("LUX:CReceipt:v1")
	DomainSepDSettlementReceipt = []byte("LUX:DSettlementReceipt:v1")
	DomainSepOracleAttestation  = []byte("LUX:OracleAttestation:v1")
	DomainSepVerifiedMessage    = []byte("LUX:VerifiedMessage:v1")
	DomainSepCredentialProof    = []byte("LUX:CredentialProof:v1")
	DomainSepOracleCert         = []byte("LUX:OracleCert:v1")
	DomainSepRelayCert          = []byte("LUX:RelayCert:v1")
	DomainSepDACert             = []byte("LUX:DACert:v1")
	DomainSepZKProof            = []byte("LUX:ZKProofCommitment:v1")
)

// =============================================================================
// CReceipt (C-Chain → X-Chain)
// =============================================================================

// Withdrawal represents an asset withdrawal from C to X
type Withdrawal struct {
	AssetID   ids.ID `json:"assetId"`
	Amount    uint64 `json:"amount"`
	Recipient []byte `json:"recipient"` // X-Chain address
	Nonce     uint64 `json:"nonce"`
}

// FeePayment represents a fee payment to be settled on X
type FeePayment struct {
	Recipient []byte `json:"recipient"`
	Amount    uint64 `json:"amount"`
	FeeType   string `json:"feeType"` // "base", "priority", "blob"
}

// CReceipt is the canonical artifact emitted by C-Chain for X-Chain settlement
type CReceipt struct {
	// Header
	Version_   uint32         `json:"version"`
	SigSuite_  SignatureSuite `json:"sigSuite"`
	DomainID_  ids.ID         `json:"domainId"`
	Height     uint64         `json:"height"`
	Timestamp_ time.Time      `json:"timestamp"`
	ExpiryTime time.Time      `json:"expiry"`

	// State commitments
	CStateRoot   [32]byte `json:"cStateRoot"`
	DARoot       [32]byte `json:"daRoot"`
	WitnessRoot  [32]byte `json:"witnessRoot"`
	MessagesRoot [32]byte `json:"messagesOutRoot"`

	// Settlement data
	Withdrawals []Withdrawal `json:"withdrawals"`
	Fees        []FeePayment `json:"fees"`

	// Proofs
	FinalityProof  []byte `json:"finalityProof"`
	InclusionProof []byte `json:"inclusionProof"`

	// Cached
	id    ids.ID
	bytes []byte
}

func (r *CReceipt) ArtifactID() ids.ID {
	if r.id == ids.Empty {
		r.id = r.computeID()
	}
	return r.id
}

func (r *CReceipt) computeID() ids.ID {
	h := sha256.New()
	h.Write(DomainSepCReceipt)
	h.Write(r.DomainID_[:])
	binary.Write(h, binary.BigEndian, r.Height)
	h.Write(r.CStateRoot[:])
	return ids.ID(h.Sum(nil))
}

func (r *CReceipt) DomainID() ids.ID               { return r.DomainID_ }
func (r *CReceipt) SchemaVersion() uint32          { return r.Version_ }
func (r *CReceipt) SignatureSuite() SignatureSuite { return r.SigSuite_ }
func (r *CReceipt) Expiry() time.Time              { return r.ExpiryTime }
func (r *CReceipt) Bytes() []byte                  { return r.bytes }

// =============================================================================
// DSettlementReceipt (D-Chain → X-Chain)
// =============================================================================

// EscrowRef references an escrow UTXO on X-Chain
type EscrowRef struct {
	TxID        ids.ID `json:"txId"`
	OutputIndex uint32 `json:"outputIndex"`
	Amount      uint64 `json:"amount"`
	AssetID     ids.ID `json:"assetId"`
}

// TradeNetting represents netted trade outcomes
type TradeNetting struct {
	Maker      []byte `json:"maker"`
	Taker      []byte `json:"taker"`
	MakerDelta int64  `json:"makerDelta"` // Positive = receive, negative = send
	TakerDelta int64  `json:"takerDelta"`
	AssetID    ids.ID `json:"assetId"`
	TradeID    ids.ID `json:"tradeId"`
}

// DSettlementReceipt is the canonical artifact for D-Chain escrow settlement
type DSettlementReceipt struct {
	// Header
	Version_   uint32         `json:"version"`
	SigSuite_  SignatureSuite `json:"sigSuite"`
	DomainID_  ids.ID         `json:"domainId"`
	Height     uint64         `json:"height"`
	Timestamp_ time.Time      `json:"timestamp"`
	ExpiryTime time.Time      `json:"expiry"`

	// Escrow inputs (X-Chain UTXO refs)
	EscrowInputs []EscrowRef `json:"escrowInputs"`

	// Trade settlements
	TradeNettings []TradeNetting `json:"tradeNettings"`

	// Fees
	Fees []FeePayment `json:"fees"`

	// Risk checks
	RiskPolicyHash [32]byte `json:"riskPolicyHash"`

	// Proofs
	FinalityProof  []byte `json:"finalityProof"`
	InclusionProof []byte `json:"inclusionProof"`

	// Cached
	id    ids.ID
	bytes []byte
}

func (r *DSettlementReceipt) ArtifactID() ids.ID {
	if r.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepDSettlementReceipt)
		h.Write(r.DomainID_[:])
		binary.Write(h, binary.BigEndian, r.Height)
		r.id = ids.ID(h.Sum(nil))
	}
	return r.id
}

func (r *DSettlementReceipt) DomainID() ids.ID               { return r.DomainID_ }
func (r *DSettlementReceipt) SchemaVersion() uint32          { return r.Version_ }
func (r *DSettlementReceipt) SignatureSuite() SignatureSuite { return r.SigSuite_ }
func (r *DSettlementReceipt) Expiry() time.Time              { return r.ExpiryTime }
func (r *DSettlementReceipt) Bytes() []byte                  { return r.bytes }

// =============================================================================
// OracleAttestation (O-Chain → X-Chain)
// =============================================================================

// OracleAttestation is the canonical artifact for oracle data feeds
type OracleAttestation struct {
	// Header
	Version_  uint32         `json:"version"`
	SigSuite_ SignatureSuite `json:"sigSuite"`
	DomainID_ ids.ID         `json:"domainId"`

	// Feed identification
	FeedID ids.ID `json:"feedId"`
	Epoch  uint64 `json:"epoch"`

	// Value (can be plain or committed)
	Value           []byte   `json:"value,omitempty"`
	ValueCommitment [32]byte `json:"valueCommitment,omitempty"`

	// Aggregation proof (optional ZK proof of correct aggregation)
	AggProof []byte `json:"aggProof,omitempty"`

	// Quorum certificate (optional, for attested mode)
	QuorumCert []byte `json:"quorumCert,omitempty"`

	// Validity window
	ValidFrom time.Time `json:"validFrom"`
	ValidTo   time.Time `json:"validTo"`

	// Policy
	PolicyHash [32]byte `json:"policyHash"`

	// Cached
	id    ids.ID
	bytes []byte
}

func (a *OracleAttestation) ArtifactID() ids.ID {
	if a.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepOracleAttestation)
		h.Write(a.FeedID[:])
		binary.Write(h, binary.BigEndian, a.Epoch)
		a.id = ids.ID(h.Sum(nil))
	}
	return a.id
}

func (a *OracleAttestation) DomainID() ids.ID               { return a.DomainID_ }
func (a *OracleAttestation) SchemaVersion() uint32          { return a.Version_ }
func (a *OracleAttestation) SignatureSuite() SignatureSuite { return a.SigSuite_ }
func (a *OracleAttestation) Expiry() time.Time              { return a.ValidTo }
func (a *OracleAttestation) Bytes() []byte                  { return a.bytes }

// =============================================================================
// VerifiedMessage (R-Chain → X-Chain)
// =============================================================================

// MessageStatus represents the delivery status
type MessageStatus uint8

const (
	MessagePending MessageStatus = iota
	MessageDelivered
	MessageAcked
	MessageTimeout
	MessageFailed
)

// VerifiedMessage is the canonical artifact for cross-chain messages
type VerifiedMessage struct {
	// Header
	Version_  uint32         `json:"version"`
	SigSuite_ SignatureSuite `json:"sigSuite"`

	// Message envelope
	SrcDomain   ids.ID `json:"srcDomain"`
	DstDomain   ids.ID `json:"dstDomain"`
	Nonce       uint64 `json:"nonce"`
	PayloadType string `json:"payloadType"`
	Payload     []byte `json:"payload"`
	Fee         uint64 `json:"fee"`
	Timeout     uint64 `json:"timeout"` // Block height

	// Verification mode
	Mode VerificationMode `json:"mode"`

	// Proofs (based on mode)
	SrcFinalityProof  []byte `json:"srcFinalityProof,omitempty"`
	SrcInclusionProof []byte `json:"srcInclusionProof,omitempty"`
	ValidityProof     []byte `json:"validityProof,omitempty"`
	RelayCert         []byte `json:"relayCert,omitempty"`

	// Status
	Status    MessageStatus `json:"status"`
	Timestamp time.Time     `json:"timestamp"`

	// Cached
	id    ids.ID
	bytes []byte
}

func (m *VerifiedMessage) ArtifactID() ids.ID {
	if m.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepVerifiedMessage)
		h.Write(m.SrcDomain[:])
		h.Write(m.DstDomain[:])
		binary.Write(h, binary.BigEndian, m.Nonce)
		m.id = ids.ID(h.Sum(nil))
	}
	return m.id
}

func (m *VerifiedMessage) DomainID() ids.ID               { return m.SrcDomain }
func (m *VerifiedMessage) SchemaVersion() uint32          { return m.Version_ }
func (m *VerifiedMessage) SignatureSuite() SignatureSuite { return m.SigSuite_ }
func (m *VerifiedMessage) Expiry() time.Time {
	return m.Timestamp.Add(time.Duration(m.Timeout) * time.Second)
}
func (m *VerifiedMessage) Bytes() []byte { return m.bytes }

// =============================================================================
// CredentialProof (I-Chain → X-Chain)
// =============================================================================

// CredentialProof is the canonical artifact for identity credentials
type CredentialProof struct {
	// Header
	Version_  uint32         `json:"version"`
	SigSuite_ SignatureSuite `json:"sigSuite"`
	DomainID_ ids.ID         `json:"domainId"`

	// Credential identification
	CredentialID ids.ID `json:"credentialId"`
	IssuerDID    string `json:"issuerDid"`
	SubjectDID   string `json:"subjectDid"`
	CredType     string `json:"credentialType"`

	// Claims (can be plain or selectively disclosed via ZK)
	Claims           map[string][]byte `json:"claims,omitempty"`
	ClaimsCommitment [32]byte          `json:"claimsCommitment,omitempty"`
	SelectiveProof   []byte            `json:"selectiveProof,omitempty"`

	// Trust policy
	IssuerTrustPolicy [32]byte `json:"issuerTrustPolicy"`

	// Freshness
	IssuedAt  time.Time `json:"issuedAt"`
	ExpiresAt time.Time `json:"expiresAt"`

	// Non-revocation proof
	RevocationProof []byte `json:"revocationProof,omitempty"`
	RevocationEpoch uint64 `json:"revocationEpoch"`

	// Subject binding (key ownership proof)
	SubjectBinding []byte `json:"subjectBinding"`

	// Cached
	id    ids.ID
	bytes []byte
}

func (c *CredentialProof) ArtifactID() ids.ID {
	if c.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepCredentialProof)
		h.Write(c.CredentialID[:])
		h.Write([]byte(c.IssuerDID))
		c.id = ids.ID(h.Sum(nil))
	}
	return c.id
}

func (c *CredentialProof) DomainID() ids.ID               { return c.DomainID_ }
func (c *CredentialProof) SchemaVersion() uint32          { return c.Version_ }
func (c *CredentialProof) SignatureSuite() SignatureSuite { return c.SigSuite_ }
func (c *CredentialProof) Expiry() time.Time              { return c.ExpiresAt }
func (c *CredentialProof) Bytes() []byte                  { return c.bytes }

// =============================================================================
// Cert Types (T-Chain → Various)
// =============================================================================

// OracleCert attests that a quorum signed an oracle attestation
type OracleCert struct {
	Version_  uint32         `json:"version"`
	SigSuite_ SignatureSuite `json:"sigSuite"`
	DomainID_ ids.ID         `json:"domainId"`

	FeedID          ids.ID   `json:"feedId"`
	Epoch           uint64   `json:"epoch"`
	AttestationHash [32]byte `json:"attestationHash"`

	// Quorum signatures
	Signers    []ids.NodeID `json:"signers"`
	Signatures [][]byte     `json:"signatures"`
	Threshold  uint32       `json:"threshold"`

	Timestamp time.Time `json:"timestamp"`
	ExpiresAt time.Time `json:"expiresAt"`

	id    ids.ID
	bytes []byte
}

func (c *OracleCert) ArtifactID() ids.ID {
	if c.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepOracleCert)
		h.Write(c.FeedID[:])
		binary.Write(h, binary.BigEndian, c.Epoch)
		c.id = ids.ID(h.Sum(nil))
	}
	return c.id
}

func (c *OracleCert) DomainID() ids.ID               { return c.DomainID_ }
func (c *OracleCert) SchemaVersion() uint32          { return c.Version_ }
func (c *OracleCert) SignatureSuite() SignatureSuite { return c.SigSuite_ }
func (c *OracleCert) Expiry() time.Time              { return c.ExpiresAt }
func (c *OracleCert) Bytes() []byte                  { return c.bytes }

// RelayCert attests that a quorum verified a message batch
type RelayCert struct {
	Version_  uint32         `json:"version"`
	SigSuite_ SignatureSuite `json:"sigSuite"`
	DomainID_ ids.ID         `json:"domainId"`

	SrcDomain    ids.ID   `json:"srcDomain"`
	MsgBatchHash [32]byte `json:"msgBatchHash"`

	// Quorum signatures
	Signers    []ids.NodeID `json:"signers"`
	Signatures [][]byte     `json:"signatures"`
	Threshold  uint32       `json:"threshold"`

	// Risk bounds (for attested mode)
	ValueCap      uint64 `json:"valueCap"`
	MinDelay      uint64 `json:"minDelay"`
	EmergencyHalt bool   `json:"emergencyHalt"`

	Timestamp time.Time `json:"timestamp"`
	ExpiresAt time.Time `json:"expiresAt"`

	id    ids.ID
	bytes []byte
}

func (c *RelayCert) ArtifactID() ids.ID {
	if c.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepRelayCert)
		h.Write(c.SrcDomain[:])
		h.Write(c.MsgBatchHash[:])
		c.id = ids.ID(h.Sum(nil))
	}
	return c.id
}

func (c *RelayCert) DomainID() ids.ID               { return c.DomainID_ }
func (c *RelayCert) SchemaVersion() uint32          { return c.Version_ }
func (c *RelayCert) SignatureSuite() SignatureSuite { return c.SigSuite_ }
func (c *RelayCert) Expiry() time.Time              { return c.ExpiresAt }
func (c *RelayCert) Bytes() []byte                  { return c.bytes }

// DACert aggregates DA sampling evidence
type DACert struct {
	Version_  uint32         `json:"version"`
	SigSuite_ SignatureSuite `json:"sigSuite"`
	DomainID_ ids.ID         `json:"domainId"`

	ChainID ids.ID   `json:"chainId"`
	Height  uint64   `json:"height"`
	DARoot  [32]byte `json:"daRoot"`

	// Sampling evidence
	SampleCount uint32       `json:"sampleCount"`
	Samplers    []ids.NodeID `json:"samplers"`
	Signatures  [][]byte     `json:"signatures"`
	Threshold   uint32       `json:"threshold"`

	Timestamp time.Time `json:"timestamp"`
	ExpiresAt time.Time `json:"expiresAt"`

	id    ids.ID
	bytes []byte
}

func (c *DACert) ArtifactID() ids.ID {
	if c.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepDACert)
		h.Write(c.ChainID[:])
		binary.Write(h, binary.BigEndian, c.Height)
		c.id = ids.ID(h.Sum(nil))
	}
	return c.id
}

func (c *DACert) DomainID() ids.ID               { return c.DomainID_ }
func (c *DACert) SchemaVersion() uint32          { return c.Version_ }
func (c *DACert) SignatureSuite() SignatureSuite { return c.SigSuite_ }
func (c *DACert) Expiry() time.Time              { return c.ExpiresAt }
func (c *DACert) Bytes() []byte                  { return c.bytes }

// =============================================================================
// ZKProofCommitment (Z-Chain → X/C)
// =============================================================================

// ZKProofCommitment is the canonical artifact for ZK proofs
type ZKProofCommitment struct {
	Version_  uint32         `json:"version"`
	SigSuite_ SignatureSuite `json:"sigSuite"`
	DomainID_ ids.ID         `json:"domainId"`

	// Proof identification
	ProofID   ids.ID `json:"proofId"`
	ProofType string `json:"proofType"` // groth16, plonk, stark, bulletproof

	// Commitments
	ProofCommitment  [32]byte `json:"proofCommitment"`
	PublicInputsHash [32]byte `json:"publicInputsHash"`
	VerifyingKeyHash [32]byte `json:"verifyingKeyHash"`

	// The actual proof (can be large)
	ProofData    []byte   `json:"proofData"`
	PublicInputs [][]byte `json:"publicInputs"`

	// Verification status
	Verified   bool      `json:"verified"`
	VerifiedAt time.Time `json:"verifiedAt,omitempty"`
	VerifiedBy ids.ID    `json:"verifiedBy,omitempty"`

	Timestamp time.Time `json:"timestamp"`
	ExpiresAt time.Time `json:"expiresAt"`

	id    ids.ID
	bytes []byte
}

func (z *ZKProofCommitment) ArtifactID() ids.ID {
	if z.id == ids.Empty {
		h := sha256.New()
		h.Write(DomainSepZKProof)
		h.Write(z.ProofID[:])
		h.Write(z.ProofCommitment[:])
		z.id = ids.ID(h.Sum(nil))
	}
	return z.id
}

func (z *ZKProofCommitment) DomainID() ids.ID               { return z.DomainID_ }
func (z *ZKProofCommitment) SchemaVersion() uint32          { return z.Version_ }
func (z *ZKProofCommitment) SignatureSuite() SignatureSuite { return z.SigSuite_ }
func (z *ZKProofCommitment) Expiry() time.Time              { return z.ExpiresAt }
func (z *ZKProofCommitment) Bytes() []byte                  { return z.bytes }
