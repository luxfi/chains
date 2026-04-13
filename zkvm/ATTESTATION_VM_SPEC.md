# Z/A-Chain: AttestationVM + ZK Coprocessor Specification

**Version**: 1.0.0-mainnet  
**Status**: Implementation Phase  
**Target**: Lux Mainnet Launch

---

## Executive Summary

The **Z/A-Chain** (Attestation + ZK Chain) combines **zero-knowledge privacy** with **AI attestation verification** to create a quantum-safe, privacy-preserving attestation layer for Lux Network.

### Core Functions
1. **ZK Privacy Coprocessor**: Confidential transactions using ZK-SNARKs
2. **AI Attestation Verifier**: On-chain verification of Hanzo.network AI compute proofs
3. **Global Attestation Registry**: Immutable record of verified AI inferences, models, and datasets

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                  Z/A-Chain (ZVM)                        │
│  ┌──────────────────────────────────────────────────┐  │
│  │         Attestation Registry Layer               │  │
│  │  - Provider DIDs                                 │  │
│  │  - Model hashes                                  │  │
│  │  - Dataset commitments                           │  │
│  │  - Inference receipts                            │  │
│  └─────────┬────────────────────────────────────────┘  │
│            │                                            │
│  ┌─────────▼────────────────────────────────────────┐  │
│  │         ZK Verification Layer                    │  │
│  │  - Groth16 verifier (commit-only v1)            │  │
│  │  - Plonk verifier (future)                       │  │
│  │  - Receipt circuit: Hash(input+model+output)     │  │
│  └─────────┬────────────────────────────────────────┘  │
│            │                                            │
│  ┌─────────▼────────────────────────────────────────┐  │
│  │         State Management Layer                   │  │
│  │  - UTXO DB (confidential outputs)                │  │
│  │  - Nullifier DB (double-spend prevention)        │  │
│  │  - Merkle State Tree (commitments)               │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
            ▲                           │
            │ Receipts                  │ Verified
            │                           ▼ Attestations
    ┌───────┴────────┐         ┌───────────────┐
    │ Hanzo.network  │         │  P-Chain      │
    │ (Compute)      │         │  (Oracle)     │
    └────────────────┘         └───────────────┘
```

---

## Transaction Types

### 1. Attestation Transactions

#### `RegisterProviderTx`
Registers an AI compute provider on-chain.

```go
type RegisterProviderTx struct {
    ProviderDID     string        // Decentralized Identifier
    PublicKey       []byte        // Provider's public key
    GPUSpecs        []GPUSpec     // Compute capacity
    TEEAttestation  []byte        // Optional TEE attestation
    StakeBond       uint64        // Required stake (100 LUX minimum)
    Signature       []byte        // Provider signature
}
```

**Validation**:
- Provider DID unique
- Stake ≥ 100 LUX
- Valid signature
- TEE attestation valid (if provided)

#### `SubmitReceiptTx`  
Submits an AI inference receipt for verification.

```go
type SubmitReceiptTx struct {
    JobID           ids.ID        // Unique job identifier
    ProviderDID     string        // Provider who executed job
    ModelHash       [32]byte      // SHA256(model_weights)
    DatasetHash     [32]byte      // SHA256(input_data)
    OutputHash      [32]byte      // SHA256(inference_result)
    Proof           []byte        // ZK-SNARK proof
    Timestamp       int64         // Execution timestamp
    Fee             uint64        // Fee in LUX
    Signature       []byte        // Provider signature
}
```

**ZK Circuit (Receipt Circuit v1 - Commit-Only)**:
```
Public Inputs:
  - job_id
  - provider_did
  - timestamp

Private Inputs:
  - model_weights
  - input_data  
  - inference_result

Circuit Constraints:
  1. Hash(model_weights) == model_hash (public)
  2. Hash(input_data) == dataset_hash (public)
  3. Hash(inference_result) == output_hash (public)
  4. Inference_result == Model(input_data) [future: in-circuit]
```

**Validation**:
- Provider registered
- Proof verifies with Groth16/Plonk
- Fee sufficient
- No duplicate job_id

#### `ChallengeTx`
Challenges an attestation as fraudulent.

```go
type ChallengeTx struct {
    ReceiptID       ids.ID        // Receipt being challenged
    ChallengerDID   string        // Challenger identity
    CounterProof    []byte        // Alternative proof
    BondAmount      uint64        // Challenge bond (50 LUX)
    Reason          string        // Challenge reason
    Signature       []byte        // Challenger signature
}
```

**Challenge Period**: 1000 blocks (~2 hours)  
**Resolution**:
- Valid challenge: Challenger gets provider stake
- Invalid challenge: Challenger loses bond

#### `SettlementTx`
Resolves a challenge through committee vote or timeout.

```go
type SettlementTx struct {
    ChallengeID     ids.ID        // Challenge being resolved
    Decision        bool          // true = challenge valid
    Evidence        []byte        // Evidence for decision
    CommitteeVotes  []Vote        // Committee signatures
}
```

### 2. Privacy Transactions

#### `ConfidentialTransferTx`
ZK-private asset transfer.

```go
type ConfidentialTransferTx struct {
    Nullifiers      [][32]byte    // Spent UTXO nullifiers
    Commitments     [][32]byte    // New UTXO commitments
    OutputNotes     []EncryptedNote // Encrypted output notes
    RangeProof      []byte        // Proves values non-negative
    ZKProof         []byte        // ZK-SNARK transfer proof
    Fee             uint64        // Public fee
}
```

---

## State Model

### UTXO Model
```go
type UTXO struct {
    TxID           ids.ID        // Creating transaction
    OutputIndex    uint32        // Output index in tx
    Commitment     [32]byte      // Pedersen commitment
    Ciphertext     []byte        // Encrypted note
    EphemeralPK    []byte        // Ephemeral public key
    Height         uint64        // Block height created
}
```

### Nullifier Model
```go
type Nullifier struct {
    Hash           [32]byte      // PRF(spend_key, serial)
    SpentAt        uint64        // Block height spent
    TxID           ids.ID        // Spending transaction
}
```

### Attestation Registry
```go
type AttestationRecord struct {
    JobID          ids.ID        // Unique job ID
    ProviderDID    string        // Provider identity
    ModelHash      [32]byte      // Model commitment
    DatasetHash    [32]byte      // Input commitment
    OutputHash     [32]byte      // Result commitment
    ProofHash      [32]byte      // ZK proof hash
    Timestamp      int64         // Attestation time
    Status         AttestStatus  // Pending/Verified/Challenged/Invalid
    ChallengeID    *ids.ID       // Challenge (if any)
}

type AttestStatus uint8
const (
    AttestPending    AttestStatus = 0
    AttestVerified   AttestStatus = 1
    AttestChallenged AttestStatus = 2
    AttestInvalid    AttestStatus = 3
)
```

---

## Proof Systems

### Receipt Circuit v1 (Commit-Only)
**Purpose**: Prove hash consistency without in-circuit inference  
**Proof System**: Groth16 (fast verify, ~200ms)  
**Circuit Size**: ~100K constraints

```
Proof Statement:
  "I know (model, data, result) such that:
   Hash(model) == model_hash AND
   Hash(data) == dataset_hash AND  
   Hash(result) == output_hash"
```

### Receipt Circuit v2 (Future - Full Inference)
**Purpose**: Prove correct inference execution in-circuit  
**Proof System**: Plonk or Halo2  
**Circuit Size**: Depends on model (millions of constraints)

```
Proof Statement:
  "I executed Model(input) == output correctly"
```

### Privacy Transfer Circuit
**Purpose**: Prove valid confidential transfer  
**Proof System**: Groth16  
**Circuit Size**: ~50K constraints per input/output

```
Proof Statement:
  "I know secret keys and values such that:
   - Nullifiers are valid spends
   - Commitments are well-formed
   - Input_sum == Output_sum + Fee
   - Values are non-negative"
```

---

## Economic Model

### Fees
- **Receipt Submission**: 0.1 LUX + proof verification cost
- **Confidential Transfer**: 0.01 LUX + 0.001 LUX per input/output
- **Provider Registration**: 100 LUX stake (refundable)
- **Challenge Bond**: 50 LUX (slashed if invalid)

### Incentives
- **Providers**: Earn from Hanzo.network for compute
- **Validators**: Earn block rewards + tx fees
- **Challengers**: Earn slashed stakes for valid challenges

---

## Security Model

### Threat Model
1. **Fraudulent Attestations**: Provider submits fake proofs
2. **Double-Spend**: User tries to spend UTXO twice
3. **Challenge Spam**: Malicious challenges on valid receipts
4. **Front-Running**: MEV on attestation submissions

### Mitigations
1. **ZK Proofs**: Cryptographic verification of attestations
2. **Nullifier DB**: Prevents double-spends
3. **Challenge Bonds**: Economic penalty for spam
4. **Encrypted Mempools**: Prevents front-running (future)

### Quantum Resistance
- **Receipt Hashes**: SHA-256 → SHA-3 (quantum-safe)
- **Signatures**: ECDSA → ML-DSA (via P-Chain integration)
- **Commitments**: Pedersen → Lattice-based (v2)

---

## API Endpoints

### Attestation APIs
```
POST /attestation/register      - Register provider
POST /attestation/submit        - Submit receipt
POST /attestation/challenge     - Challenge receipt
GET  /attestation/query         - Query attestations
GET  /attestation/provider/:did - Get provider info
```

### Privacy APIs
```
POST /privacy/transfer          - Confidential transfer
GET  /privacy/balance           - Get shielded balance
GET  /privacy/utxos             - List available UTXOs
```

### Indexer APIs
```
GET  /index/providers           - List all providers
GET  /index/jobs                - Query job history
GET  /index/models              - List attested models
GET  /index/datasets            - List attested datasets
```

---

## Implementation Checklist

### Phase 1: Core Infrastructure (Mainnet Launch)
- [x] UTXO database
- [x] Nullifier database  
- [x] Merkle state tree
- [x] ZK proof verifier framework
- [ ] Groth16 verifier integration
- [ ] Receipt Circuit v1 implementation
- [ ] Attestation registry storage

### Phase 2: Transaction Types
- [ ] RegisterProviderTx
- [ ] SubmitReceiptTx
- [ ] ChallengeTx
- [ ] SettlementTx
- [x] ConfidentialTransferTx (base)

### Phase 3: Integration
- [ ] P-Chain PQC signature verification
- [ ] Hanzo.network receipt ingestion API
- [ ] B-Chain fee routing
- [ ] Indexer for attestation queries

### Phase 4: Advanced Features (Post-Launch)
- [ ] TEE attestation policy
- [ ] Receipt Circuit v2 (in-circuit inference)
- [ ] Encrypted mempool
- [ ] Dispute resolution DAO

---

## Testing Requirements

### Unit Tests
- UTXO/Nullifier DB operations
- State tree updates
- Transaction validation logic
- Proof verification

### Integration Tests  
- End-to-end attestation flow
- Challenge and settlement
- Confidential transfer flow
- P-Chain PQC integration

### Load Tests
- 1000 TPS attestation submission
- 100 concurrent challenges
- 10K provider registrations

### Security Tests
- Double-spend attempts
- Invalid proof submissions
- Challenge spam scenarios
- Front-running attacks

---

## Deployment Plan

1. **Testnet** (Week 1-2)
   - Deploy Z/A-Chain on testnet
   - Public bug bounty
   - Load testing

2. **Mainnet Beta** (Week 3-4)
   - Limited provider whitelist
   - Manual challenge review
   - Graduated fee reduction

3. **Mainnet General Availability** (Week 5+)
   - Open provider registration
   - Automated challenge resolution
   - Full feature set

---

## References

- [ZK-SNARK Explainer](https://z.cash/technology/zksnarks/)
- [Groth16 Paper](https://eprint.iacr.org/2016/260.pdf)
- [Zcash Sapling Protocol](https://github.com/zcash/zips/blob/master/protocol/sapling.pdf)
- [Lux Consensus](https://github.com/luxfi/consensus)
- [Hanzo AI Network](https://hanzo.ai)

---

**Maintainers**: Lux Core Team  
**Last Updated**: 2025-10-31  
**Next Review**: Pre-Mainnet Launch
