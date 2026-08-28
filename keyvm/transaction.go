// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package keyvm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
)

// Transaction types. Each is a MUTATING operation that may only take effect
// through a fee-settled consensus block — never through a synchronous RPC.
const (
	TxRegisterKey uint8 = 1 // record a key's PUBLIC material + commitments + policy
	TxSetPolicy   uint8 = 2 // update a key's authorization policy
	TxAuthorize   uint8 = 3 // authorize (trigger) a committee ceremony: dkg/sign/reshare
	TxRevokeKey   uint8 = 4 // revoke a key
)

// payerAuthMode is the algorithm K uses to authenticate a transaction's payer.
// It is the platform service-identity scheme (ML-DSA-65). Authentication is a
// PUBLIC operation: K parses the payer's public key and verifies a signature;
// it never possesses the payer's secret.
const payerAuthMode = mldsa.MLDSA65

// Transaction is a K-Chain consensus transaction. Its header is deterministic
// binary; Payload is an opaque, PUBLIC, op-specific JSON blob; Auth is the
// payer's ML-DSA-65 public key and Sig the payer's signature over the signing
// bytes. Nothing here is or can become secret material.
type Transaction struct {
	Type      uint8
	Algorithm string      // key algorithm (drives per-algorithm gas); "" for policy-only ops
	Payer     fee.Account // fee payer + authorization subject (public address)
	KeyID     ids.ID      // target key (RegisterKey derives it; others reference it)
	GasLimit  uint64      // payer-declared gas ceiling for this tx
	Nonce     uint64      // payer replay/uniqueness nonce
	Payload   []byte      // op-specific PUBLIC encoding
	Auth      []byte      // payer ML-DSA-65 PUBLIC key
	Sig       []byte      // payer signature over SigningBytes()

	id ids.ID // cached, computed from full Bytes()
}

// Operation payloads. All fields are PUBLIC.

// RegisterKeyPayload records the PUBLIC result of an off-K DKG (or anchors a new
// key): its public key, threshold parameters, VSS commitments, the committee
// that holds the shares off-K, and the initial policy. No shares appear here.
type RegisterKeyPayload struct {
	Name        string       `json:"name"`
	PublicKey   []byte       `json:"publicKey"`
	Threshold   uint32       `json:"threshold"`
	TotalShares uint32       `json:"totalShares"`
	Commitments [][]byte     `json:"commitments"`
	Committee   []ids.NodeID `json:"committee"`
	Policy      AuthPolicy   `json:"policy"`
}

// SetPolicyPayload replaces a key's authorization policy.
type SetPolicyPayload struct {
	Policy AuthPolicy `json:"policy"`
}

// AuthorizePayload triggers a committee ceremony. Message is the PUBLIC digest
// to be signed (for sign ceremonies); empty for dkg/reshare.
type AuthorizePayload struct {
	Ceremony string `json:"ceremony"` // CeremonyDKG | CeremonySign | CeremonyReshare
	Message  []byte `json:"message"`
}

// RevokePayload revokes a key.
type RevokePayload struct {
	Reason string `json:"reason"`
}

// ID returns the transaction's content hash (over the full Bytes).
func (tx *Transaction) ID() ids.ID {
	if tx.id == ids.Empty {
		tx.id = ids.ID(sha256.Sum256(tx.Bytes()))
	}
	return tx.id
}

// addressOf derives a payer account from an ML-DSA public key. K is internally
// consistent: it derives the same address it checks a payer against. This is a
// PUBLIC, one-way derivation (no secret involved).
func addressOf(pub []byte) fee.Account {
	h := sha256.Sum256(pub)
	var a fee.Account
	copy(a[:], h[:ids.ShortIDLen])
	return a
}

// SyntacticVerify checks the transaction is well-formed and priceable, without
// any state. It rejects unknown types, unpriceable algorithms, and undecodable
// or out-of-range payloads — all fail-closed.
func (tx *Transaction) SyntacticVerify() error {
	switch tx.Type {
	case TxRegisterKey, TxSetPolicy, TxAuthorize, TxRevokeKey:
	default:
		return ErrInvalidTxType
	}
	// Pricing also validates the algorithm membership for algorithm-bearing ops.
	if _, err := GasFor(tx); err != nil {
		return err
	}
	switch tx.Type {
	case TxRegisterKey:
		var p RegisterKeyPayload
		if err := json.Unmarshal(tx.Payload, &p); err != nil {
			return fmt.Errorf("keyvm: %w: register: %v", ErrInvalidPayload, err)
		}
		if p.Name == "" || len(p.PublicKey) == 0 {
			return fmt.Errorf("keyvm: %w: register: empty name or public key", ErrInvalidPayload)
		}
		if p.Threshold == 0 || p.TotalShares == 0 || p.Threshold > p.TotalShares {
			return fmt.Errorf("keyvm: %w: t=%d n=%d", ErrInvalidThreshold, p.Threshold, p.TotalShares)
		}
		if len(p.Commitments) == 0 {
			return fmt.Errorf("keyvm: %w: register: no commitments", ErrInvalidPayload)
		}
	case TxSetPolicy:
		var p SetPolicyPayload
		if err := json.Unmarshal(tx.Payload, &p); err != nil {
			return fmt.Errorf("keyvm: %w: setpolicy: %v", ErrInvalidPayload, err)
		}
	case TxAuthorize:
		var p AuthorizePayload
		if err := json.Unmarshal(tx.Payload, &p); err != nil {
			return fmt.Errorf("keyvm: %w: authorize: %v", ErrInvalidPayload, err)
		}
		switch p.Ceremony {
		case CeremonyDKG, CeremonySign, CeremonyReshare:
		default:
			return fmt.Errorf("keyvm: %w: %q", ErrInvalidCeremony, p.Ceremony)
		}
	case TxRevokeKey:
		var p RevokePayload
		if err := json.Unmarshal(tx.Payload, &p); err != nil {
			return fmt.Errorf("keyvm: %w: revoke: %v", ErrInvalidPayload, err)
		}
	}
	return nil
}

// authenticate verifies the payer authorized this transaction. PUBLIC ONLY:
// parse the payer's ML-DSA-65 public key, require it hashes to Payer, and verify
// the signature over SigningBytes. No secret material is touched.
func (tx *Transaction) authenticate() error {
	if len(tx.Auth) == 0 || len(tx.Sig) == 0 {
		return ErrUnsignedTx
	}
	if addressOf(tx.Auth) != tx.Payer {
		return ErrPayerMismatch
	}
	pub, err := mldsa.PublicKeyFromBytes(tx.Auth, payerAuthMode)
	if err != nil {
		return fmt.Errorf("keyvm: payer public key: %w", err)
	}
	if !pub.VerifySignature(tx.SigningBytes(), tx.Sig) {
		return ErrBadSignature
	}
	return nil
}

func deriveKeyID(name string) ids.ID {
	return ids.ID(sha256.Sum256([]byte("keyvm/key/" + name)))
}

// checkAuth is the single, read-only authorization predicate for a transaction:
// it decides whether tx may take effect against the CURRENT committed state at
// time now, and RESOLVES the key record the operation targets. It mutates
// nothing. It is the one place the policy model is enforced, called at three
// layers so unauthorized transactions are rejected at the earliest gate and
// never charged: admission (SubmitTx), block assembly (BuildBlock) and consensus
// (Block.Verify). Apply then works from the record this returned rather than
// resolving and re-authorizing it a second time — one resolution, one decision.
// A registration has no target record yet, so it resolves to nil. The caller
// holds the appropriate stateLock.
func (tx *Transaction) checkAuth(vm *VM, now int64) (*KeyRecord, error) {
	switch tx.Type {
	case TxRegisterKey:
		var p RegisterKeyPayload
		if err := json.Unmarshal(tx.Payload, &p); err != nil {
			return nil, fmt.Errorf("keyvm: %w: register", ErrInvalidPayload)
		}
		if _, ok := vm.getKey(deriveKeyID(p.Name)); ok {
			return nil, ErrKeyExists
		}
		return nil, nil
	case TxSetPolicy:
		rec, ok := vm.getKey(tx.KeyID)
		if !ok {
			return nil, ErrKeyNotFound
		}
		if rec.Status != StatusActive {
			return nil, ErrKeyRevoked
		}
		if !rec.Policy.MayAdmin(tx.Payer) {
			return nil, ErrUnauthorized
		}
		return rec, nil
	case TxAuthorize:
		rec, ok := vm.getKey(tx.KeyID)
		if !ok {
			return nil, ErrKeyNotFound
		}
		if rec.Status != StatusActive {
			return nil, ErrKeyRevoked
		}
		if !rec.Policy.MayInvoke(tx.Payer, now) {
			return nil, ErrUnauthorized
		}
		return rec, nil
	case TxRevokeKey:
		rec, ok := vm.getKey(tx.KeyID)
		if !ok {
			return nil, ErrKeyNotFound
		}
		if !rec.Policy.MayAdmin(tx.Payer) {
			return nil, ErrUnauthorized
		}
		return rec, nil
	default:
		return nil, ErrInvalidTxType
	}
}

// Apply mutates VM state for an already-verified, already-paid transaction. It
// runs inside block.Accept, writing through the VM's versiondb so the effect
// commits atomically with the fee burn. now is the accepting block's unix time.
// It authorizes through checkAuth and applies to the record checkAuth resolved.
func (tx *Transaction) Apply(vm *VM, now int64) error {
	rec, err := tx.checkAuth(vm, now)
	if err != nil {
		return err
	}
	switch tx.Type {
	case TxRegisterKey:
		return tx.applyRegister(vm, now)
	case TxSetPolicy:
		return tx.applySetPolicy(vm, now, rec)
	case TxAuthorize:
		return tx.applyAuthorize(vm, now)
	case TxRevokeKey:
		return tx.applyRevoke(vm, now, rec)
	}
	// checkAuth is the type gate, so no other value reaches here. The arm stays
	// because a fifth operation added to checkAuth and not to this switch must
	// fail closed, never fall through into whichever apply sits last.
	return ErrInvalidTxType
}

func (tx *Transaction) applyRegister(vm *VM, now int64) error {
	var p RegisterKeyPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("keyvm: %w: register", ErrInvalidPayload)
	}
	// The registrant is always an admin of the key it registers, so it can never
	// lock itself out (fail-secure default).
	policy := p.Policy
	if !policy.MayAdmin(tx.Payer) {
		policy.Admins = append(policy.Admins, tx.Payer)
	}
	rec := &KeyRecord{
		ID:          deriveKeyID(p.Name),
		Name:        p.Name,
		Algorithm:   tx.Algorithm,
		PublicKey:   p.PublicKey,
		Threshold:   p.Threshold,
		TotalShares: p.TotalShares,
		Commitments: p.Commitments,
		Committee:   p.Committee,
		Policy:      policy,
		Owner:       tx.Payer,
		Status:      StatusActive,
		CreatedAt:   now,
		UpdatedAt:   now,
	}
	return vm.putKey(rec)
}

func (tx *Transaction) applySetPolicy(vm *VM, now int64, rec *KeyRecord) error {
	var p SetPolicyPayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("keyvm: %w: setpolicy", ErrInvalidPayload)
	}
	// The owner remains an admin no matter what the new policy says — a key's
	// owner can never be evicted by a policy update (fail-secure).
	newPolicy := p.Policy
	if !newPolicy.MayAdmin(rec.Owner) {
		newPolicy.Admins = append(newPolicy.Admins, rec.Owner)
	}
	rec.Policy = newPolicy
	rec.UpdatedAt = now
	return vm.putKey(rec)
}

func (tx *Transaction) applyAuthorize(vm *VM, now int64) error {
	var p AuthorizePayload
	if err := json.Unmarshal(tx.Payload, &p); err != nil {
		return fmt.Errorf("keyvm: %w: authorize", ErrInvalidPayload)
	}
	// CeremonyID binds key, requester, nonce and message so it is unique and
	// auditable. K records the AUTHORIZATION; the committee fulfils it off-K.
	var seed []byte
	seed = append(seed, tx.KeyID[:]...)
	seed = append(seed, tx.Payer[:]...)
	var nb [8]byte
	binary.BigEndian.PutUint64(nb[:], tx.Nonce)
	seed = append(seed, nb[:]...)
	seed = append(seed, p.Message...)
	c := &CeremonyRecord{
		ID:        ids.ID(sha256.Sum256(seed)),
		KeyID:     tx.KeyID,
		Type:      p.Ceremony,
		Requester: tx.Payer,
		Message:   p.Message,
		Status:    CeremonyAuthorized,
		CreatedAt: now,
	}
	return vm.putCeremony(c)
}

func (tx *Transaction) applyRevoke(vm *VM, now int64, rec *KeyRecord) error {
	rec.Status = StatusRevoked
	rec.UpdatedAt = now
	return vm.putKey(rec)
}
