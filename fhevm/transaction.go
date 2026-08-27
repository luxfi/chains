// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/ids"
)

// Transaction types. Each is a MUTATING operation that may only take effect
// through a fee-settled consensus block — never through a synchronous RPC.
// Together they are the whole life of a confidential value on F: it is
// registered, capabilities over it are granted and revoked, its decryption is
// requested, and the committee answers; the committee that answers is itself
// rotated by the sixth.
const (
	TxRegisterCiphertext uint8 = 1 // record a ciphertext's PUBLIC handle + metadata
	TxGrantPermit        uint8 = 2 // owner grants a capability over a handle
	TxRevokePermit       uint8 = 3 // owner withdraws a capability it granted
	TxRequestDecrypt     uint8 = 4 // permitted grantee asks the committee to decrypt
	TxFulfillDecrypt     uint8 = 5 // committee member attests the PUBLIC result
	TxAdvanceEpoch       uint8 = 6 // committee installs its successor
)

// payerAuthMode is the algorithm F uses to authenticate a transaction's payer
// and to identify a committee member. It is the platform service-identity
// scheme (ML-DSA-65). Authentication is a PUBLIC operation: F parses the
// payer's public key and verifies a signature; it never possesses a secret.
const payerAuthMode = mldsa.MLDSA65

// Transaction is an F-Chain consensus transaction. Its header is deterministic
// binary; Payload is an opaque, PUBLIC, op-specific JSON blob; Auth is the
// payer's ML-DSA-65 public key and Sig the payer's signature over the signing
// bytes. Nothing here is or can become ciphertext, plaintext, or a key share.
type Transaction struct {
	Type     uint8
	Scheme   string      // FHE scheme + ring dimension (drives per-scheme gas); "" for scheme-independent ops
	Payer    fee.Account // fee payer + authorization subject (public address)
	Subject  [32]byte    // the object this operation acts on or creates (see below)
	GasLimit uint64      // payer-declared gas ceiling for this tx
	Nonce    uint64      // payer replay/uniqueness nonce
	Payload  []byte      // op-specific PUBLIC encoding
	Auth     []byte      // payer ML-DSA-65 PUBLIC key
	Sig      []byte      // payer signature over SigningBytes()

	id ids.ID // cached, computed from full Bytes()
}

// Subject names the object of the operation, and is ALWAYS checked against what
// the payload derives — so the signature covers the object, not just the
// arguments that happen to produce it:
//
//	TxRegisterCiphertext  the handle the payload's digest+scheme derive
//	TxGrantPermit         the handle being granted over
//	TxRevokePermit        the permit being withdrawn
//	TxRequestDecrypt      the handle whose decryption is asked for
//	TxFulfillDecrypt      the request being answered
//	TxAdvanceEpoch        the digest of the successor committee being approved

// Operation payloads. All fields are PUBLIC.

// RegisterPayload records an encrypted value's PUBLIC coordinates. Digest is
// the hash of the ciphertext BODY, which lives in off-chain storage — F stores
// the hash so anyone can check a fetched body against the chain, and never the
// body itself.
type RegisterPayload struct {
	Digest [32]byte `json:"digest"`
	Type   uint8    `json:"type"`  // FHE plaintext type tag (bool, uint8, …)
	Level  int      `json:"level"` // remaining multiplicative level
	Size   uint32   `json:"size"`  // ciphertext body size in bytes
}

// GrantPayload grants a capability over one handle to one grantee until Expiry.
// Operations is a bitmask of fhe.PermitOp* values.
type GrantPayload struct {
	Grantee    fee.Account `json:"grantee"`
	Operations uint32      `json:"operations"`
	Expiry     int64       `json:"expiry"` // unix seconds; 0 = no expiry
}

// RevokePayload withdraws a permit.
type RevokePayload struct {
	Reason string `json:"reason"`
}

// RequestPayload asks the committee to threshold-decrypt a handle under the
// authority of a permit the requester holds. Callback and Selector name where
// the answer should be delivered on the source chain.
type RequestPayload struct {
	PermitID [32]byte `json:"permitId"`
	Callback [20]byte `json:"callback"`
	Selector [4]byte  `json:"selector"`
	Expiry   int64    `json:"expiry"` // unix seconds; 0 = the chain's default window
}

// FulfillPayload is one committee member's attestation of the PUBLIC handle a
// threshold decryption produced. The plaintext itself is delivered off-chain to
// the callback; F records only which handle the committee agreed on.
type FulfillPayload struct {
	Result [32]byte `json:"result"`
}

// AdvancePayload proposes the next epoch's committee and the network public key
// it jointly generated. Every approving member sends the identical proposal;
// the epoch installs when Threshold of the CURRENT committee have.
type AdvancePayload struct {
	Epoch     uint64                `json:"epoch"`
	Committee []fhe.CommitteeMember `json:"committee"`
	Threshold int                   `json:"threshold"`
	PublicKey []byte                `json:"publicKey"`
}

// DefaultRequestWindow is how long a decryption request stays answerable when
// the requester names no expiry. A request that no committee can still answer
// is dead weight in state, and an unbounded one would be answerable by a future
// committee that never saw the permit that authorized it.
const DefaultRequestWindow = int64(3600)

// ID returns the transaction's content hash (over the full Bytes).
func (tx *Transaction) ID() ids.ID {
	if tx.id == ids.Empty {
		tx.id = ids.ID(sha256.Sum256(tx.Bytes()))
	}
	return tx.id
}

// addressOf derives an account from an ML-DSA public key. F is internally
// consistent: it derives the same address it checks a payer against, and the
// same address it recognises a committee member by. This is a PUBLIC, one-way
// derivation (no secret involved).
func addressOf(pub []byte) fee.Account {
	h := sha256.Sum256(pub)
	var a fee.Account
	copy(a[:], h[:ids.ShortIDLen])
	return a
}

// SyntacticVerify checks the transaction is well-formed and priceable, without
// any state. It rejects unknown types, unpriceable schemes, undecodable or
// out-of-range payloads, and any Subject that disagrees with what the payload
// derives — all fail-closed.
func (tx *Transaction) SyntacticVerify() error {
	switch tx.Type {
	case TxRegisterCiphertext, TxGrantPermit, TxRevokePermit,
		TxRequestDecrypt, TxFulfillDecrypt, TxAdvanceEpoch:
	default:
		return ErrInvalidTxType
	}
	// Pricing also validates scheme membership for scheme-bearing ops.
	if _, err := GasFor(tx); err != nil {
		return err
	}
	if tx.Nonce == 0 {
		return fmt.Errorf("fhevm: %w: nonce starts at 1", ErrBadNonce)
	}

	switch tx.Type {
	case TxRegisterCiphertext:
		p, err := decode[RegisterPayload](tx.Payload, "register")
		if err != nil {
			return err
		}
		if p.Digest == ([32]byte{}) {
			return fmt.Errorf("fhevm: %w: register: empty ciphertext digest", ErrInvalidPayload)
		}
		if p.Size == 0 {
			return fmt.Errorf("fhevm: %w: register: zero-length ciphertext", ErrInvalidPayload)
		}
		if p.Level < 0 {
			return fmt.Errorf("fhevm: %w: register: negative level", ErrInvalidPayload)
		}
		if tx.Subject != deriveHandle(p.Digest, tx.Scheme) {
			return fmt.Errorf("fhevm: %w: handle does not match digest+scheme", ErrHandleMismatch)
		}

	case TxGrantPermit:
		p, err := decode[GrantPayload](tx.Payload, "grant")
		if err != nil {
			return err
		}
		if p.Operations == 0 {
			return fmt.Errorf("fhevm: %w: grant confers no operation", ErrInvalidPayload)
		}
		if p.Operations & ^permitOpMask != 0 {
			return fmt.Errorf("fhevm: %w: unknown permit operation bits", ErrInvalidPayload)
		}
		if p.Expiry < 0 {
			return fmt.Errorf("fhevm: %w: negative expiry", ErrInvalidPayload)
		}

	case TxRevokePermit:
		if _, err := decode[RevokePayload](tx.Payload, "revoke"); err != nil {
			return err
		}

	case TxRequestDecrypt:
		p, err := decode[RequestPayload](tx.Payload, "request")
		if err != nil {
			return err
		}
		if p.PermitID == ([32]byte{}) {
			return fmt.Errorf("fhevm: %w: request names no permit", ErrInvalidPayload)
		}
		if p.Expiry < 0 {
			return fmt.Errorf("fhevm: %w: negative expiry", ErrInvalidPayload)
		}

	case TxFulfillDecrypt:
		p, err := decode[FulfillPayload](tx.Payload, "fulfill")
		if err != nil {
			return err
		}
		if p.Result == ([32]byte{}) {
			return fmt.Errorf("fhevm: %w: fulfill carries no result handle", ErrInvalidPayload)
		}

	case TxAdvanceEpoch:
		p, err := decode[AdvancePayload](tx.Payload, "advance")
		if err != nil {
			return err
		}
		if err := ValidateCommittee(p.Committee, p.Threshold, p.PublicKey); err != nil {
			return err
		}
		if tx.Subject != committeeDigest(p.Epoch, p.Threshold, p.PublicKey, p.Committee) {
			return fmt.Errorf("fhevm: %w: subject does not match the proposed committee", ErrHandleMismatch)
		}
	}
	return nil
}

// permitOpMask is every capability bit the FHE runtime defines. A grant that
// sets a bit outside it is refused rather than silently conferring nothing.
const permitOpMask = fhe.PermitOpDecrypt | fhe.PermitOpReencrypt | fhe.PermitOpCompute | fhe.PermitOpTransfer

// ValidateCommittee checks a committee is installable: non-empty, canonically
// ordered by node ID, free of duplicates, with a real threshold and with every
// member carrying a parseable ML-DSA-65 public key. The last check is what
// stops F being wedged by an epoch whose members can never sign an attestation
// — the committee that cannot speak can never be replaced either. Genesis and
// TxAdvanceEpoch both go through here, so the two can never disagree.
func ValidateCommittee(c []fhe.CommitteeMember, threshold int, publicKey []byte) error {
	if len(c) == 0 {
		return fmt.Errorf("fhevm: %w: empty committee", ErrInvalidCommittee)
	}
	if threshold <= 0 || threshold > len(c) {
		return fmt.Errorf("fhevm: %w: threshold %d of %d", ErrInvalidThreshold, threshold, len(c))
	}
	if len(publicKey) == 0 {
		return fmt.Errorf("fhevm: %w: no network public key", ErrInvalidCommittee)
	}
	if !committeeOrder(c) {
		return fmt.Errorf("fhevm: %w: members not in canonical node-ID order", ErrInvalidCommittee)
	}
	for i, m := range c {
		if i > 0 && c[i-1].NodeID == m.NodeID {
			return fmt.Errorf("fhevm: %w: duplicate member %s", ErrInvalidCommittee, m.NodeID)
		}
		if _, err := mldsa.PublicKeyFromBytes(m.PublicKey, payerAuthMode); err != nil {
			return fmt.Errorf("fhevm: %w: member %s key: %v", ErrInvalidCommittee, m.NodeID, err)
		}
	}
	return nil
}

// decode unmarshals an op payload, naming the operation in the error.
func decode[T any](payload []byte, op string) (T, error) {
	var v T
	if err := json.Unmarshal(payload, &v); err != nil {
		return v, fmt.Errorf("fhevm: %w: %s: %v", ErrInvalidPayload, op, err)
	}
	return v, nil
}

// authenticate verifies the payer authorized this transaction. PUBLIC ONLY:
// parse the payer's ML-DSA-65 public key, require it hashes to Payer, and
// verify the signature over SigningBytes. No secret material is touched.
func (tx *Transaction) authenticate() error {
	if len(tx.Auth) == 0 || len(tx.Sig) == 0 {
		return ErrUnsignedTx
	}
	if addressOf(tx.Auth) != tx.Payer {
		return ErrPayerMismatch
	}
	pub, err := mldsa.PublicKeyFromBytes(tx.Auth, payerAuthMode)
	if err != nil {
		return fmt.Errorf("fhevm: payer public key: %w", err)
	}
	if !pub.VerifySignature(tx.SigningBytes(), tx.Sig) {
		return ErrBadSignature
	}
	return nil
}

// effect names, in 32 bytes, the state entry this transaction writes — and,
// where an entry legitimately takes a write from each of several actors, which
// actor writes it. Two transactions sharing an effect cannot both take place:
// the second would find the ciphertext already registered, the permit already
// withdrawn, or the member already counted, and abort the block that carried
// them both.
//
// Nonces do not catch that on their own. A payer's nonces n and n+1 are both
// valid, so one payer can build two transactions that individually pass every
// check and together wedge a block — and since a rejected block requeues its
// contents, the same doomed pair would be rebuilt indefinitely. Naming the
// effect lets admission refuse the second before it is ever queued (vm.go
// SubmitTx) and lets consensus refuse a peer's block that contains both
// (block.go Verify). One function, both layers, no drift.
func (tx *Transaction) effect() [32]byte {
	h := sha256.New()
	h.Write([]byte{tx.Type})
	h.Write(tx.Subject[:])
	switch tx.Type {
	case TxRegisterCiphertext, TxRevokePermit:
		// The entry is named by Subject alone: one registration per handle, one
		// withdrawal per permit, whoever asks for it.

	case TxFulfillDecrypt, TxAdvanceEpoch:
		// A threshold decision takes one write per member, so the effect is the
		// member's VOTE rather than the value voted for. That is what stops a
		// member spending twice on one decision, or hedging across two values.
		h.Write(tx.Payer[:])

	default:
		// A grant and a request CREATE an entry whose id already carries the
		// payer and its nonce, so no two of them collide — the same owner may
		// grant twice over one handle, to different grantees, in one block.
		// Qualifying by the same two fields keeps that true here.
		h.Write(tx.Payer[:])
		var u8 [8]byte
		binary.BigEndian.PutUint64(u8[:], tx.Nonce)
		h.Write(u8[:])
	}
	return [32]byte(h.Sum(nil))
}

// checkAuth is the single, read-only authorization predicate for a transaction:
// it decides whether tx may take effect against the CURRENT committed state at
// time now. It mutates nothing. It is the one place F's access model is
// enforced, called at three layers so unauthorized transactions are rejected at
// the earliest gate and never charged: admission (SubmitTx), consensus
// (Block.Verify), and — as defense in depth — application (Apply). The caller
// holds the appropriate stateLock.
func (tx *Transaction) checkAuth(vm *VM, now int64) error {
	switch tx.Type {
	case TxRegisterCiphertext:
		if _, ok := vm.getCiphertext(tx.Subject); ok {
			return ErrCiphertextExists
		}
		return nil

	case TxGrantPermit:
		ct, ok := vm.getCiphertext(tx.Subject)
		if !ok {
			return ErrCiphertextNotFound
		}
		// Only the owner may confer a capability over its ciphertext — and,
		// because only the owner grants, only the owner revokes.
		if ct.Owner != tx.Payer {
			return ErrUnauthorized
		}
		return nil

	case TxRevokePermit:
		pm, ok := vm.getPermit(tx.Subject)
		if !ok {
			return ErrPermitNotFound
		}
		if pm.Status != StatusActive {
			return ErrPermitRevoked
		}
		if pm.Grantor != tx.Payer {
			return ErrUnauthorized
		}
		return nil

	case TxRequestDecrypt:
		p, err := decode[RequestPayload](tx.Payload, "request")
		if err != nil {
			return err
		}
		if _, ok := vm.getCiphertext(tx.Subject); !ok {
			return ErrCiphertextNotFound
		}
		pm, ok := vm.getPermit(p.PermitID)
		if !ok {
			return ErrPermitNotFound
		}
		if pm.Status != StatusActive {
			return ErrPermitRevoked
		}
		if pm.Handle != tx.Subject {
			return fmt.Errorf("fhevm: %w: permit is for another handle", ErrPermitInvalid)
		}
		if pm.Grantee != tx.Payer {
			return ErrUnauthorized
		}
		if pm.Expiry != 0 && now > pm.Expiry {
			return ErrPermitExpired
		}
		if pm.Operations&fhe.PermitOpDecrypt == 0 {
			return fmt.Errorf("fhevm: %w: permit does not confer decrypt", ErrPermitInvalid)
		}
		// The request's id carries the requester's nonce, and a nonce is used
		// once, so a request cannot collide with an existing one. That is the
		// whole uniqueness argument — there is no second check to keep in step
		// with it.
		return nil

	case TxFulfillDecrypt:
		req, ok := vm.getDecrypt(tx.Subject)
		if !ok {
			return ErrRequestNotFound
		}
		if req.Status != fhe.RequestPending {
			return ErrRequestClosed
		}
		if req.Expiry != 0 && now > req.Expiry {
			return ErrRequestExpired
		}
		// Only the committee of the epoch the request was made in may answer it:
		// a later committee holds different shares and never saw the permit.
		ep, ok := vm.getEpoch(req.Epoch)
		if !ok {
			return ErrEpochNotFound
		}
		if !ep.memberOf(tx.Payer) {
			return ErrNotCommittee
		}
		if attested(req.Attestations, tx.Payer) {
			return ErrAlreadyAttested
		}
		return nil

	case TxAdvanceEpoch:
		p, err := decode[AdvancePayload](tx.Payload, "advance")
		if err != nil {
			return err
		}
		cur := vm.currentEpoch()
		if p.Epoch != cur.Epoch+1 {
			return fmt.Errorf("fhevm: %w: proposed %d, next is %d", ErrEpochMismatch, p.Epoch, cur.Epoch+1)
		}
		// Only the sitting committee decides its successor.
		if !cur.memberOf(tx.Payer) {
			return ErrNotCommittee
		}
		if attested(cur.Attestations, tx.Payer) {
			return ErrAlreadyAttested
		}
		return nil

	default:
		return ErrInvalidTxType
	}
}

// Apply mutates VM state for an already-verified, already-paid transaction. It
// runs inside block.Accept, writing through the VM's versiondb so the effect
// commits atomically with the fee burn. now is the accepting block's unix time
// — every timestamp F stores comes from here, never from a validator's clock.
// It re-runs checkAuth (defense in depth) before mutating.
func (tx *Transaction) Apply(vm *VM, now int64) error {
	if err := tx.checkAuth(vm, now); err != nil {
		return err
	}
	switch tx.Type {
	case TxRegisterCiphertext:
		return tx.applyRegister(vm, now)
	case TxGrantPermit:
		return tx.applyGrant(vm, now)
	case TxRevokePermit:
		return tx.applyRevoke(vm)
	case TxRequestDecrypt:
		return tx.applyRequest(vm, now)
	case TxFulfillDecrypt:
		return tx.applyFulfill(vm, now)
	case TxAdvanceEpoch:
		return tx.applyAdvance(vm, now)
	default:
		return ErrInvalidTxType
	}
}

func (tx *Transaction) applyRegister(vm *VM, now int64) error {
	p, err := decode[RegisterPayload](tx.Payload, "register")
	if err != nil {
		return err
	}
	rec := &CiphertextRecord{
		CiphertextMeta: fhe.CiphertextMeta{
			Handle:       tx.Subject,
			Owner:        tx.Payer,
			Type:         p.Type,
			Level:        p.Level,
			Epoch:        vm.currentEpoch().Epoch,
			RegisteredAt: now,
			Size:         p.Size,
			ChainID:      vm.chainID,
		},
		Scheme: tx.Scheme,
		Digest: p.Digest,
	}
	return vm.putCiphertext(rec)
}

func (tx *Transaction) applyGrant(vm *VM, now int64) error {
	p, err := decode[GrantPayload](tx.Payload, "grant")
	if err != nil {
		return err
	}
	rec := &PermitRecord{
		Permit: fhe.Permit{
			PermitID:   derivePermitID(tx.Subject, tx.Payer, p.Grantee, p.Operations, p.Expiry, tx.Nonce),
			Handle:     tx.Subject,
			Grantee:    p.Grantee,
			Grantor:    tx.Payer,
			Operations: p.Operations,
			Expiry:     p.Expiry,
			CreatedAt:  now,
			ChainID:    vm.chainID,
		},
		Status: StatusActive,
	}
	return vm.putPermit(rec)
}

func (tx *Transaction) applyRevoke(vm *VM) error {
	pm, ok := vm.getPermit(tx.Subject)
	if !ok {
		return ErrPermitNotFound
	}
	pm.Status = StatusRevoked
	return vm.putPermit(pm)
}

func (tx *Transaction) applyRequest(vm *VM, now int64) error {
	p, err := decode[RequestPayload](tx.Payload, "request")
	if err != nil {
		return err
	}
	expiry := p.Expiry
	if expiry == 0 {
		expiry = now + DefaultRequestWindow
	}
	rec := &DecryptRecord{
		DecryptRequest: fhe.DecryptRequest{
			RequestID:        deriveRequestID(tx.Subject, tx.Payer, tx.Nonce),
			CiphertextHandle: tx.Subject,
			Requester:        tx.Payer,
			Callback:         p.Callback,
			CallbackSelector: p.Selector,
			SourceChain:      vm.chainID,
			Epoch:            vm.currentEpoch().Epoch,
			Nonce:            tx.Nonce,
			Expiry:           expiry,
			Status:           fhe.RequestPending,
			CreatedAt:        now,
		},
		PermitID: p.PermitID,
	}
	return vm.putDecrypt(rec)
}

func (tx *Transaction) applyFulfill(vm *VM, now int64) error {
	p, err := decode[FulfillPayload](tx.Payload, "fulfill")
	if err != nil {
		return err
	}
	req, ok := vm.getDecrypt(tx.Subject)
	if !ok {
		return ErrRequestNotFound
	}
	ep, ok := vm.getEpoch(req.Epoch)
	if !ok {
		return ErrEpochNotFound
	}
	req.Attestations = append(req.Attestations, Attestation{Member: tx.Payer, Value: p.Result})
	// The request completes the moment a threshold of DISTINCT members have
	// named the same handle. A member that names a different one is counted
	// against that value alone, so it delays nothing and pays for the privilege.
	if tally(req.Attestations, p.Result) >= ep.Threshold {
		req.Status = fhe.RequestCompleted
		req.ResultHandle = p.Result
		req.CompletedAt = now
	}
	return vm.putDecrypt(req)
}

func (tx *Transaction) applyAdvance(vm *VM, now int64) error {
	p, err := decode[AdvancePayload](tx.Payload, "advance")
	if err != nil {
		return err
	}
	cur := vm.currentEpoch()
	cur.Attestations = append(cur.Attestations, Attestation{Member: tx.Payer, Value: tx.Subject})
	if tally(cur.Attestations, tx.Subject) < cur.Threshold {
		// Not yet decided: record the vote against the sitting epoch and stop.
		return vm.putEpoch(cur)
	}
	// Decided. The transaction that carries the deciding vote also carries the
	// proposal itself, so no proposal body is ever stored while it is pending —
	// the digest the members attested is the whole record of what they agreed.
	cur.EndTime = now
	cur.Status = fhe.EpochEnded
	if err := vm.putEpoch(cur); err != nil {
		return err
	}
	next := &EpochRecord{EpochInfo: fhe.EpochInfo{
		Epoch:     p.Epoch,
		StartTime: now,
		Committee: p.Committee,
		Threshold: p.Threshold,
		PublicKey: p.PublicKey,
		Status:    fhe.EpochActive,
	}}
	if err := vm.putEpoch(next); err != nil {
		return err
	}
	return vm.setCurrentEpoch(p.Epoch)
}
