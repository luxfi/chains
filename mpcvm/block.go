// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// block.go — the M-Chain state transition.
//
// A block is not a log of what a proposer says happened; it is a proposed state
// transition that every validator re-checks against its own state before
// accepting. The distinction is the whole point of putting custody on a chain
// rather than in a signer cluster:
//
//   - A SIGN operation carries the signature the ceremony produced. Verify
//     re-verifies it against the group public key already in the registry. A
//     proposer cannot fabricate one, because fabricating it means forging ECDSA
//     under a key it does not hold. This check needs no participation in the
//     ceremony and no trust in the proposer — a validator that sat out the
//     ceremony entirely still verifies the result.
//
//   - A KEYGEN operation carries a proof-of-possession by the new group key
//     over the key-commit digest. Verify re-verifies it, checks the policy is
//     deployable and that the participant set matches it, and — if this
//     validator holds a share for that key — checks the record against its own
//     config. One honest participant is therefore enough to reject a key
//     registered with a wrong degree or a wrong committee.
//
//   - Every block carries the post-state root. Verify recomputes it from local
//     state plus the block's operations and rejects a mismatch, so two
//     validators that would diverge cannot both accept.
//
// A failed ceremony is not a state transition and is not recorded. Only
// outcomes that are verifiable and that change state reach a block.

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
)

// Operation kinds recorded on M-Chain.
const (
	OpTypeKeygen = "keygen"
	OpTypeSign   = "sign"
)

var (
	ErrInvalidOperation = errors.New("mpcvm: invalid operation")
	ErrBadArtifact      = errors.New("mpcvm: ceremony artifact does not verify")
	ErrQuorumTooSmall   = errors.New("mpcvm: signer set smaller than the key's policy requires")
	ErrStaleParent      = errors.New("mpcvm: parent block is not this node's applied state")
	ErrBlockTooLarge    = errors.New("mpcvm: block carries more operations than a block may")
	ErrFutureBlock      = errors.New("mpcvm: block timestamp is too far ahead of this node's clock")
)

// maxOpsPerBlock bounds the operations one block may carry.
//
// It is a CONSTANT, not configuration, because it is a consensus rule: Verify
// enforces it on every block this node receives, and a bound each operator
// could set independently would let two honestly-configured validators reach
// opposite verdicts on the same block. It bounds the work an arriving block can
// make every validator do — each sign operation costs an ECDSA verification, so
// an unbounded block is an unbounded verification cost paid by the whole
// network at whatever rate a proposer chooses.
//
// The same constant bounds assembly, so this node never builds a block its
// peers would refuse. One predicate, three places.
const maxOpsPerBlock = 64

// maxBlockBytes bounds the wire encoding a block may arrive as, checked before
// anything is decoded. maxOpsPerBlock operations of the largest shape M-Chain
// produces — a keygen carrying a key record with N party ids — is on the order
// of 50 KiB, so this is roughly twenty times the largest honest block and still
// small enough that a peer cannot make this node allocate against it.
const maxBlockBytes = 1 << 20

// maxFutureSkew is how far ahead of this node's clock a block's timestamp may
// be. Timestamps are monotonic (Verify refuses one below its parent's), so an
// unbounded timestamp is not a one-block error: it raises the floor every later
// block must clear, and one block dated a year out stops the chain producing
// for a year. The bound is loose enough to absorb ordinary clock disagreement
// between honest validators and tight enough that the damage from an
// out-of-range one is a single rejected block.
const maxFutureSkew = 10 * time.Second

// Operation is one verifiable state transition.
//
// Key is non-nil exactly when Type is OpTypeKeygen: the operation carries the
// registration it is asking consensus to make, so there is no second place a
// key record can enter state.
type Operation struct {
	Type string
	// CeremonyID is derived from (keyID, digest, signer set) — never announced
	// by a coordinator. It is the ceremony log's primary key.
	CeremonyID string
	KeyID      string
	// RequestingChain names the chain that asked for this ceremony. Empty when
	// the ceremony was initiated on M-Chain itself.
	RequestingChain string
	// Digest is the 32 bytes the ceremony signed: the caller's message digest
	// for a sign, the key-commit digest for a keygen.
	Digest []byte
	// Artifact is the 65-byte r‖s‖v secp256k1 signature the ceremony produced.
	Artifact []byte
	// Signers is the participating set, canonically ordered.
	Signers []party.ID
	// Key is the registration carried by a keygen operation; nil otherwise.
	Key *KeyRecord
}

// digest returns the operation's contribution to the state root. Domain
// separation by kind means a keygen digest can never be replayed as a sign
// digest even if every other field coincides.
func (op *Operation) digest() [32]byte {
	h := sha256.New()
	switch op.Type {
	case OpTypeKeygen:
		writeTagged(h, tagOpKeygen)
		writeField(h, []byte(op.CeremonyID))
		if op.Key != nil {
			kc := KeyCommitDigest(op.Key)
			writeField(h, kc[:])
			writeUint64(h, op.Key.CreatedHeight)
			writeField(h, op.Key.Address)
		}
	default:
		writeTagged(h, tagOpSign)
		writeField(h, []byte(op.CeremonyID))
		writeField(h, []byte(op.KeyID))
		writeField(h, op.Digest)
		writeParties(h, op.Signers)
	}
	writeField(h, op.Artifact)
	writeField(h, []byte(op.RequestingChain))
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// Block is one M-Chain block.
type Block struct {
	ID_            ids.ID
	ParentID_      ids.ID
	BlockHeight    uint64
	BlockTimestamp int64
	// StateRoot is the root AFTER applying Operations. Every validator
	// recomputes it; a proposer that applied something different is rejected.
	StateRoot  [32]byte
	Operations []*Operation

	vm     *VM
	status choices.Status
}

func (b *Block) ID() ids.ID                      { return b.ID_ }
func (b *Block) Parent() ids.ID                  { return b.ParentID_ }
func (b *Block) ParentID() ids.ID                { return b.ParentID_ }
func (b *Block) Height() uint64                  { return b.BlockHeight }
func (b *Block) Timestamp() time.Time            { return time.Unix(b.BlockTimestamp, 0) }
func (b *Block) Status() uint8                   { return uint8(b.status) }
func (b *Block) ChoicesStatus() choices.Status   { return b.status }
func (b *Block) SetStatus(status choices.Status) { b.status = status }

// Bytes returns the block's canonical wire encoding.
func (b *Block) Bytes() []byte { return b.Marshal() }

// computeID is the block id: the hash of its canonical bytes. Because
// StateRoot is inside those bytes, the id commits to the post-state.
func (b *Block) computeID() ids.ID { return ids.ID(sha256.Sum256(b.Marshal())) }

// Verify re-checks the proposed transition against this validator's own state.
// It mutates nothing: a rejected block must leave state untouched.
func (b *Block) Verify(ctx context.Context) error {
	vm := b.vm
	if vm == nil {
		return errors.New("mpcvm: block has no VM")
	}
	if b.BlockHeight == 0 {
		return errors.New("mpcvm: genesis block is not verifiable as a transition")
	}

	// The parent is resolved through the chain's lock, before this takes the
	// VM's. Holding the VM's across that would take the two in the opposite
	// order to the one Accept takes them in, which is a deadlock.
	parent, err := vm.loadBlock(b.ParentID_)
	if err != nil {
		return fmt.Errorf("mpcvm: unknown parent %s: %w", b.ParentID_, err)
	}
	if b.BlockHeight != parent.BlockHeight+1 {
		return fmt.Errorf("mpcvm: height %d is not parent height %d + 1", b.BlockHeight, parent.BlockHeight)
	}
	if b.BlockTimestamp < parent.BlockTimestamp {
		return fmt.Errorf("mpcvm: timestamp %d precedes parent %d", b.BlockTimestamp, parent.BlockTimestamp)
	}
	if skew := time.Until(b.Timestamp()); skew > maxFutureSkew {
		return fmt.Errorf("%w: %s ahead, at most %s allowed", ErrFutureBlock, skew, maxFutureSkew)
	}
	if len(b.Operations) == 0 {
		return errors.New("mpcvm: empty block")
	}
	if len(b.Operations) > maxOpsPerBlock {
		return fmt.Errorf("%w: %d operations, at most %d", ErrBlockTooLarge, len(b.Operations), maxOpsPerBlock)
	}

	vm.mu.RLock()
	defer vm.mu.RUnlock()

	// Fold the operations, checking each against state plus the effects of the
	// operations before it in this same block, and accumulating the root.
	root := vm.state.Root()

	// Every check below reads APPLIED state — the registry, the ceremony log,
	// this node's own shares — so the transition is only meaningful as an
	// extension of what is applied. A block whose parent's post-state is not
	// this node's current state is being checked against the wrong state, and
	// the accumulated root would be right for a history the chain does not
	// have: it verifies now and fails at Accept, after consensus has decided
	// it, which is the divergence the root exists to prevent. Comparing the
	// parent's declared post-state to ours says exactly that, and says it
	// whether the parent is an unapplied sibling, an ancestor, or a block still
	// in flight above the tip.
	if parent.StateRoot != root {
		return fmt.Errorf("%w: parent %s leaves root %x, this node is at %x",
			ErrStaleParent, b.ParentID_, parent.StateRoot[:8], root[:8])
	}
	pending := make(map[string]*KeyRecord, len(b.Operations))
	seen := make(map[string]struct{}, len(b.Operations))

	for i, op := range b.Operations {
		if _, dup := seen[op.CeremonyID]; dup {
			return fmt.Errorf("%w: ceremony %s appears twice in one block", ErrInvalidOperation, op.CeremonyID)
		}
		seen[op.CeremonyID] = struct{}{}

		if err := vm.verifyOperation(op, pending); err != nil {
			return fmt.Errorf("mpcvm: operation %d (%s): %w", i, op.Type, err)
		}
		if op.Type == OpTypeKeygen {
			pending[op.Key.KeyID] = op.Key
		}
		root = advance(root, op.digest())
	}

	if root != b.StateRoot {
		return fmt.Errorf("%w: computed %x, block claims %x", ErrRootMismatch, root[:8], b.StateRoot[:8])
	}
	return nil
}

// verifyOperation checks one operation. pending carries key registrations made
// earlier in the same block so a key can be registered and used in one block.
//
// Caller holds vm.mu at least for read.
func (vm *VM) verifyOperation(op *Operation, pending map[string]*KeyRecord) error {
	if op.CeremonyID == "" {
		return fmt.Errorf("%w: no ceremony id", ErrInvalidOperation)
	}
	if op.KeyID == "" {
		return fmt.Errorf("%w: no key id", ErrInvalidOperation)
	}
	// A ceremony id is derived from the task, so re-recording one is a replay
	// of an identical task — for a bridge release, a double spend.
	if _, err := vm.state.GetCeremony(op.CeremonyID); err == nil {
		return fmt.Errorf("%w: %s", ErrCeremonyExists, op.CeremonyID)
	}

	switch op.Type {
	case OpTypeKeygen:
		return vm.verifyKeygen(op, pending)
	case OpTypeSign:
		return vm.verifySign(op, pending)
	default:
		return fmt.Errorf("%w: unknown type %q", ErrInvalidOperation, op.Type)
	}
}

// verifyKeygen checks a proposed custody-key registration.
func (vm *VM) verifyKeygen(op *Operation, pending map[string]*KeyRecord) error {
	rec := op.Key
	if rec == nil {
		return fmt.Errorf("%w: keygen carries no key record", ErrInvalidOperation)
	}
	if rec.KeyID != op.KeyID {
		return fmt.Errorf("%w: key id %q does not match record %q", ErrInvalidOperation, op.KeyID, rec.KeyID)
	}
	// Validate() enforces the structural invariants every later signature check
	// depends on: deployable policy, |participants| == N, canonical ordering,
	// 33-byte compressed group key, 20-byte address.
	if err := rec.Validate(); err != nil {
		return err
	}
	// The address must be the one the external chain will derive. Recomputing
	// it here means a proposer cannot publish a custody address that does not
	// belong to the group key.
	want := publicKeyToAddress(rec.GroupPublicKey)
	if want == nil {
		return fmt.Errorf("%w: group public key does not decode to a point", ErrInvalidOperation)
	}
	if string(want) != string(rec.Address) {
		return fmt.Errorf("%w: address %x is not keccak(pubkey) %x", ErrInvalidOperation, rec.Address, want)
	}
	if _, dup := pending[rec.KeyID]; dup {
		return fmt.Errorf("%w: %s", ErrKeyExists, rec.KeyID)
	}
	switch has, err := vm.state.HasKey(rec.KeyID); {
	case err != nil:
		return err
	case has:
		return fmt.Errorf("%w: %s", ErrKeyExists, rec.KeyID)
	}

	// The signer set of a keygen IS its participant set: a DKG has no K-subset,
	// every party runs every round. Leaving it unchecked let a proposer write
	// any names it liked into the ceremony log's Signers — the log is the
	// replicated evidence of who generated a custody key, and unverified
	// evidence is worse than none.
	if !samePartySet(op.Signers, rec.Participants) {
		return fmt.Errorf("%w: keygen signers are not the key's participant set", ErrInvalidOperation)
	}
	// The ceremony id must be the one this exact registration derives —
	// domain-separated from a signing id, so the two can never collide.
	//
	// Leaving it unchecked made the id proposer-chosen, and a recorded id is
	// permanently unusable (verifyOperation refuses a ceremony already in the
	// log). A keygen carrying the DERIVED id of some future signing task would
	// therefore censor that task forever, and signing ids are derived from
	// public inputs, so the task to censor can be named in advance.
	if want := keygenCeremonyID(rec.KeyID, rec.Policy, rec.Participants); want != op.CeremonyID {
		return fmt.Errorf("%w: ceremony id %q is not derived from this registration (want %q)",
			ErrInvalidOperation, op.CeremonyID, want)
	}
	// The ceremony must have signed the commit digest for exactly this record.
	commit := KeyCommitDigest(rec)
	if string(op.Digest) != string(commit[:]) {
		return fmt.Errorf("%w: digest is not this record's key commitment", ErrInvalidOperation)
	}
	// Proof of possession: the new group key signs its own registration.
	if err := verifyGroupSignature(rec.GroupPublicKey, commit[:], op.Artifact); err != nil {
		return fmt.Errorf("%w: proof of possession: %w", ErrBadArtifact, err)
	}

	// Participant cross-check. If this validator holds a share for the key, it
	// knows the truth about the group key and the degree, and a disagreement
	// means the proposer mis-declared the ceremony. This is what binds the
	// declared degree — a proof of possession alone cannot.
	if err := vm.crossCheckOwnShare(rec); err != nil {
		return err
	}
	return nil
}

// verifySign checks a proposed signature record.
func (vm *VM) verifySign(op *Operation, pending map[string]*KeyRecord) error {
	rec, ok := pending[op.KeyID]
	if !ok {
		var err error
		if rec, err = vm.state.GetKey(op.KeyID); err != nil {
			return err
		}
	}
	if len(op.Digest) != 32 {
		return fmt.Errorf("%w: digest is %d bytes, want 32", ErrInvalidOperation, len(op.Digest))
	}
	// The signer set must satisfy the key's own policy. K signers, not K-1: a
	// set of size Degree() cannot produce a signature, so a record claiming one
	// did is either a lie or a wrong-degree key.
	//
	// Which particular K-subset signed is deliberately NOT pinned here. The
	// signature verifies under the group key or it does not, and an adversary
	// able to produce one already holds K shares — constraining the subset adds
	// no security, while leaving it open lets a future availability-aware
	// reselection ship without a consensus change.
	if len(op.Signers) < rec.Policy.K {
		return fmt.Errorf("%w: %d signers for policy %s", ErrQuorumTooSmall, len(op.Signers), rec.Policy)
	}
	if !sortedUnique(op.Signers) {
		return fmt.Errorf("%w: signer set is not canonical (sorted+unique)", ErrInvalidOperation)
	}
	// Every signer must actually hold a share of this key.
	members := make(map[party.ID]struct{}, len(rec.Participants))
	for _, p := range rec.Participants {
		members[p] = struct{}{}
	}
	for _, s := range op.Signers {
		if _, ok := members[s]; !ok {
			return fmt.Errorf("%w: %s is not a participant of key %s", ErrInvalidOperation, s, rec.KeyID)
		}
	}
	// The ceremony id must be the one this exact task derives. This is what
	// makes the id unforgeable rather than a proposer-chosen label, and it is
	// what makes replay detection meaningful.
	if want := ceremonyID(rec.KeyID, op.Digest, op.Signers); want != op.CeremonyID {
		return fmt.Errorf("%w: ceremony id %q is not derived from this task (want %q)",
			ErrInvalidOperation, op.CeremonyID, want)
	}
	// The check that needs no trust: does the signature verify under the
	// registered group key?
	if err := verifyGroupSignature(rec.GroupPublicKey, op.Digest, op.Artifact); err != nil {
		return fmt.Errorf("%w: %w", ErrBadArtifact, err)
	}
	return nil
}

// crossCheckOwnShare compares a proposed key record against this node's own
// share, when it holds one. A non-participant returns nil — it has nothing to
// compare and relies on the proof of possession plus the participants.
//
// Caller holds vm.mu at least for read.
func (vm *VM) crossCheckOwnShare(rec *KeyRecord) error {
	held, ok := vm.shares[rec.KeyID]
	if !ok {
		return nil
	}
	pub, degree, err := held.groupKeyAndDegree()
	if err != nil {
		return fmt.Errorf("mpcvm: reading own share for %s: %w", rec.KeyID, err)
	}
	if string(pub) != string(rec.GroupPublicKey) {
		return fmt.Errorf("%w: record registers group key %x but our share belongs to %x",
			ErrInvalidOperation, rec.GroupPublicKey, pub)
	}
	if degree != rec.Degree() {
		return fmt.Errorf("%w: record declares policy %s (degree %d) but our share has degree %d",
			ErrInvalidOperation, rec.Policy, rec.Degree(), degree)
	}
	return nil
}

// verifyGroupSignature checks a 65-byte r‖s‖v signature against a compressed
// group public key. The recovery byte is not verified against — only r‖s — so
// a wrong v cannot make a good signature fail, and cannot make a bad one pass.
func verifyGroupSignature(groupPub, digest, sig []byte) error {
	if len(sig) != 65 {
		return fmt.Errorf("signature is %d bytes, want 65 (r‖s‖v)", len(sig))
	}
	if len(digest) != 32 {
		return fmt.Errorf("digest is %d bytes, want 32", len(digest))
	}
	if len(groupPub) != 33 {
		return fmt.Errorf("group key is %d bytes, want 33 (compressed)", len(groupPub))
	}
	if !secp256k1.VerifySignature(groupPub, digest, sig[:64]) {
		return errors.New("does not verify under the registered group key")
	}
	return nil
}

// Accept applies the transition and durably records it. Verify has already run,
// so every precondition holds; anything that fails here is an I/O fault, not a
// validation failure, and must not be swallowed — a block the engine believes
// is accepted but whose state was not written is exactly the divergence the
// state root exists to catch.
func (b *Block) Accept(ctx context.Context) error {
	return b.vm.chain.Accept(b)
}

// Write folds the block's operations into the registry and the ceremony log,
// and stages the root they reach.
//
// The root check used to run AFTER every key and ceremony had already been
// written, so refusing here left exactly the disagreeing state it refuses to
// persist — and the duplicate guards in PutKey and PutCeremony then made that
// block permanently unacceptable, wedging the chain at that height. Now
// nothing is durable until the check has passed and the whole block commits.
func (b *Block) Write(database.Database) error {
	vm := b.vm
	vm.mu.Lock()
	defer vm.mu.Unlock()

	root := vm.state.Root()
	for _, op := range b.Operations {
		if op.Type == OpTypeKeygen {
			if err := vm.state.PutKey(op.Key); err != nil {
				return fmt.Errorf("mpcvm: accept keygen %s: %w", op.KeyID, err)
			}
		}
		if err := vm.state.PutCeremony(&CeremonyRecord{
			ID:              op.CeremonyID,
			Kind:            op.Type,
			KeyID:           op.KeyID,
			Digest:          op.Digest,
			Signers:         op.Signers,
			Artifact:        op.Artifact,
			RequestingChain: op.RequestingChain,
			Height:          b.BlockHeight,
		}); err != nil {
			return fmt.Errorf("mpcvm: accept ceremony %s: %w", op.CeremonyID, err)
		}
		root = advance(root, op.digest())
	}
	if root != b.StateRoot {
		// Verify passed, so this can only be a state mutation between Verify
		// and Accept. Refuse rather than persist a state that disagrees with
		// the block the network accepted.
		return fmt.Errorf("%w at accept: computed %x, block claims %x", ErrRootMismatch, root[:8], b.StateRoot[:8])
	}
	return vm.state.WriteRoot(root)
}

// Publish makes the block's root current and releases the ceremonies it
// carried. It runs after the commit, so the root this node reports is one that
// is on disk and a ceremony leaves the staging queue only once the block
// recording it is durable.
func (b *Block) Publish() {
	b.status = choices.Accepted

	b.vm.mu.Lock()
	b.vm.state.HoldRoot(b.StateRoot)
	b.vm.mu.Unlock()

	b.vm.staged.Drop(b.Operations)

	b.vm.log.Info("accepted M-Chain block",
		log.Stringer("blockID", b.ID()),
		log.Uint64("height", b.BlockHeight),
		log.Int("operations", len(b.Operations)),
		log.String("stateRoot", fmt.Sprintf("%x", b.StateRoot[:8])),
	)
}

// Reject drops a block. State was never touched, so there is nothing to undo.
func (b *Block) Reject(ctx context.Context) error {
	b.status = choices.Rejected
	b.vm.chain.Drop(b.ID())
	// The ceremonies stay staged: rejection means this block did not land, not
	// that the ceremony was invalid, so the result may be re-proposed.
	b.vm.log.Info("rejected M-Chain block", log.Stringer("blockID", b.ID()))
	return nil
}
