// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// state.go — M-Chain's persisted state, and the line between what is
// replicated and what is not.
//
// # Two keyspaces, two trust properties
//
// M-Chain custody state divides cleanly in two, and braiding them is how an
// off-chain signer cluster ends up with nodes that silently disagree about
// which key is the custodian:
//
//   - CONSENSUS state (prefix "c/") is replicated. Every honest validator holds
//     byte-identical consensus state at a given height, and Root() commits to
//     it. It contains only public values: which custody keys exist, their
//     quorum policy, their group public key, and the ceremonies that produced
//     or used them. A secret never appears here.
//
//   - NODE state (prefix "n/") is this validator's own. It holds this node's
//     private key shares and its view pointers. It is NOT replicated, NOT
//     committed by Root(), and differs legitimately between nodes — party A's
//     share is not party B's.
//
// The prefixes are disjoint by construction, and only operation digests folded
// through advance() enter Root() — never a raw stored value. So "could a secret
// have reached consensus state" is answerable by reading the writers of the c/
// prefix, which are the three Put* methods below, rather than auditing the
// whole VM.
//
// # What Root() commits to
//
// Root is a hash chain over applied operations: r0 = H(TAG_GENESIS ‖ chainID),
// r_{i+1} = H(TAG_STEP ‖ r_i ‖ opDigest). Because every validator applies the
// same accepted blocks in the same order to the same initial state, equal
// histories give equal roots and any divergence in applied state shows up as a
// root mismatch at the next block — which Block.Verify rejects.
//
// This is a transition-log commitment, not a membership-proof commitment: it
// proves two nodes agree on the whole registry, but it cannot prove to a third
// party that one particular key is in it without replaying the log. That is
// enough for M-Chain's job (validators must agree on custody), and it is what
// LP-134's mchain_ceremony_root asks for. A Merkle registry root is the upgrade
// if external membership proofs are ever needed; it is deliberately not built
// on speculation.

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/luxfi/chains/mpcvm/types"
	"github.com/luxfi/database"
	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
)

// Keyspace prefixes. Disjoint by construction; see the package comment.
var (
	prefixKeyRecord = []byte("c/key/")      // replicated: custody key registry
	prefixCeremony  = []byte("c/ceremony/") // replicated: ceremony log
	keyRoot         = []byte("c/root")      // replicated: current state root
	prefixShare     = []byte("n/share/")    // NODE-PRIVATE: this party's key share
)

// Domain separation tags. Every hash M-Chain computes is tagged, so a digest
// from one context can never be replayed as a digest from another — in
// particular a ceremony id can never alias a signing preimage, and a state root
// can never alias a key commitment.
const (
	tagRootGenesis = "LUX_MCHAIN_ROOT_GENESIS_v1"
	tagRootStep    = "LUX_MCHAIN_ROOT_STEP_v1"
	tagOpKeygen    = "LUX_MCHAIN_OP_KEYGEN_v1"
	tagOpSign      = "LUX_MCHAIN_OP_SIGN_v1"
	// tagKeyCommit is the message a freshly generated group key signs to prove
	// possession. See KeyCommitDigest.
	tagKeyCommit = "LUX_MCHAIN_KEY_COMMIT_v1"
)

var (
	ErrKeyExists      = errors.New("mpcvm: key already registered")
	ErrUnknownKey     = errors.New("mpcvm: key not registered")
	ErrCeremonyExists = errors.New("mpcvm: ceremony already recorded")
	ErrShareNotHeld   = errors.New("mpcvm: this node holds no share for that key")
	ErrPolicyMismatch = errors.New("mpcvm: key policy does not match its participant set")
	ErrRootMismatch   = errors.New("mpcvm: post-state root mismatch")
)

// KeyRecord is the replicated, public record of one custody key.
//
// It is deliberately share-free: the group public key and the policy are
// everything a validator needs to check a signature and everything B-Chain
// needs to know who the custodian is. The share that produced it lives in node
// state and never leaves the node that generated it.
type KeyRecord struct {
	KeyID string
	// Kind is the threshold protocol that generated the key (cggmp21, frost,
	// ...). A key is bound to its protocol: cross-scheme reuse of a share is
	// prohibited (LP-4700), and Kind is what enforces the binding at signing.
	Kind string
	// Policy is the quorum in operator form: K signers of N parties. The
	// polynomial degree the protocol was parameterised with is Policy.Degree(),
	// derived — never stored independently, because two stored numbers can
	// disagree and one cannot.
	Policy quorum.Policy
	// Participants are the parties holding a share, in canonical (sorted) order
	// so every validator hashes the same bytes. len(Participants) == Policy.N.
	Participants []party.ID
	// GroupPublicKey is the compressed secp256k1 point (33 bytes) that
	// signatures verify under.
	GroupPublicKey []byte
	// Address is the 20-byte Ethereum-style address of GroupPublicKey — the
	// external-chain custody address that actually holds bridged funds.
	Address []byte
	// Generation increments on each resharing/refresh of the same public key.
	Generation uint64
	// CreatedHeight is the M-Chain height at which the key was registered.
	CreatedHeight uint64
}

// Degree returns the polynomial degree this key was generated with. It is the
// value to hand to cmp/frost, and it is derived from the policy at the one
// boundary that is allowed to convert between k and t.
func (r *KeyRecord) Degree() int { return r.Policy.Degree() }

// Validate checks the record's internal consistency. A record that fails this
// must never be admitted to consensus state, because every later signature
// check trusts these fields.
func (r *KeyRecord) Validate() error {
	if r.KeyID == "" {
		return errors.New("mpcvm: key record has no id")
	}
	if r.Kind == "" {
		return errors.New("mpcvm: key record has no protocol kind")
	}
	if !r.Policy.Valid() {
		return fmt.Errorf("mpcvm: key %s has undeployable policy %s", r.KeyID, r.Policy)
	}
	// The custody floor, defined once in the shared substrate: a key whose
	// policy admits two disjoint quorums lets two halves of the committee
	// authorise contradictory releases of the same funds.
	if !types.HasUniqueQuorum(r.Policy) {
		return fmt.Errorf("mpcvm: key %s policy %s admits two disjoint quorums", r.KeyID, r.Policy)
	}
	if len(r.Participants) != r.Policy.N {
		return fmt.Errorf("%w: %s has %d participants for policy %s",
			ErrPolicyMismatch, r.KeyID, len(r.Participants), r.Policy)
	}
	if !sortedUnique(r.Participants) {
		return fmt.Errorf("mpcvm: key %s participants not sorted+unique (non-canonical)", r.KeyID)
	}
	if len(r.GroupPublicKey) != 33 {
		return fmt.Errorf("mpcvm: key %s group public key is %d bytes, want 33 (compressed secp256k1)",
			r.KeyID, len(r.GroupPublicKey))
	}
	if len(r.Address) != 20 {
		return fmt.Errorf("mpcvm: key %s address is %d bytes, want 20", r.KeyID, len(r.Address))
	}
	return nil
}

// KeyCommitDigest is the message a newly generated group key signs to prove
// possession of itself. Binding the policy, the participant set and the group
// key together means a proposer cannot register a key under a policy or a
// committee other than the one the ceremony actually ran with and still produce
// a verifying proof.
//
// What this proves and what it does not: a valid proof-of-possession shows that
// whoever produced it can sign under GroupPublicKey, which rules out a proposer
// registering a public key it does not control (rogue-key registration). It
// does NOT by itself prove the declared degree — a single party holding the
// whole secret could also sign. Degree is established by the participant
// cross-check in Block.Verify: a validator that holds a share for this key
// compares the record against its own config and rejects a mismatch, so one
// honest participant is enough to stop a mis-declared key.
func KeyCommitDigest(r *KeyRecord) [32]byte {
	h := sha256.New()
	writeTagged(h, tagKeyCommit)
	writeField(h, []byte(r.KeyID))
	writeField(h, []byte(r.Kind))
	writeUint64(h, uint64(r.Policy.K))
	writeUint64(h, uint64(r.Policy.N))
	writeParties(h, r.Participants)
	writeField(h, r.GroupPublicKey)
	writeUint64(h, r.Generation)
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// CeremonyRecord is the replicated record of one completed ceremony. It is the
// audit trail: which key, over which digest, by which signers, producing what.
type CeremonyRecord struct {
	// ID is the derived ceremony id — H(tag ‖ keyID ‖ digest ‖ sorted signers).
	// Derived, not announced: every validator computing the same task lands on
	// the same id with no coordination round and no coordinator.
	ID string
	// Kind is the operation: OpTypeKeygen or OpTypeSign.
	Kind string
	// KeyID is the custody key the ceremony created or used.
	KeyID string
	// Digest is the 32-byte message that was signed (sign ceremonies) or the
	// key-commit digest (keygen ceremonies).
	Digest []byte
	// Signers are the parties that participated, in canonical order.
	Signers []party.ID
	// Artifact is the ceremony's verifiable output: for a sign ceremony the
	// 65-byte r‖s‖v signature; for a keygen ceremony the proof-of-possession
	// over KeyCommitDigest.
	Artifact []byte
	// RequestingChain names the chain that asked for this ceremony (B-Chain for
	// bridge custody). Empty for locally initiated ceremonies.
	RequestingChain string
	// Height is the M-Chain height at which the ceremony was recorded.
	Height uint64
}

// State is M-Chain's persisted state over one database. It owns the encoding
// and the root; it does not know what a ceremony means.
//
// State is not safe for concurrent use; the VM holds it under its own lock.
// That is deliberate — a state machine with its own internal locking invites
// callers to interleave reads and writes across a transition and observe a
// half-applied block.
type State struct {
	db   database.Database
	root [32]byte
}

// NewState opens state over db, resuming from whatever is already persisted.
// chainID seeds the genesis root so two different chains running the same
// operations do not produce the same root.
func NewState(db database.Database, chainID ids.ID) (*State, error) {
	s := &State{db: db}
	switch stored, err := db.Get(keyRoot); {
	case err == nil:
		if len(stored) != 32 {
			return nil, fmt.Errorf("mpcvm: stored root is %d bytes, want 32", len(stored))
		}
		copy(s.root[:], stored)
	case errors.Is(err, database.ErrNotFound):
		s.root = genesisRoot(chainID)
		if err := db.Put(keyRoot, s.root[:]); err != nil {
			return nil, fmt.Errorf("mpcvm: seed root: %w", err)
		}
	default:
		return nil, fmt.Errorf("mpcvm: read root: %w", err)
	}
	return s, nil
}

// Root returns the current state root.
func (s *State) Root() [32]byte { return s.root }

// genesisRoot is the root of empty state for a given chain.
func genesisRoot(chainID ids.ID) [32]byte {
	h := sha256.New()
	writeTagged(h, tagRootGenesis)
	writeField(h, chainID[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// advance folds one operation digest into the root. Pure: it returns the next
// root without touching state, so Verify can compute a candidate post-state
// root without mutating anything.
func advance(root [32]byte, opDigest [32]byte) [32]byte {
	h := sha256.New()
	writeTagged(h, tagRootStep)
	writeField(h, root[:])
	writeField(h, opDigest[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// -----------------------------------------------------------------------------
// Key registry (replicated)
// -----------------------------------------------------------------------------

// PutKey registers a custody key. Registration is once-only: a key id is a
// permanent binding to a group public key, and silently rebinding it would let
// a later ceremony redirect custody of live funds. Rotation is a new
// Generation of the same record via ReplaceKey, never a fresh PutKey.
func (s *State) PutKey(r *KeyRecord) error {
	if err := r.Validate(); err != nil {
		return err
	}
	k := append(append([]byte(nil), prefixKeyRecord...), r.KeyID...)
	switch has, err := s.db.Has(k); {
	case err != nil:
		return err
	case has:
		return fmt.Errorf("%w: %s", ErrKeyExists, r.KeyID)
	}
	b, err := marshalKeyRecord(r)
	if err != nil {
		return err
	}
	return s.db.Put(k, b)
}

// ReplaceKey overwrites an existing key record — the resharing/refresh path,
// where the group public key is unchanged but the shares and generation move.
func (s *State) ReplaceKey(r *KeyRecord) error {
	if err := r.Validate(); err != nil {
		return err
	}
	prev, err := s.GetKey(r.KeyID)
	if err != nil {
		return err
	}
	if string(prev.GroupPublicKey) != string(r.GroupPublicKey) {
		return fmt.Errorf("mpcvm: refusing to rebind custody key %s to a different public key", r.KeyID)
	}
	if r.Generation <= prev.Generation {
		return fmt.Errorf("mpcvm: key %s generation must increase (%d -> %d)", r.KeyID, prev.Generation, r.Generation)
	}
	b, err := marshalKeyRecord(r)
	if err != nil {
		return err
	}
	return s.db.Put(append(append([]byte(nil), prefixKeyRecord...), r.KeyID...), b)
}

// GetKey reads a registered custody key.
func (s *State) GetKey(keyID string) (*KeyRecord, error) {
	b, err := s.db.Get(append(append([]byte(nil), prefixKeyRecord...), keyID...))
	if errors.Is(err, database.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrUnknownKey, keyID)
	}
	if err != nil {
		return nil, err
	}
	return parseKeyRecord(b)
}

// HasKey reports whether a key id is registered.
func (s *State) HasKey(keyID string) (bool, error) {
	return s.db.Has(append(append([]byte(nil), prefixKeyRecord...), keyID...))
}

// Keys returns every registered custody key in key-id order.
func (s *State) Keys() ([]*KeyRecord, error) {
	it := s.db.NewIteratorWithPrefix(prefixKeyRecord)
	defer it.Release()
	var out []*KeyRecord
	for it.Next() {
		r, err := parseKeyRecord(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, it.Error()
}

// -----------------------------------------------------------------------------
// Ceremony log (replicated)
// -----------------------------------------------------------------------------

// PutCeremony records a completed ceremony. Ceremony ids are derived from
// (key, digest, signer set), so a repeat id means a genuine replay of an
// identical task and is rejected: recording it twice would double-count a
// bridge release.
func (s *State) PutCeremony(c *CeremonyRecord) error {
	if c.ID == "" {
		return errors.New("mpcvm: ceremony has no id")
	}
	k := append(append([]byte(nil), prefixCeremony...), c.ID...)
	switch has, err := s.db.Has(k); {
	case err != nil:
		return err
	case has:
		return fmt.Errorf("%w: %s", ErrCeremonyExists, c.ID)
	}
	b, err := marshalCeremonyRecord(c)
	if err != nil {
		return err
	}
	return s.db.Put(k, b)
}

// GetCeremony reads a recorded ceremony.
func (s *State) GetCeremony(id string) (*CeremonyRecord, error) {
	b, err := s.db.Get(append(append([]byte(nil), prefixCeremony...), id...))
	if errors.Is(err, database.ErrNotFound) {
		return nil, fmt.Errorf("mpcvm: no ceremony %s", id)
	}
	if err != nil {
		return nil, err
	}
	return parseCeremonyRecord(b)
}

// Ceremonies returns every recorded ceremony in id order.
func (s *State) Ceremonies() ([]*CeremonyRecord, error) {
	it := s.db.NewIteratorWithPrefix(prefixCeremony)
	defer it.Release()
	var out []*CeremonyRecord
	for it.Next() {
		c, err := parseCeremonyRecord(it.Value())
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, it.Error()
}

// -----------------------------------------------------------------------------
// Node-private share store (NOT replicated, NOT in Root)
// -----------------------------------------------------------------------------

// PutShare stores this node's secret key share for keyID.
//
// This is the one secret M-Chain writes to disk, and it is written under the
// node/ prefix so it is structurally outside consensus state and outside
// Root(). The trust model is the validator's own disk — the same place its
// staking key lives. A node that loses this cannot sign for keyID and must be
// re-shared in; a node that leaks it has leaked one share, which is below the
// policy's corruption bound unless K-1 others leak too.
func (s *State) PutShare(keyID string, share []byte) error {
	if len(share) == 0 {
		return errors.New("mpcvm: refusing to store an empty share")
	}
	return s.db.Put(append(append([]byte(nil), prefixShare...), keyID...), share)
}

// GetShare reads this node's secret share for keyID.
func (s *State) GetShare(keyID string) ([]byte, error) {
	b, err := s.db.Get(append(append([]byte(nil), prefixShare...), keyID...))
	if errors.Is(err, database.ErrNotFound) {
		return nil, fmt.Errorf("%w: %s", ErrShareNotHeld, keyID)
	}
	return b, err
}

// HasShare reports whether this node participates in keyID's committee.
func (s *State) HasShare(keyID string) (bool, error) {
	return s.db.Has(append(append([]byte(nil), prefixShare...), keyID...))
}

// -----------------------------------------------------------------------------
// Chain pointers
// -----------------------------------------------------------------------------

// WriteRoot stages the root a block reaches. It is staged, not landed: the
// block, its height entry, the tip pointer and every record the block wrote all
// commit together or not at all, so a root can never name a state the chain
// does not have.
func (s *State) WriteRoot(root [32]byte) error {
	return s.db.Put(keyRoot, root[:])
}

// HoldRoot makes a committed root current. It runs after the commit, so the
// root this node reports is always one that is on disk.
func (s *State) HoldRoot(root [32]byte) { s.root = root }

// ReadRoot puts the committed root back, discarding an advance that belonged
// to a block whose writes were discarded.
func (s *State) ReadRoot() error {
	stored, err := s.db.Get(keyRoot)
	if err != nil {
		return err
	}
	if len(stored) != 32 {
		return fmt.Errorf("mpcvm: stored root is %d bytes, want 32", len(stored))
	}
	copy(s.root[:], stored)
	return nil
}

// -----------------------------------------------------------------------------
// Canonical hashing helpers
// -----------------------------------------------------------------------------
//
// Every variable-length field is length-prefixed before hashing so that
// H(a‖b) cannot collide with H(a'‖b') for a different split — without this,
// ("ab","c") and ("a","bc") hash identically and a ceremony id could be forged
// by moving a byte between the key id and the digest.

type byteWriter interface{ Write([]byte) (int, error) }

func writeTagged(h byteWriter, tag string) { writeField(h, []byte(tag)) }

func writeField(h byteWriter, b []byte) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(b)))
	_, _ = h.Write(n[:])
	_, _ = h.Write(b)
}

func writeUint64(h byteWriter, v uint64) {
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], v)
	_, _ = h.Write(n[:])
}

func writeParties(h byteWriter, ps []party.ID) {
	writeUint64(h, uint64(len(ps)))
	for _, p := range ps {
		writeField(h, []byte(p))
	}
}

// canonicalParties returns a sorted, de-duplicated copy. Sorting is what makes
// a signer set order-independent: two validators that enumerate the same
// committee in different orders must derive the same ceremony id.
func canonicalParties(ps []party.ID) []party.ID {
	out := append([]party.ID(nil), ps...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	dedup := out[:0]
	for i, p := range out {
		if i == 0 || p != out[i-1] {
			dedup = append(dedup, p)
		}
	}
	return dedup
}

func sortedUnique(ps []party.ID) bool {
	for i := 1; i < len(ps); i++ {
		if ps[i-1] >= ps[i] {
			return false
		}
	}
	return true
}
