// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Quasar: the Q-Chain finality bridge.
//
// A block is final when a quorum of the committee has SIGNED it and the
// aggregate of those signatures verifies against the committee's keys. Every
// word of that is load-bearing here: signed, not claimed; verified, not counted;
// aggregate, not a tally of names a sender chose for itself.

package quantumvm

import (
	"context"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/chains/quantumvm/config"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

var (
	// errDuplicateSigner — a validator that already contributed a signature for
	// this block sent another. The quorum is counted over signers, so admitting
	// a second signature from one validator would let a single peer reach the
	// threshold alone by resending.
	errDuplicateSigner = errors.New("quantumvm: validator already signed this block")

	// errUnverifiedSigner — the signature does not check out against the
	// registered key of the validator it names, over the block it names.
	errUnverifiedSigner = errors.New("quantumvm: signature does not verify for the validator it claims")

	errUnknownBlock      = errors.New("quantumvm: no block awaiting signatures")
	errNoValidatorID     = errors.New("quantumvm: a signer with no identity cannot be a member of a quorum")
	errAggregateRefused  = errors.New("quantumvm: the aggregate of the collected signatures does not verify")
	errAlreadyRegistered = errors.New("quantumvm: validator is already in the committee")
	errCommitteeFull     = errors.New("quantumvm: the committee is full")
)

// Quasar collects validator signatures for Q-Chain blocks and finalizes a block
// once the quorum's aggregate signature verifies.
//
// The core underneath signs with the validator's BLS key and, in the same call,
// attests the same message with that validator's ML-DSA-65 identity key
// (FIPS 204) — so the post-quantum half rides inside every signature this
// collects, and VerifyQuasarSig checks both halves or rejects.
type Quasar struct {
	mu sync.RWMutex

	// core is the consensus signing engine: it holds the committee's keys and
	// is the only thing that can say whether a signature is real.
	core *quasar.Quasar

	validatorID string
	threshold   int
	committee   int

	log log.Logger

	// validators is the committee roster this bridge registered. The core
	// holds their keys; this holds the membership, which is what makes the
	// committee a set of a declared size rather than whatever accumulated.
	validators map[string]struct{}

	finalizedBlocks map[ids.ID]bool
	pendingBlocks   map[ids.ID]*PendingBlock
}

// PendingBlock tracks a block gathering signatures. Every signature in the slice
// has been verified against BlockHash and against the registered key of the
// validator it names, and no two name the same validator.
type PendingBlock struct {
	BlockID    ids.ID
	BlockHash  []byte
	Height     uint64
	Signatures []*quasar.QuasarSig
	Finalized  bool
}

// by returns this block's signature from one validator, or nil.
func (p *PendingBlock) by(validatorID string) *quasar.QuasarSig {
	for _, sig := range p.Signatures {
		if sig.ValidatorID == validatorID {
			return sig
		}
	}
	return nil
}

// QuasarConfig configures the finality bridge. The committee size is the only
// quorum input: the threshold follows from it, so the two cannot be set to
// disagree.
type QuasarConfig struct {
	ValidatorID string
	Committee   int
	Logger      log.Logger
}

// NewQuasar creates the finality bridge and registers this node with the
// consensus core as its own validator.
//
// Registration is not optional and not deferred, because a bridge that cannot
// sign for its own identity does nothing at all: SignMessage answers "validator
// not found", so no signature is ever recorded, so no peer signature ever finds
// a block to attach to, so the quorum is never reached and finality is
// unreachable — silently, one warning line per block.
//
// The committee must be able to survive a fault. Below config.CommitteeMin the
// quorum ⌊2n/3⌋+1 is the entire committee, which the consensus core refuses
// outright and which would in any case make one absent validator a halt and one
// dishonest validator the decision.
func NewQuasar(cfg QuasarConfig) (*Quasar, error) {
	if cfg.ValidatorID == "" {
		return nil, errNoValidatorID
	}
	if cfg.Committee == 0 {
		cfg.Committee = config.CommitteeMin
	}
	if cfg.Committee < config.CommitteeMin {
		return nil, fmt.Errorf("quantumvm: a committee of %d tolerates no fault; %d is the smallest that does",
			cfg.Committee, config.CommitteeMin)
	}
	if cfg.Logger == nil {
		cfg.Logger = log.NewNoOpLogger()
	}

	threshold := config.Quorum(cfg.Committee)
	core, err := quasar.NewQuasar(threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to create Quasar core: %w", err)
	}

	q := &Quasar{
		core:            core,
		validatorID:     cfg.ValidatorID,
		threshold:       threshold,
		committee:       cfg.Committee,
		log:             cfg.Logger,
		validators:      make(map[string]struct{}, cfg.Committee),
		finalizedBlocks: make(map[ids.ID]bool),
		pendingBlocks:   make(map[ids.ID]*PendingBlock),
	}

	if err := q.AddValidator(cfg.ValidatorID, 1); err != nil {
		return nil, fmt.Errorf("failed to register this node with its own consensus core: %w", err)
	}

	return q, nil
}

// SignBlock signs a block with this node's validator key and records the
// signature. Signing the same block again returns the signature already
// recorded: one validator makes one statement about one block.
func (q *Quasar) SignBlock(ctx context.Context, blockID ids.ID, blockHash []byte, height uint64) (*quasar.QuasarSig, error) {
	q.mu.Lock()
	pending, tracked := q.pendingBlocks[blockID]
	if !tracked {
		pending = &PendingBlock{BlockID: blockID, BlockHash: blockHash, Height: height}
		q.pendingBlocks[blockID] = pending
	}
	if have := pending.by(q.validatorID); have != nil {
		q.mu.Unlock()
		return have, nil
	}
	core, validatorID := q.core, q.validatorID
	q.mu.Unlock()

	sig, err := core.SignMessageWithContext(ctx, validatorID, pending.BlockHash)
	if err != nil {
		// The entry was created for a signature that never arrived. Only a
		// block this node signed is ever finalized, and only a finalized block
		// is ever cleaned up, so leaving it behind leaks one map entry per
		// failure for the life of the process.
		if !tracked {
			q.mu.Lock()
			delete(q.pendingBlocks, blockID)
			q.mu.Unlock()
		}
		return nil, fmt.Errorf("quantumvm: sign failed: %w", err)
	}

	q.mu.Lock()
	defer q.mu.Unlock()
	if err := q.record(pending, sig); err != nil {
		if have := pending.by(validatorID); have != nil {
			return have, nil
		}
		return nil, err
	}

	q.log.Debug("block signed",
		"blockID", blockID,
		"height", height,
		"signatures", len(pending.Signatures),
		"threshold", q.threshold,
	)
	return sig, nil
}

// record admits one signature into a block's set. Caller holds q.mu.
//
// It VERIFIES before it counts, and it files the signature under the identity
// that verification authenticated. Counting a caller-supplied name instead made
// the quorum a count of strings: three fabricated validator ids finalized a
// block, and five spellings of one name — case, a trailing space, a NUL, the
// fullwidth forms — counted as five signers of one signature. Verification
// looks the claimed id up in the committee and checks the signature against
// THAT key over THIS block's hash, so a name nobody holds a key for fails, a
// respelling resolves to no validator and fails, and a signature made for
// another block fails against this one.
func (q *Quasar) record(p *PendingBlock, sig *quasar.QuasarSig) error {
	if sig == nil {
		return errUnverifiedSigner
	}
	if !q.core.VerifyQuasarSig(p.BlockHash, sig) {
		return fmt.Errorf("%w: %q on block %s", errUnverifiedSigner, sig.ValidatorID, p.BlockID)
	}
	if p.by(sig.ValidatorID) != nil {
		return fmt.Errorf("%w: %s", errDuplicateSigner, sig.ValidatorID)
	}
	p.Signatures = append(p.Signatures, sig)
	return nil
}

// AddSignature admits a peer's signature for a block this node is tracking.
func (q *Quasar) AddSignature(blockID ids.ID, sig *quasar.QuasarSig) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return fmt.Errorf("%w: %s", errUnknownBlock, blockID)
	}
	if err := q.record(pending, sig); err != nil {
		return err
	}

	q.log.Debug("signature added",
		"blockID", blockID,
		"signatures", len(pending.Signatures),
		"threshold", q.threshold,
	)
	return nil
}

// VerifySignature reports whether one validator signature checks out over a
// message.
func (q *Quasar) VerifySignature(message []byte, sig *quasar.QuasarSig) bool {
	if sig == nil {
		return false
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.core.VerifyQuasarSig(message, sig)
}

// VerifyAggregate reports whether an aggregated signature checks out over a
// message: the aggregate itself against the aggregated keys of the DISTINCT
// registered validators it names, at or above the threshold.
func (q *Quasar) VerifyAggregate(ctx context.Context, message []byte, agg *quasar.AggregatedSignature) bool {
	if agg == nil {
		return false
	}
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.core.VerifyAggregatedSignatureWithContext(ctx, message, agg)
}

// TryFinalize finalizes a block once the quorum's signatures aggregate into a
// signature that verifies over the block.
//
// Reaching the count is necessary and not sufficient: the aggregate is built
// and checked, and only a check that passes finalizes anything.
func (q *Quasar) TryFinalize(ctx context.Context, blockID ids.ID) (*quasar.AggregatedSignature, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return nil, false, fmt.Errorf("%w: %s", errUnknownBlock, blockID)
	}

	if len(pending.Signatures) < q.threshold {
		q.log.Debug("insufficient signatures to finalize",
			"blockID", blockID,
			"have", len(pending.Signatures),
			"need", q.threshold,
		)
		return nil, false, nil
	}

	agg, err := q.core.AggregateSignaturesWithContext(ctx, pending.BlockHash, pending.Signatures)
	if err != nil {
		return nil, false, fmt.Errorf("failed to aggregate signatures: %w", err)
	}
	if !q.core.VerifyAggregatedSignatureWithContext(ctx, pending.BlockHash, agg) {
		return nil, false, fmt.Errorf("%w: %s", errAggregateRefused, blockID)
	}

	pending.Finalized = true
	q.finalizedBlocks[blockID] = true

	q.log.Info("Q-block finalized",
		"blockID", blockID,
		"height", pending.Height,
		"signatures", len(pending.Signatures),
		"threshold", q.threshold,
	)

	return agg, true, nil
}

// IsFinalized checks if a block has been finalized
func (q *Quasar) IsFinalized(blockID ids.ID) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.finalizedBlocks[blockID]
}

// GetQuasar returns the underlying Quasar core engine
func (q *Quasar) GetQuasar() *quasar.Quasar {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.core
}

// GetThreshold returns how many validators must sign a block.
func (q *Quasar) GetThreshold() int {
	return q.threshold
}

// Committee returns the committee size the threshold was derived from.
func (q *Quasar) Committee() int {
	return q.committee
}

// GetActiveValidators returns the count of registered validators.
func (q *Quasar) GetActiveValidators() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return len(q.validators)
}

// AddValidator registers a validator with the consensus core. Only a registered
// validator's signature can verify, so this is what decides whose statements
// count toward the quorum.
//
// The committee is a SET, and it is the set the threshold was derived from.
// Registering an id twice hands the core a fresh key for it, which silently
// invalidates every signature that validator has already contributed;
// registering more validators than the committee declares makes the threshold a
// quorum of a committee that no longer exists.
func (q *Quasar) AddValidator(validatorID string, weight uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if validatorID == "" {
		return errNoValidatorID
	}
	if _, have := q.validators[validatorID]; have {
		return fmt.Errorf("%w: %s", errAlreadyRegistered, validatorID)
	}
	if len(q.validators) >= q.committee {
		return fmt.Errorf("%w: %d of %d", errCommitteeFull, len(q.validators), q.committee)
	}

	if _, err := q.core.AddValidator(validatorID, weight); err != nil {
		return fmt.Errorf("failed to add validator: %w", err)
	}
	q.validators[validatorID] = struct{}{}

	q.log.Info("validator registered",
		"validatorID", validatorID,
		"weight", weight,
		"registered", len(q.validators),
		"committee", q.committee,
		"threshold", q.threshold,
	)

	return nil
}

// Cleanup drops every block tracked below minHeight.
//
// The height is the caller's finalized frontier, so a block beneath it will
// never gather another signature whether it finalized or not. Keeping only the
// finalized ones meant the entries that could not be cleaned up were exactly
// the ones that accumulated: every proposal that lost, timed out, or failed to
// sign stayed in both maps for the life of the process.
func (q *Quasar) Cleanup(minHeight uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for blockID, pending := range q.pendingBlocks {
		if pending.Height < minHeight {
			delete(q.pendingBlocks, blockID)
			delete(q.finalizedBlocks, blockID)
		}
	}
}

// QuasarBridge is the Q-Chain finality bridge.
type QuasarBridge = Quasar

// QuasarBridgeConfig is an alias for QuasarConfig
type QuasarBridgeConfig = QuasarConfig

// NewQuasarBridge creates a new Quasar bridge (alias for NewQuasar)
func NewQuasarBridge(cfg QuasarBridgeConfig) (*QuasarBridge, error) {
	return NewQuasar(cfg)
}
