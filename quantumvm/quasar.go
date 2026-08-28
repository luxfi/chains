// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Quasar: Quantum-Safe Finality Engine
//
// Like stellar fusion combining hydrogen into helium, Quasar unifies
// classical BLS signatures with post-quantum Corona signatures.
// Both burn in parallel - classical for speed, quantum for eternity.
//
// No block escapes the event horizon without quantum finality.

package quantumvm

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"

	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// BlockSigs contains both BLS and Corona signatures for a block.
// Both are produced in parallel during signing.
type BlockSigs struct {
	BLS    *quasar.BLSSignature
	Corona *quasar.CoronaSignature
}

// Quasar is the core Post-Quantum BFT consensus engine for Q-Chain.
// Like a supermassive black hole, it pulls all blocks to quantum finality
// using dual BLS+Corona threshold signatures:
// - BLS threshold signatures (classical security, fast path)
// - Corona threshold signatures (post-quantum, Ring-LWE based)
//
// Blocks are NOT considered produced without BOTH thresholds being met.
type Quasar struct {
	mu sync.RWMutex

	// Core Quasar engine - provides both BLS and Corona signing directly
	quasar *quasar.Quasar

	// Validator configuration
	validatorID string
	threshold   int
	totalNodes  int

	// Logging
	log log.Logger

	// Block finality tracking
	finalizedBlocks map[ids.ID]bool
	pendingBlocks   map[ids.ID]*PendingBlock
}

// PendingBlock tracks a block awaiting dual signature finality.
// Both BLS AND Corona must reach threshold for quantum finality.
// Signatures are collected in parallel - either can complete first.
type PendingBlock struct {
	BlockID          ids.ID
	BlockHash        []byte
	Height           uint64
	BLSSignatures    []*quasar.BLSSignature    // Classical threshold signatures (parallel)
	CoronaSignatures []*quasar.CoronaSignature // Post-quantum threshold signatures (parallel)
	BLSFinalized     bool                      // BLS threshold reached
	CoronaFinalized  bool                      // Corona threshold reached
	Finalized        bool                      // BOTH complete = quantum finality
}

// QuasarConfig configures the Quasar PQ-BFT consensus
type QuasarConfig struct {
	ValidatorID string
	Threshold   int
	TotalNodes  int
	Logger      log.Logger
}

// NewQuasar creates a new Quasar PQ-BFT consensus engine.
//
// The committee size is settled BEFORE the threshold is derived from it.
// Deriving first read TotalNodes while it was still zero, so a config that left
// it unset got (0*2/3)+1 = 1 — a one-of-three quorum on the three-node network
// the very next line then assumed. Any single validator would have finalized
// alone.
func NewQuasar(cfg QuasarConfig) (*Quasar, error) {
	if cfg.TotalNodes < 1 {
		cfg.TotalNodes = 3 // Default 3-node network
	}
	if cfg.Threshold < 1 {
		cfg.Threshold = (cfg.TotalNodes * 2 / 3) + 1 // 2/3+1 BFT threshold
	}
	if cfg.Logger == nil {
		cfg.Logger = log.NewNoOpLogger()
	}

	// Initialize Quasar core with BLS + Corona
	qcore, err := quasar.NewQuasar(cfg.Threshold)
	if err != nil {
		return nil, fmt.Errorf("failed to create Quasar core: %w", err)
	}

	q := &Quasar{
		quasar:          qcore,
		validatorID:     cfg.ValidatorID,
		threshold:       cfg.Threshold,
		totalNodes:      cfg.TotalNodes,
		log:             cfg.Logger,
		finalizedBlocks: make(map[ids.ID]bool),
		pendingBlocks:   make(map[ids.ID]*PendingBlock),
	}

	return q, nil
}

// NOTE: there is intentionally no per-epoch dual-threshold key generation here.
// A prior helper (InitializeDualThreshold) called consensus quasar.GenerateDualKeys,
// a TRUSTED-DEALER keygen in which one process mints and holds every validator's
// BLS+Corona secret share — defeating threshold security. Consensus fenced that
// helper test-only (corona-genesis hardening), and this VM never invoked it: the
// Quasar bridge below signs through the consensus core with per-validator keys, and
// validators join via AddValidator. If a genuine per-epoch group key is ever needed,
// it MUST come from a dealerless DKG (corona dkg2 / pulsar v0.3 distributed), never a
// trusted dealer.

// SignBlock creates both BLS and Corona signatures for a block in parallel.
// Returns both signatures; both must reach threshold for quantum finality.
func (q *Quasar) SignBlock(ctx context.Context, blockID ids.ID, blockHash []byte, height uint64) (*BlockSigs, error) {
	q.mu.Lock()
	pending, tracked := q.pendingBlocks[blockID]
	if !tracked {
		pending = &PendingBlock{
			BlockID:          blockID,
			BlockHash:        blockHash,
			Height:           height,
			BLSSignatures:    make([]*quasar.BLSSignature, 0),
			CoronaSignatures: make([]*quasar.CoronaSignature, 0),
		}
		q.pendingBlocks[blockID] = pending
	}
	qcore := q.quasar
	validatorID := q.validatorID
	q.mu.Unlock()

	// Run both lanes in parallel
	var (
		blsSig *quasar.BLSSignature
		pqSig  *quasar.CoronaSignature
		blsErr error
		pqErr  error
	)

	var wg sync.WaitGroup
	wg.Add(2)

	// BLS signing (single round, fast path)
	go func() {
		defer wg.Done()
		quasarSig, err := qcore.SignMessageWithContext(ctx, validatorID, blockHash)
		if err != nil {
			blsErr = err
			return
		}
		blsSig = &quasar.BLSSignature{
			Signature:   quasarSig.BLS,
			ValidatorID: quasarSig.ValidatorID,
			SignerIndex: quasarSig.SignerIndex,
		}
	}()

	// Corona signing (Round 1 - D matrix + MACs)
	go func() {
		defer wg.Done()
		sessionID := int(height) // Use height as session ID
		// A digest, not a prefix. Slicing blockHash[:32] panicked on anything
		// shorter, and the caller decides what it signs over — StampBlock takes
		// an arbitrary message from the finality bridge.
		digest := sha256.Sum256(blockHash)
		round1Data, err := qcore.CoronaRound1(validatorID, sessionID, digest[:])
		if err != nil {
			pqErr = err
			return
		}
		// Round1Data contains D matrix and MACs - we store the party ID and a marker
		// The actual signature aggregation happens via Round2 + Finalize
		pqSig = &quasar.CoronaSignature{
			Signature:   []byte{byte(round1Data.PartyID)}, // Store party ID, full data in aggregation
			ValidatorID: validatorID,
			SignerIndex: round1Data.PartyID,
			Round:       1,
		}
	}()

	wg.Wait()

	if blsErr != nil || pqErr != nil {
		// The entry was created for a signature that never arrived. Only a
		// block this node signed is ever finalized, and only a finalized block
		// is ever cleaned up, so leaving it behind leaks one map entry per
		// failure for the life of the process.
		if !tracked {
			q.mu.Lock()
			delete(q.pendingBlocks, blockID)
			q.mu.Unlock()
		}
		if blsErr != nil {
			return nil, fmt.Errorf("BLS sign failed: %w", blsErr)
		}
		return nil, fmt.Errorf("Corona sign failed: %w", pqErr)
	}

	// The counts are read under the same lock that appends them. Reading them
	// afterwards for the log line raced every peer signature arriving through
	// AddBLSSignature.
	q.mu.Lock()
	pending.addBLS(blsSig)
	pending.addCorona(pqSig)
	blsCount, coronaCount := len(pending.BLSSignatures), len(pending.CoronaSignatures)
	q.mu.Unlock()

	q.log.Debug("Block signed with Quasar (BLS + Corona parallel)",
		"blockID", blockID,
		"height", height,
		"blsSigCount", blsCount,
		"coronaSigCount", coronaCount,
	)

	return &BlockSigs{BLS: blsSig, Corona: pqSig}, nil
}

// errDuplicateSigner — a validator that already contributed a signature for this
// block sent another. Both finality legs are counted by len(signatures) against
// the threshold, so admitting a second signature from one validator would let a
// single peer reach the threshold alone by resending.
var errDuplicateSigner = errors.New("quantumvm: validator already signed this block")

// addBLS records one BLS signature per validator and reports whether it was new.
// Caller holds q.mu.
func (p *PendingBlock) addBLS(sig *quasar.BLSSignature) bool {
	for _, have := range p.BLSSignatures {
		if have.ValidatorID == sig.ValidatorID {
			return false
		}
	}
	p.BLSSignatures = append(p.BLSSignatures, sig)
	return true
}

// addCorona records one Corona signature per validator and reports whether it was
// new. Caller holds q.mu.
func (p *PendingBlock) addCorona(sig *quasar.CoronaSignature) bool {
	for _, have := range p.CoronaSignatures {
		if have.ValidatorID == sig.ValidatorID {
			return false
		}
	}
	p.CoronaSignatures = append(p.CoronaSignatures, sig)
	return true
}

// AddBLSSignature adds a BLS signature from another validator
func (q *Quasar) AddBLSSignature(blockID ids.ID, sig *quasar.BLSSignature) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return fmt.Errorf("pending block not found: %s", blockID)
	}

	if !pending.addBLS(sig) {
		return fmt.Errorf("%w: %s (BLS)", errDuplicateSigner, sig.ValidatorID)
	}

	q.log.Debug("Added BLS signature",
		"blockID", blockID,
		"blsSigCount", len(pending.BLSSignatures),
		"threshold", q.threshold,
	)

	return nil
}

// AddCoronaSignature adds a Corona signature from another validator.
//
// The Corona leg is finalized on count alone (TryFinalize does not verify Corona
// signatures the way the BLS leg verifies its aggregate), so the count must be a
// count of DISTINCT validators or the post-quantum half of quantum finality is
// satisfied by one peer resending one signature.
func (q *Quasar) AddCoronaSignature(blockID ids.ID, sig *quasar.CoronaSignature) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return fmt.Errorf("pending block not found: %s", blockID)
	}

	if !pending.addCorona(sig) {
		return fmt.Errorf("%w: %s (Corona)", errDuplicateSigner, sig.ValidatorID)
	}

	q.log.Debug("Added Corona signature",
		"blockID", blockID,
		"coronaSigCount", len(pending.CoronaSignatures),
		"threshold", q.threshold,
	)

	return nil
}

// TryFinalize attempts to finalize a block if BOTH threshold signatures are collected.
// Quantum finality requires both BLS AND Corona thresholds to be met.
func (q *Quasar) TryFinalize(ctx context.Context, blockID ids.ID) (*quasar.AggregatedSignature, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return nil, false, fmt.Errorf("block %s not found", blockID)
	}
	qcore := q.quasar

	// Check BLS threshold
	if !pending.BLSFinalized {
		if len(pending.BLSSignatures) >= q.threshold {
			// Convert BLSSignatures to QuasarSigs for aggregation
			quasarSigs := make([]*quasar.QuasarSig, len(pending.BLSSignatures))
			for i, blsSig := range pending.BLSSignatures {
				quasarSigs[i] = &quasar.QuasarSig{
					BLS:         blsSig.Signature,
					ValidatorID: blsSig.ValidatorID,
					IsThreshold: blsSig.IsThreshold,
					SignerIndex: blsSig.SignerIndex,
				}
			}

			aggSig, err := qcore.AggregateSignaturesWithContext(ctx, pending.BlockHash, quasarSigs)
			if err != nil {
				return nil, false, fmt.Errorf("failed to aggregate BLS signatures: %w", err)
			}

			if qcore.VerifyAggregatedSignatureWithContext(ctx, pending.BlockHash, aggSig) {
				pending.BLSFinalized = true
				q.log.Debug("BLS threshold reached",
					"blockID", blockID,
					"count", len(pending.BLSSignatures),
				)
			}
		}
	}

	// Check Corona threshold
	if !pending.CoronaFinalized {
		if len(pending.CoronaSignatures) >= q.threshold {
			// Corona finalized when threshold reached
			pending.CoronaFinalized = true
			q.log.Debug("Corona threshold reached",
				"blockID", blockID,
				"count", len(pending.CoronaSignatures),
			)
		}
	}

	// Both must be finalized for quantum finality
	if pending.BLSFinalized && pending.CoronaFinalized {
		pending.Finalized = true
		q.finalizedBlocks[blockID] = true

		// Create aggregated signature with both components
		quasarSigs := make([]*quasar.QuasarSig, len(pending.BLSSignatures))
		for i, blsSig := range pending.BLSSignatures {
			quasarSigs[i] = &quasar.QuasarSig{
				BLS:         blsSig.Signature,
				ValidatorID: blsSig.ValidatorID,
				IsThreshold: blsSig.IsThreshold,
				SignerIndex: blsSig.SignerIndex,
			}
		}
		aggSig, _ := qcore.AggregateSignaturesWithContext(ctx, pending.BlockHash, quasarSigs)

		q.log.Info("═══════════════════════════════════════════════════════════════════")
		q.log.Info("║ Q-BLOCK FINALIZED with Quasar PQ-BFT                            ║")
		q.log.Info("║ Block ID:", log.Stringer("blockID", blockID))
		q.log.Info("║ Height:", log.Uint64("height", pending.Height))
		q.log.Info("║ BLS Signatures:", log.Int("count", len(pending.BLSSignatures)))
		q.log.Info("║ Corona Signatures:", log.Int("count", len(pending.CoronaSignatures)))
		q.log.Info("║ Quantum Finality:", log.Bool("complete", true))
		q.log.Info("═══════════════════════════════════════════════════════════════════")

		return aggSig, true, nil
	}

	q.log.Debug("Insufficient signatures for quantum finalization",
		"blockID", blockID,
		"blsHave", len(pending.BLSSignatures),
		"coronaHave", len(pending.CoronaSignatures),
		"blsFinalized", pending.BLSFinalized,
		"coronaFinalized", pending.CoronaFinalized,
		"need", q.threshold,
	)

	return nil, false, nil
}

// IsFinalized checks if a block has been finalized with BOTH signature types
func (q *Quasar) IsFinalized(blockID ids.ID) bool {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.finalizedBlocks[blockID]
}

// GetQuasar returns the underlying Quasar core engine
func (q *Quasar) GetQuasar() *quasar.Quasar {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.quasar
}

// GetThreshold returns the consensus threshold
func (q *Quasar) GetThreshold() int {
	return q.threshold
}

// GetActiveValidators returns the count of active validators
func (q *Quasar) GetActiveValidators() int {
	q.mu.RLock()
	defer q.mu.RUnlock()
	return q.quasar.GetActiveValidatorCount()
}

// AddValidator adds a new validator to the Quasar consensus
func (q *Quasar) AddValidator(validatorID string, weight uint64) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	_, err := q.quasar.AddValidator(validatorID, weight)
	if err != nil {
		return fmt.Errorf("failed to add validator: %w", err)
	}

	activeCount := q.quasar.GetActiveValidatorCount()

	q.log.Info("Validator added to Quasar PQ-BFT",
		"validatorID", validatorID,
		"weight", weight,
		"activeCount", activeCount,
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

// QuasarBridge is an alias for Quasar - the hybrid P/Q consensus bridge
// that connects P-Chain BLS + Q-Chain Corona for dual signature finality
type QuasarBridge = Quasar

// QuasarBridgeConfig is an alias for QuasarConfig
type QuasarBridgeConfig = QuasarConfig

// NewQuasarBridge creates a new Quasar bridge (alias for NewQuasar)
func NewQuasarBridge(cfg QuasarBridgeConfig) (*QuasarBridge, error) {
	return NewQuasar(cfg)
}
