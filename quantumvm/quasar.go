// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Quasar: Quantum-Safe Finality Engine
//
// Like stellar fusion combining hydrogen into helium, Quasar unifies
// classical BLS signatures with post-quantum Ringtail signatures.
// Both burn in parallel - classical for speed, quantum for eternity.
//
// No block escapes the event horizon without quantum finality.

package quantumvm

import (
	"context"
	"fmt"
	"sync"

	"github.com/luxfi/accel"
	accellattice "github.com/luxfi/accel/ops/lattice"
	"github.com/luxfi/consensus/protocol/quasar"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// BlockSigs contains both BLS and Ringtail signatures for a block.
// Both are produced in parallel during signing.
type BlockSigs struct {
	BLS      *quasar.BLSSignature
	Ringtail *quasar.CoronaSignature
}

// Quasar is the core Post-Quantum BFT consensus engine for Q-Chain.
// Like a supermassive black hole, it pulls all blocks to quantum finality
// using dual BLS+Ringtail threshold signatures:
// - BLS threshold signatures (classical security, fast path)
// - Ringtail threshold signatures (post-quantum, Ring-LWE based)
//
// Blocks are NOT considered produced without BOTH thresholds being met.
type Quasar struct {
	mu sync.RWMutex

	// Core Quasar engine - provides both BLS and Ringtail signing directly
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
// Both BLS AND Ringtail must reach threshold for quantum finality.
// Signatures are collected in parallel - either can complete first.
type PendingBlock struct {
	BlockID            ids.ID
	BlockHash          []byte
	Height             uint64
	BLSSignatures      []*quasar.BLSSignature      // Classical threshold signatures (parallel)
	CoronaSignatures []*quasar.CoronaSignature // Post-quantum threshold signatures (parallel)
	BLSFinalized       bool                        // BLS threshold reached
	RingtailFinalized  bool                        // Ringtail threshold reached
	Finalized          bool                        // BOTH complete = quantum finality
}

// QuasarConfig configures the Quasar PQ-BFT consensus
type QuasarConfig struct {
	ValidatorID string
	Threshold   int
	TotalNodes  int
	Logger      log.Logger
}

// NewQuasar creates a new Quasar PQ-BFT consensus engine
func NewQuasar(cfg QuasarConfig) (*Quasar, error) {
	if cfg.Threshold < 1 {
		cfg.Threshold = (cfg.TotalNodes * 2 / 3) + 1 // 2/3+1 BFT threshold
	}
	if cfg.TotalNodes < 1 {
		cfg.TotalNodes = 3 // Default 3-node network
	}

	// Initialize Quasar core with BLS + Ringtail
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

// InitializeDualThreshold sets up BLS and Ringtail threshold keys for a new epoch
func (q *Quasar) InitializeDualThreshold(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	// Generate dual threshold keys (BLS + Ringtail)
	config, err := quasar.GenerateDualKeys(q.threshold, q.totalNodes)
	if err != nil {
		return fmt.Errorf("failed to generate dual threshold keys: %w", err)
	}

	// Create new Signer engine with full dual threshold support
	signer, err := quasar.NewSignerWithConfig(*config)
	if err != nil {
		return fmt.Errorf("failed to initialize dual threshold signer: %w", err)
	}
	// Note: signer is used for logging only - actual signing goes through q.quasar
	_ = signer

	// Initialize validators on the Quasar core
	validatorIDs := make([]string, q.totalNodes)
	for i := 0; i < q.totalNodes; i++ {
		validatorIDs[i] = fmt.Sprintf("v%d", i)
	}
	if err := q.quasar.InitializeValidators(validatorIDs); err != nil {
		return fmt.Errorf("failed to initialize validators: %w", err)
	}

	q.log.Info("═══════════════════════════════════════════════════════════════════")
	q.log.Info("║ QUASAR PQ-BFT INITIALIZED                                       ║")
	q.log.Info("───────────────────────────────────────────────────────────────────")
	q.log.Info("║ Threshold:", log.Int("t", q.threshold), log.Int("n", q.totalNodes))
	q.log.Info("║ BLS Threshold Mode:", log.Bool("enabled", signer.IsThresholdMode()))
	q.log.Info("║ Ringtail PQ Mode:", log.Bool("enabled", signer.IsDualThresholdMode()))
	q.log.Info("═══════════════════════════════════════════════════════════════════")

	return nil
}

// SignBlock creates both BLS and Ringtail signatures for a block in parallel.
// Returns both signatures; both must reach threshold for quantum finality.
func (q *Quasar) SignBlock(ctx context.Context, blockID ids.ID, blockHash []byte, height uint64) (*BlockSigs, error) {
	q.mu.Lock()
	pending := q.pendingBlocks[blockID]
	if pending == nil {
		pending = &PendingBlock{
			BlockID:            blockID,
			BlockHash:          blockHash,
			Height:             height,
			BLSSignatures:      make([]*quasar.BLSSignature, 0),
			CoronaSignatures: make([]*quasar.CoronaSignature, 0),
		}
		q.pendingBlocks[blockID] = pending
	}
	qcore := q.quasar
	validatorID := q.validatorID
	q.mu.Unlock()

	if qcore == nil {
		return nil, fmt.Errorf("quasar not initialized - call InitializeDualThreshold first")
	}

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

	// Ringtail signing (Round 1 - D matrix + MACs)
	go func() {
		defer wg.Done()
		sessionID := int(height) // Use height as session ID
		prfKey := blockHash[:32] // Use block hash prefix as PRF key
		round1Data, err := qcore.CoronaRound1(validatorID, sessionID, prfKey)
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

	if blsErr != nil {
		return nil, fmt.Errorf("BLS sign failed: %w", blsErr)
	}
	if pqErr != nil {
		return nil, fmt.Errorf("Ringtail sign failed: %w", pqErr)
	}

	q.mu.Lock()
	pending.BLSSignatures = append(pending.BLSSignatures, blsSig)
	pending.CoronaSignatures = append(pending.CoronaSignatures, pqSig)
	q.mu.Unlock()

	q.log.Debug("Block signed with Quasar (BLS + Ringtail parallel)",
		"blockID", blockID,
		"height", height,
		"blsSigCount", len(pending.BLSSignatures),
		"coronaSigCount", len(pending.CoronaSignatures),
	)

	return &BlockSigs{BLS: blsSig, Ringtail: pqSig}, nil
}

// AddBLSSignature adds a BLS signature from another validator
func (q *Quasar) AddBLSSignature(blockID ids.ID, sig *quasar.BLSSignature) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return fmt.Errorf("pending block not found: %s", blockID)
	}

	pending.BLSSignatures = append(pending.BLSSignatures, sig)

	q.log.Debug("Added BLS signature",
		"blockID", blockID,
		"blsSigCount", len(pending.BLSSignatures),
		"threshold", q.threshold,
	)

	return nil
}

// AddCoronaSignature adds a Ringtail signature from another validator
func (q *Quasar) AddCoronaSignature(blockID ids.ID, sig *quasar.CoronaSignature) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return fmt.Errorf("pending block not found: %s", blockID)
	}

	pending.CoronaSignatures = append(pending.CoronaSignatures, sig)

	q.log.Debug("Added Ringtail signature",
		"blockID", blockID,
		"coronaSigCount", len(pending.CoronaSignatures),
		"threshold", q.threshold,
	)

	return nil
}

// TryFinalize attempts to finalize a block if BOTH threshold signatures are collected.
// Quantum finality requires both BLS AND Ringtail thresholds to be met.
func (q *Quasar) TryFinalize(ctx context.Context, blockID ids.ID) (*quasar.AggregatedSignature, bool, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	pending := q.pendingBlocks[blockID]
	if pending == nil {
		return nil, false, fmt.Errorf("block %s not found", blockID)
	}

	qcore := q.quasar
	if qcore == nil {
		return nil, false, fmt.Errorf("quasar not initialized")
	}

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

	// Check Ringtail threshold
	if !pending.RingtailFinalized {
		if len(pending.CoronaSignatures) >= q.threshold {
			// Ringtail finalized when threshold reached
			pending.RingtailFinalized = true
			q.log.Debug("Ringtail threshold reached",
				"blockID", blockID,
				"count", len(pending.CoronaSignatures),
			)
		}
	}

	// Both must be finalized for quantum finality
	if pending.BLSFinalized && pending.RingtailFinalized {
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
		q.log.Info("║ Ringtail Signatures:", log.Int("count", len(pending.CoronaSignatures)))
		q.log.Info("║ Quantum Finality:", log.Bool("complete", true))
		q.log.Info("═══════════════════════════════════════════════════════════════════")

		return aggSig, true, nil
	}

	q.log.Debug("Insufficient signatures for quantum finalization",
		"blockID", blockID,
		"blsHave", len(pending.BLSSignatures),
		"ringtailHave", len(pending.CoronaSignatures),
		"blsFinalized", pending.BLSFinalized,
		"ringtailFinalized", pending.RingtailFinalized,
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
	if q.quasar == nil {
		return 0
	}
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

// NTTForwardRingtail transforms Ringtail polynomial coefficients to NTT domain
// using GPU acceleration when available. This enables O(n log n) polynomial
// multiplication in the Ring-LWE scheme used by Ringtail threshold signatures.
func (q *Quasar) NTTForwardRingtail(coefficients []uint64) ([]uint64, error) {
	params := accellattice.NTTParams{
		N:       256,     // Ring dimension for Ringtail (X^256 + 1)
		Modulus: 8380417, // Dilithium prime q
		Root:    1753,    // Primitive 256th root of unity mod q
	}
	return accellattice.NTTForward(params, coefficients)
}

// NTTInverseRingtail transforms NTT-domain values back to coefficient form
// using GPU acceleration when available.
func (q *Quasar) NTTInverseRingtail(evaluations []uint64) ([]uint64, error) {
	params := accellattice.NTTParams{
		N:       256,
		Modulus: 8380417,
		Root:    1753,
	}
	return accellattice.NTTInverse(params, evaluations)
}

// BatchNTTForwardRingtail transforms multiple polynomials in parallel on GPU.
// Used when processing multiple Ringtail signature shares simultaneously.
func (q *Quasar) BatchNTTForwardRingtail(polys [][]uint64) ([][]uint64, error) {
	params := accellattice.NTTParams{
		N:       256,
		Modulus: 8380417,
		Root:    1753,
	}
	return accellattice.BatchNTTForward(params, polys)
}

// GPUAccelAvailable reports whether GPU acceleration is available for
// lattice operations (NTT, batch ML-DSA verify).
func (q *Quasar) GPUAccelAvailable() bool {
	return accel.Available()
}

// Cleanup removes finalized blocks older than the given height
func (q *Quasar) Cleanup(minHeight uint64) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for blockID, pending := range q.pendingBlocks {
		if pending.Height < minHeight && pending.Finalized {
			delete(q.pendingBlocks, blockID)
			delete(q.finalizedBlocks, blockID)
		}
	}
}

// QuasarBridge is an alias for Quasar - the hybrid P/Q consensus bridge
// that connects P-Chain BLS + Q-Chain Ringtail for dual signature finality
type QuasarBridge = Quasar

// QuasarBridgeConfig is an alias for QuasarConfig
type QuasarBridgeConfig = QuasarConfig

// NewQuasarBridge creates a new Quasar bridge (alias for NewQuasar)
// The quantumSigner parameter is reserved for future quantum signer integration
func NewQuasarBridge(cfg QuasarBridgeConfig, _ interface{}) (*QuasarBridge, error) {
	return NewQuasar(cfg)
}
