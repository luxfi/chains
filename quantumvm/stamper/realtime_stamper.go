// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Real-time Q-Chain Quantum Stamping for Live Block Production

package stamper

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/ethdb"
	"github.com/luxfi/geth/event"
	"github.com/luxfi/log"
)

var (
	ErrAlreadyRunning = errors.New("realtime stamper already running")
	ErrNotRunning     = errors.New("realtime stamper not running")
	ErrNoBlockchain   = errors.New("blockchain not configured")
)

// RealtimeStamperConfig configuration for real-time quantum stamping
type RealtimeStamperConfig struct {
	Mode             QuantumStampMode
	CacheSize        int
	StampingInterval time.Duration // Minimum interval between stamps
	BatchSize        int           // Number of blocks to batch stamp
	VerifyPrevious   bool          // Verify previous stamps on startup
	PersistenceDB    ethdb.Database
	EnableMetrics    bool
}

// RealtimeQuantumStamper provides real-time quantum stamping for C-Chain blocks
type RealtimeQuantumStamper struct {
	stamper    *QuantumStamper
	blockchain *core.BlockChain
	config     *RealtimeStamperConfig
	logger     log.Logger

	// Block subscription
	blockChan chan *types.Block
	blockSub  event.Subscription
	headChan  chan core.ChainHeadEvent
	headSub   event.Subscription

	// Control
	ctx     context.Context
	cancel  context.CancelFunc
	running bool
	mu      sync.RWMutex

	// Batching
	batchMu    sync.Mutex
	batch      []*types.Block
	batchTimer *time.Timer

	// Metrics
	metrics *StamperMetrics
}

// StamperMetrics tracks stamping performance metrics
type StamperMetrics struct {
	BlocksReceived    uint64
	BlocksStamped     uint64
	BlocksVerified    uint64
	StampingErrors    uint64
	AvgStampingTimeMs float64
	LastStampedHeight uint64
	LastStampedHash   common.Hash
	QChainHeight      uint64
}

// NewRealtimeQuantumStamper creates a new real-time quantum stamper
func NewRealtimeQuantumStamper(
	logger log.Logger,
	blockchain *core.BlockChain,
	config *RealtimeStamperConfig,
) (*RealtimeQuantumStamper, error) {
	if blockchain == nil {
		return nil, ErrNoBlockchain
	}

	// Create base stamper
	stamper, err := NewQuantumStamper(logger, config.Mode, config.CacheSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create quantum stamper: %w", err)
	}

	rts := &RealtimeQuantumStamper{
		stamper:    stamper,
		blockchain: blockchain,
		config:     config,
		logger:     logger,
		blockChan:  make(chan *types.Block, 100),
		batch:      make([]*types.Block, 0, config.BatchSize),
		metrics:    &StamperMetrics{},
	}

	// Verify previous stamps if configured
	if config.VerifyPrevious {
		if err := rts.verifyHistoricalStamps(); err != nil {
			logger.Warn("Historical stamp verification failed", "error", err)
		}
	}

	return rts, nil
}

// Start begins real-time quantum stamping
func (rts *RealtimeQuantumStamper) Start() error {
	rts.mu.Lock()
	defer rts.mu.Unlock()

	if rts.running {
		return ErrAlreadyRunning
	}

	rts.logger.Info("Starting real-time quantum stamper",
		"mode", rts.config.Mode,
		"interval", rts.config.StampingInterval,
		"batchSize", rts.config.BatchSize)

	// Create context for lifecycle management
	rts.ctx, rts.cancel = context.WithCancel(context.Background())

	// Subscribe to new blocks
	rts.headChan = make(chan core.ChainHeadEvent, 10)
	rts.headSub = rts.blockchain.SubscribeChainHeadEvent(rts.headChan)

	// Start workers
	go rts.blockProcessor()
	go rts.stampingWorker()
	go rts.metricsReporter()

	rts.running = true
	rts.logger.Info("Real-time quantum stamper started")

	return nil
}

// Stop halts real-time quantum stamping
func (rts *RealtimeQuantumStamper) Stop() error {
	rts.mu.Lock()
	defer rts.mu.Unlock()

	if !rts.running {
		return ErrNotRunning
	}

	rts.logger.Info("Stopping real-time quantum stamper")

	// Cancel context
	rts.cancel()

	// Unsubscribe from events
	if rts.headSub != nil {
		rts.headSub.Unsubscribe()
	}

	// Process any remaining batch
	rts.processBatch()

	// Close channels
	close(rts.blockChan)
	if rts.headChan != nil {
		close(rts.headChan)
	}

	// Close base stamper
	rts.stamper.Close()

	rts.running = false
	rts.logger.Info("Real-time quantum stamper stopped")

	return nil
}

// blockProcessor handles incoming blocks
func (rts *RealtimeQuantumStamper) blockProcessor() {
	for {
		select {
		case <-rts.ctx.Done():
			return

		case event, ok := <-rts.headChan:
			if !ok {
				return
			}

			rts.metrics.BlocksReceived++
			// Get the block from the header
			block := rts.blockchain.GetBlock(event.Header.Hash(), event.Header.Number.Uint64())
			if block == nil {
				rts.logger.Error("Failed to get block", "hash", event.Header.Hash(), "number", event.Header.Number)
				continue
			}

			// Add to batch
			rts.batchMu.Lock()
			rts.batch = append(rts.batch, block)

			// Check if batch is full
			if len(rts.batch) >= rts.config.BatchSize {
				rts.processBatch()
			} else if rts.batchTimer == nil {
				// Start batch timer
				rts.batchTimer = time.AfterFunc(rts.config.StampingInterval, func() {
					rts.batchMu.Lock()
					defer rts.batchMu.Unlock()
					rts.processBatch()
				})
			}
			rts.batchMu.Unlock()

			// Log important blocks
			if block.NumberU64()%1000 == 0 {
				rts.logger.Info("Processing milestone block",
					"height", block.NumberU64(),
					"hash", block.Hash().Hex())
			}
		}
	}
}

// processBatch stamps a batch of blocks
func (rts *RealtimeQuantumStamper) processBatch() {
	if len(rts.batch) == 0 {
		return
	}

	startTime := time.Now()
	blocks := rts.batch
	rts.batch = make([]*types.Block, 0, rts.config.BatchSize)

	// Cancel timer if running
	if rts.batchTimer != nil {
		rts.batchTimer.Stop()
		rts.batchTimer = nil
	}

	// Stamp blocks in parallel
	var wg sync.WaitGroup
	stampChan := make(chan *stampResult, len(blocks))

	for _, block := range blocks {
		wg.Add(1)
		go func(b *types.Block) {
			defer wg.Done()

			stamp, err := rts.stamper.StampBlock(b)
			stampChan <- &stampResult{
				block: b,
				stamp: stamp,
				err:   err,
			}
		}(block)
	}

	// Wait for all stamps
	go func() {
		wg.Wait()
		close(stampChan)
	}()

	// Collect results
	successCount := 0
	for result := range stampChan {
		if result.err != nil {
			rts.logger.Warn("Failed to stamp block",
				"height", result.block.NumberU64(),
				"error", result.err)
			rts.metrics.StampingErrors++
		} else {
			successCount++
			rts.metrics.BlocksStamped++
			rts.metrics.LastStampedHeight = result.block.NumberU64()
			rts.metrics.LastStampedHash = result.block.Hash()
			rts.metrics.QChainHeight = result.stamp.QChainHeight

			// Persist stamp if configured
			if rts.config.PersistenceDB != nil {
				rts.persistStamp(result.stamp)
			}
		}
	}

	// Update metrics
	duration := time.Since(startTime)
	avgMs := float64(duration.Milliseconds()) / float64(len(blocks))
	rts.metrics.AvgStampingTimeMs = (rts.metrics.AvgStampingTimeMs + avgMs) / 2

	rts.logger.Info("Batch stamping completed",
		"blocks", len(blocks),
		"success", successCount,
		"duration", duration,
		"avgMs", avgMs)
}

type stampResult struct {
	block *types.Block
	stamp *QuantumStamp
	err   error
}

// stampingWorker handles continuous stamping
func (rts *RealtimeQuantumStamper) stampingWorker() {
	ticker := time.NewTicker(rts.config.StampingInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rts.ctx.Done():
			return

		case <-ticker.C:
			// Force batch processing if any blocks pending
			rts.batchMu.Lock()
			if len(rts.batch) > 0 {
				rts.processBatch()
			}
			rts.batchMu.Unlock()
		}
	}
}

// metricsReporter periodically reports metrics
func (rts *RealtimeQuantumStamper) metricsReporter() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-rts.ctx.Done():
			return

		case <-ticker.C:
			rts.reportMetrics()
		}
	}
}

// reportMetrics logs current metrics
func (rts *RealtimeQuantumStamper) reportMetrics() {
	rts.mu.RLock()
	metrics := *rts.metrics
	rts.mu.RUnlock()

	successRate := float64(0)
	if metrics.BlocksReceived > 0 {
		successRate = float64(metrics.BlocksStamped) * 100 / float64(metrics.BlocksReceived)
	}

	rts.logger.Info("Quantum stamping metrics",
		"received", metrics.BlocksReceived,
		"stamped", metrics.BlocksStamped,
		"verified", metrics.BlocksVerified,
		"errors", metrics.StampingErrors,
		"successRate", fmt.Sprintf("%.2f%%", successRate),
		"avgTimeMs", fmt.Sprintf("%.2f", metrics.AvgStampingTimeMs),
		"lastHeight", metrics.LastStampedHeight,
		"qHeight", metrics.QChainHeight)
}

// verifyHistoricalStamps verifies stamps from previous runs
func (rts *RealtimeQuantumStamper) verifyHistoricalStamps() error {
	if rts.config.PersistenceDB == nil {
		return nil
	}

	rts.logger.Info("Verifying historical quantum stamps...")

	// Get current chain head
	head := rts.blockchain.CurrentBlock()
	if head == nil {
		return errors.New("no chain head")
	}

	verifiedCount := 0
	failedCount := 0
	startHeight := uint64(0)

	if head.Number.Uint64() > 1000 {
		startHeight = head.Number.Uint64() - 1000
	}

	// Verify last 1000 blocks
	for height := startHeight; height <= head.Number.Uint64(); height++ {
		block := rts.blockchain.GetBlockByNumber(height)
		if block == nil {
			continue
		}

		// Load stamp from persistence
		stamp, err := rts.loadStamp(block.Hash())
		if err != nil {
			continue // No stamp found
		}

		// Verify stamp
		if rts.stamper.VerifyStamp(stamp, block) {
			verifiedCount++
			rts.metrics.BlocksVerified++
		} else {
			failedCount++
			rts.logger.Warn("Historical stamp verification failed",
				"height", height,
				"hash", block.Hash().Hex())
		}
	}

	rts.logger.Info("Historical verification complete",
		"verified", verifiedCount,
		"failed", failedCount)

	return nil
}

// persistStamp saves a quantum stamp to persistence database
func (rts *RealtimeQuantumStamper) persistStamp(stamp *QuantumStamp) error {
	if rts.config.PersistenceDB == nil {
		return nil
	}

	key := append([]byte("qstamp-realtime-"), stamp.CChainHash.Bytes()...)
	data, err := encodeStamp(stamp)
	if err != nil {
		return err
	}

	return rts.config.PersistenceDB.Put(key, data)
}

// loadStamp loads a quantum stamp from persistence database
func (rts *RealtimeQuantumStamper) loadStamp(blockHash common.Hash) (*QuantumStamp, error) {
	if rts.config.PersistenceDB == nil {
		return nil, errors.New("no persistence database")
	}

	key := append([]byte("qstamp-realtime-"), blockHash.Bytes()...)
	data, err := rts.config.PersistenceDB.Get(key)
	if err != nil {
		return nil, err
	}

	return decodeStamp(data)
}

// GetMetrics returns current metrics
func (rts *RealtimeQuantumStamper) GetMetrics() *StamperMetrics {
	rts.mu.RLock()
	defer rts.mu.RUnlock()

	metrics := *rts.metrics
	return &metrics
}

// VerifyBlock verifies quantum stamp for a specific block
func (rts *RealtimeQuantumStamper) VerifyBlock(blockHash common.Hash) (bool, error) {
	// Get block from blockchain
	block := rts.blockchain.GetBlockByHash(blockHash)
	if block == nil {
		return false, errors.New("block not found")
	}

	// Check cache first
	stamp, found := rts.stamper.GetStampForBlock(blockHash)
	if !found {
		// Try loading from persistence
		var err error
		stamp, err = rts.loadStamp(blockHash)
		if err != nil {
			return false, fmt.Errorf("stamp not found: %w", err)
		}
	}

	// Verify stamp
	valid := rts.stamper.VerifyStamp(stamp, block)
	if valid {
		rts.metrics.BlocksVerified++
	}

	return valid, nil
}

// GetStampInfo returns quantum stamp information for a block
func (rts *RealtimeQuantumStamper) GetStampInfo(blockHash common.Hash) (map[string]interface{}, error) {
	stamp, found := rts.stamper.GetStampForBlock(blockHash)
	if !found {
		// Try loading from persistence
		var err error
		stamp, err = rts.loadStamp(blockHash)
		if err != nil {
			return nil, fmt.Errorf("stamp not found: %w", err)
		}
	}

	info := map[string]interface{}{
		"cchain_height": stamp.CChainHeight,
		"cchain_hash":   stamp.CChainHash.Hex(),
		"qchain_height": stamp.QChainHeight,
		"qchain_hash":   stamp.QChainHash.Hex(),
		"mode":          stamp.Mode,
		"timestamp":     stamp.Timestamp.Format(time.RFC3339),
		"state_root":    stamp.StateRoot.Hex(),
		"receipts_root": stamp.ReceiptsRoot.Hex(),
		"gas_used":      stamp.GasUsed,
	}

	// Add signature info
	if len(stamp.MLDSASignature) > 0 {
		info["mldsa_sig_size"] = len(stamp.MLDSASignature)
		info["mldsa_pubkey_size"] = len(stamp.PublicKeyML)
	}
	if len(stamp.SLHDSASignature) > 0 {
		info["slhdsa_sig_size"] = len(stamp.SLHDSASignature)
		info["slhdsa_pubkey_size"] = len(stamp.PublicKeySLH)
	}

	return info, nil
}

// Helper functions for stamp encoding/decoding
func encodeStamp(stamp *QuantumStamp) ([]byte, error) {
	// Simplified encoding
	data := make([]byte, 0, 1024)

	// Add fields...
	// This is simplified - implement proper encoding

	return data, nil
}

func decodeStamp(data []byte) (*QuantumStamp, error) {
	// Simplified decoding
	stamp := &QuantumStamp{}

	// Decode fields...
	// This is simplified - implement proper decoding

	return stamp, nil
}
