// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/ids"
)

// Service provides QVM RPC service
type Service struct {
	vm *VM
}

// GetBlockArgs are the arguments for GetBlock
type GetBlockArgs struct {
	BlockID string `json:"blockID"`
}

// BlockSummary is how a block appears over RPC.
type BlockSummary struct {
	ID       string `json:"id"`
	ParentID string `json:"parentID"`
	Height   uint64 `json:"height"`
}

// GetBlockReply is the reply for GetBlock
type GetBlockReply struct {
	Block      BlockSummary `json:"block"`
	Height     uint64       `json:"height"`
	Timestamp  int64        `json:"timestamp"`
	TxCount    int          `json:"txCount"`
	QuantumSig bool         `json:"quantumSig"`
}

// GetBlock returns a block by ID
func (s *Service) GetBlock(r *http.Request, args *GetBlockArgs, reply *GetBlockReply) error {
	blockID, err := ids.FromString(args.BlockID)
	if err != nil {
		return fmt.Errorf("invalid block ID: %w", err)
	}

	block, err := s.vm.block(blockID)
	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	reply.Block = BlockSummary{
		ID:       block.ID().String(),
		ParentID: block.parentID.String(),
		Height:   block.height,
	}
	reply.Height = block.height
	reply.Timestamp = block.timestamp.Unix()
	reply.TxCount = len(block.transactions)
	reply.QuantumSig = false // blocks carry no stamp; see signBlockWithQuasar

	return nil
}

// GenerateCoronaKeyArgs are the arguments for GenerateCoronaKey
type GenerateCoronaKeyArgs struct{}

// GenerateCoronaKeyReply is the reply for GenerateCoronaKey
type GenerateCoronaKeyReply struct {
	PublicKey string `json:"publicKey"`
	Version   uint32 `json:"version"`
	KeySize   int    `json:"keySize"`
}

// GenerateCoronaKey generates a new Corona key pair
func (s *Service) GenerateCoronaKey(r *http.Request, args *GenerateCoronaKeyArgs, reply *GenerateCoronaKeyReply) error {
	if !s.vm.Config.CoronaEnabled {
		return errors.New("corona keys are not enabled")
	}

	key, err := s.vm.quantumSigner.GenerateCoronaKey()
	if err != nil {
		return fmt.Errorf("failed to generate corona key: %w", err)
	}

	reply.PublicKey = fmt.Sprintf("%x", key.PublicKey)
	reply.Version = key.Version
	reply.KeySize = len(key.PublicKey)

	return nil
}

// VerifyQuantumSignatureArgs are the arguments for VerifyQuantumSignature
type VerifyQuantumSignatureArgs struct {
	Message   string          `json:"message"`
	Signature json.RawMessage `json:"signature"`
}

// VerifyQuantumSignatureReply is the reply for VerifyQuantumSignature
type VerifyQuantumSignatureReply struct {
	Valid     bool   `json:"valid"`
	Algorithm uint32 `json:"algorithm"`
}

// VerifyQuantumSignature verifies a quantum signature
func (s *Service) VerifyQuantumSignature(r *http.Request, args *VerifyQuantumSignatureArgs, reply *VerifyQuantumSignatureReply) error {
	if !s.vm.Config.QuantumStampEnabled {
		return errors.New("quantum signatures are not enabled")
	}

	// Parse signature
	var sig quantum.QuantumSignature
	if err := json.Unmarshal(args.Signature, &sig); err != nil {
		return fmt.Errorf("failed to parse signature: %w", err)
	}

	// Verify signature
	err := s.vm.quantumSigner.Verify([]byte(args.Message), &sig)
	reply.Valid = err == nil
	reply.Algorithm = sig.Algorithm

	return nil
}

// GetPendingTransactionsArgs are the arguments for GetPendingTransactions
type GetPendingTransactionsArgs struct {
	Limit int `json:"limit"`
}

// TransactionSummary is how a pending transaction appears over RPC.
type TransactionSummary struct {
	ID        string `json:"id"`
	Timestamp int64  `json:"timestamp"`
}

// GetPendingTransactionsReply is the reply for GetPendingTransactions
type GetPendingTransactionsReply struct {
	Transactions []TransactionSummary `json:"transactions"`
	Count        int                  `json:"count"`
}

// GetPendingTransactions returns pending transactions
func (s *Service) GetPendingTransactions(r *http.Request, args *GetPendingTransactionsArgs, reply *GetPendingTransactionsReply) error {
	limit := args.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	txs := s.vm.txPool.GetPendingTransactions(limit)
	reply.Transactions = make([]TransactionSummary, len(txs))

	for i, tx := range txs {
		reply.Transactions[i] = TransactionSummary{
			ID:        tx.ID().String(),
			Timestamp: tx.Timestamp().Unix(),
		}
	}

	reply.Count = len(txs)
	return nil
}

// GetHealthArgs are the arguments for GetHealth
type GetHealthArgs struct{}

// GetHealthReply is the reply for GetHealth
type GetHealthReply struct {
	Healthy         bool   `json:"healthy"`
	Version         string `json:"version"`
	QuantumEnabled  bool   `json:"quantumEnabled"`
	CoronaEnabled   bool   `json:"coronaEnabled"`
	PendingTxCount  int    `json:"pendingTxCount"`
	ParallelWorkers int    `json:"parallelWorkers"`
}

// GetHealth returns the health status of the QVM
func (s *Service) GetHealth(r *http.Request, args *GetHealthArgs, reply *GetHealthReply) error {
	health := s.vm.health()

	reply.Healthy = health.Healthy
	reply.Version = health.Details["version"]
	reply.QuantumEnabled = s.vm.Config.QuantumStampEnabled
	reply.CoronaEnabled = s.vm.Config.CoronaEnabled
	reply.PendingTxCount = s.vm.txPool.PendingCount()
	reply.ParallelWorkers = s.vm.Config.MaxParallelTxs

	return nil
}

// GetConfigArgs are the arguments for GetConfig
type GetConfigArgs struct{}

// GetConfigReply is the reply for GetConfig. It reports what actually governs
// the chain — no fee schedule, because Q-Chain charges none (LP-0130 §6).
type GetConfigReply struct {
	MaxParallelTxs          int    `json:"maxParallelTxs"`
	QuantumAlgorithmVersion uint32 `json:"quantumAlgorithmVersion"`
	QuantumStampEnabled     bool   `json:"quantumStampEnabled"`
	CoronaEnabled           bool   `json:"coronaEnabled"`
	ParallelBatchSize       int    `json:"parallelBatchSize"`
}

// GetConfig returns the QVM configuration
func (s *Service) GetConfig(r *http.Request, args *GetConfigArgs, reply *GetConfigReply) error {
	reply.MaxParallelTxs = s.vm.Config.MaxParallelTxs
	reply.QuantumAlgorithmVersion = s.vm.Config.QuantumAlgorithmVersion
	reply.QuantumStampEnabled = s.vm.Config.QuantumStampEnabled
	reply.CoronaEnabled = s.vm.Config.CoronaEnabled
	reply.ParallelBatchSize = s.vm.Config.ParallelBatchSize

	return nil
}
