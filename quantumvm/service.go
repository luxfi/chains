// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"context"
	"errors"
	"fmt"
	"net/http"

	"encoding/json"

	"github.com/luxfi/ids"
	"github.com/luxfi/chains/quantumvm/quantum"
)

// Service provides QVM RPC service
type Service struct {
	vm *VM
}

// GetBlockArgs are the arguments for GetBlock
type GetBlockArgs struct {
	BlockID string `json:"blockID"`
}

// GetBlockReply is the reply for GetBlock
type GetBlockReply struct {
	Block      json.RawMessage `json:"block"`
	Height     uint64          `json:"height"`
	Timestamp  int64           `json:"timestamp"`
	TxCount    int             `json:"txCount"`
	QuantumSig bool            `json:"quantumSig"`
}

// GetBlock returns a block by ID
func (s *Service) GetBlock(r *http.Request, args *GetBlockArgs, reply *GetBlockReply) error {
	blockID, err := ids.FromString(args.BlockID)
	if err != nil {
		return fmt.Errorf("invalid block ID: %w", err)
	}

	block, err := s.vm.GetBlock(context.Background(), blockID)
	if err != nil {
		return fmt.Errorf("failed to get block: %w", err)
	}

	qBlock, ok := block.(*Block)
	if !ok {
		return errors.New("invalid block type")
	}

	blockData, err := json.Marshal(map[string]interface{}{
		"id":       qBlock.ID().String(),
		"parentID": qBlock.parentID.String(),
		"height":   qBlock.height,
	})
	if err != nil {
		return err
	}

	reply.Block = blockData
	reply.Height = qBlock.height
	reply.Timestamp = qBlock.timestamp.Unix()
	reply.TxCount = len(qBlock.transactions)
	reply.QuantumSig = qBlock.quantumSignature != nil

	return nil
}

// GenerateRingtailKeyArgs are the arguments for GenerateRingtailKey
type GenerateRingtailKeyArgs struct{}

// GenerateRingtailKeyReply is the reply for GenerateRingtailKey
type GenerateRingtailKeyReply struct {
	PublicKey string `json:"publicKey"`
	Version   uint32 `json:"version"`
	KeySize   int    `json:"keySize"`
}

// GenerateRingtailKey generates a new Ringtail key pair
func (s *Service) GenerateRingtailKey(r *http.Request, args *GenerateRingtailKeyArgs, reply *GenerateRingtailKeyReply) error {
	if !s.vm.Config.RingtailEnabled {
		return errors.New("ringtail keys are not enabled")
	}

	key, err := s.vm.quantumSigner.GenerateRingtailKey()
	if err != nil {
		return fmt.Errorf("failed to generate ringtail key: %w", err)
	}

	reply.PublicKey = fmt.Sprintf("%x", key.PublicKey)
	reply.Version = key.Version
	reply.KeySize = len(key.PublicKey)

	return nil
}

// SignWithQuantumArgs are the arguments for SignWithQuantum
type SignWithQuantumArgs struct {
	Message    string `json:"message"`
	PrivateKey string `json:"privateKey"`
}

// SignWithQuantumReply is the reply for SignWithQuantum
type SignWithQuantumReply struct {
	Signature string `json:"signature"`
	Algorithm uint32 `json:"algorithm"`
	Timestamp int64  `json:"timestamp"`
}

// SignWithQuantum signs a message with quantum signature
func (s *Service) SignWithQuantum(r *http.Request, args *SignWithQuantumArgs, reply *SignWithQuantumReply) error {
	if !s.vm.Config.QuantumStampEnabled {
		return errors.New("quantum signatures are not enabled")
	}

	// This would typically validate the private key and create proper signature
	// For security reasons, this is a simplified example
	return errors.New("direct signing not supported via RPC")
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

// GetPendingTransactionsReply is the reply for GetPendingTransactions
type GetPendingTransactionsReply struct {
	Transactions []json.RawMessage `json:"transactions"`
	Count        int               `json:"count"`
}

// GetPendingTransactions returns pending transactions
func (s *Service) GetPendingTransactions(r *http.Request, args *GetPendingTransactionsArgs, reply *GetPendingTransactionsReply) error {
	limit := args.Limit
	if limit <= 0 || limit > 100 {
		limit = 100
	}

	txs := s.vm.txPool.GetPendingTransactions(limit)
	reply.Transactions = make([]json.RawMessage, len(txs))

	for i, tx := range txs {
		txData, err := json.Marshal(map[string]interface{}{
			"id":        tx.ID().String(),
			"timestamp": tx.Timestamp().Unix(),
		})
		if err != nil {
			return err
		}
		reply.Transactions[i] = txData
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
	RingtailEnabled bool   `json:"ringtailEnabled"`
	PendingTxCount  int    `json:"pendingTxCount"`
	ParallelWorkers int    `json:"parallelWorkers"`
}

// GetHealth returns the health status of the QVM
func (s *Service) GetHealth(r *http.Request, args *GetHealthArgs, reply *GetHealthReply) error {
	health, err := s.vm.HealthCheck(context.Background())
	if err != nil {
		return err
	}

	reply.Healthy = health.Healthy
	reply.Version = health.Details["version"]
	reply.QuantumEnabled = s.vm.Config.QuantumStampEnabled
	reply.RingtailEnabled = s.vm.Config.RingtailEnabled
	reply.PendingTxCount = s.vm.txPool.PendingCount()
	reply.ParallelWorkers = s.vm.parallelWorkers

	return nil
}

// GetConfigArgs are the arguments for GetConfig
type GetConfigArgs struct{}

// GetConfigReply is the reply for GetConfig
type GetConfigReply struct {
	TxFee                   uint64 `json:"txFee"`
	CreateAssetTxFee        uint64 `json:"createAssetTxFee"`
	QuantumVerificationFee  uint64 `json:"quantumVerificationFee"`
	MaxParallelTxs          int    `json:"maxParallelTxs"`
	QuantumAlgorithmVersion uint32 `json:"quantumAlgorithmVersion"`
	RingtailKeySize         int    `json:"ringtailKeySize"`
	QuantumStampEnabled     bool   `json:"quantumStampEnabled"`
	RingtailEnabled         bool   `json:"ringtailEnabled"`
	ParallelBatchSize       int    `json:"parallelBatchSize"`
}

// GetConfig returns the QVM configuration
func (s *Service) GetConfig(r *http.Request, args *GetConfigArgs, reply *GetConfigReply) error {
	reply.TxFee = s.vm.Config.TxFee
	reply.CreateAssetTxFee = s.vm.Config.CreateAssetTxFee
	reply.QuantumVerificationFee = s.vm.Config.QuantumVerificationFee
	reply.MaxParallelTxs = s.vm.Config.MaxParallelTxs
	reply.QuantumAlgorithmVersion = s.vm.Config.QuantumAlgorithmVersion
	reply.RingtailKeySize = s.vm.Config.RingtailKeySize
	reply.QuantumStampEnabled = s.vm.Config.QuantumStampEnabled
	reply.RingtailEnabled = s.vm.Config.RingtailEnabled
	reply.ParallelBatchSize = s.vm.Config.ParallelBatchSize

	return nil
}
