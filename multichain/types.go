// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package multichain

import (
	"context"
	"errors"
)

// ChainID identifies which sub-chain a transaction targets.
type ChainID uint8

const (
	ChainC ChainID = iota // C-Chain — primary EVM
	ChainD                // D-Chain — DEX (CLOB + AMM)
	ChainF                // F-Chain — FHE / encrypted compute
)

// CrossChainBatch is the input to ExecuteBlock. It carries the per-chain
// transaction sets that need to land in the same atomic block.
type CrossChainBatch struct {
	// CChainTxs are EVM transactions. Their precompile calls into 0x9010
	// (PoolManager), 0x9012 (SwapRouter), 0x9020 (CLOB) route to the
	// D-Chain handler in shared MvMemory; calls into the FHE precompile
	// range route to the F-Chain handler. Phase 1 coordinates this via
	// host dispatch; Phase 2 inlines it in a single GPU kernel.
	CChainTxs []EVMTx

	// DChainOps are direct DEX operations (limit orders, market orders,
	// AMM swaps) submitted to D-Chain without going through an EVM call.
	DChainOps []DEXOp

	// FChainOps are direct FHE compute operations.
	FChainOps []FHEOp

	// CrossRefs declares dependencies between transactions across chains.
	// A C-Chain tx that calls the CLOB precompile creates an implicit
	// CrossRef from the EVM transaction to the resulting D-Chain trade.
	// Block sealing fails if any declared CrossRef is unresolved.
	CrossRefs []CrossRef

	// Deadline bounds total wall-clock budget for the block. After
	// Deadline elapses the builder stops accepting new dispatches and
	// seals whatever atomic prefix completed.
	Deadline context.Context
}

// EVMTx is a typed wrapper to keep the multichain API independent of any
// specific EVM tx encoding. The host code marshals it to the cevm
// Transaction shape before dispatch.
type EVMTx struct {
	Raw  []byte // RLP or canonical wire encoding
	Hash [32]byte
}

// DEXOp is a direct DEX-chain operation.
type DEXOp struct {
	Kind    DEXOpKind
	Payload []byte // ZAP-encoded operation body
	Hash    [32]byte
}

// DEXOpKind enumerates the operations the D-Chain block builder accepts.
type DEXOpKind uint8

const (
	DEXOpUnknown DEXOpKind = iota
	DEXOpPlaceLimit
	DEXOpPlaceMarket
	DEXOpCancel
	DEXOpAMMSwap
	DEXOpAMMAddLiquidity
	DEXOpAMMRemoveLiquidity
)

// FHEOp is a direct F-Chain operation.
type FHEOp struct {
	Kind    FHEOpKind
	Payload []byte
	Hash    [32]byte
}

// FHEOpKind enumerates encrypted-compute ops the F-Chain handles.
type FHEOpKind uint8

const (
	FHEOpUnknown FHEOpKind = iota
	FHEOpEncrypt
	FHEOpDecrypt
	FHEOpAdd
	FHEOpSub
	FHEOpMul
	FHEOpBootstrap
)

// CrossRef declares "the result of From's execution feeds Into".
// Block sealing verifies every CrossRef resolved with concrete state
// writes; an unresolved CrossRef means a chain's kernel exited early
// and the block is incomplete.
type CrossRef struct {
	From ChainID
	FromHash [32]byte
	Into ChainID
	IntoHash [32]byte
}

// Receipt is the per-tx outcome surfaced to gossip + to the local trie.
type Receipt struct {
	Chain    ChainID
	TxHash   [32]byte
	Status   uint8 // 0=success, 1=revert, see EVM_GPU_TX_*
	GasUsed  uint64
	Logs     [][]byte // ZAP-encoded log entries
	CrossOut []CrossRef // CrossRefs produced by executing this tx
}

// MultiChainBlock is the sealed atomic output. The three sub-blocks are
// opaque ZAP-encoded byte buffers — the host never inspects their
// contents during construction. They get gossiped through the configured
// transport and verified independently on the receiving side.
type MultiChainBlock struct {
	CChainBlock []byte
	DChainBlock []byte
	FChainBlock []byte
	Receipts    []Receipt
	StateRoots  [3][32]byte // [ChainC, ChainD, ChainF]
}

// BlockBuilder runs cross-chain blocks. Implementations live alongside
// this package (see builder.go for the host-coordinated default).
type BlockBuilder interface {
	// ExecuteBlock runs the batch atomically. Returns the sealed block or
	// an error. The implementation never partially commits: either every
	// CrossRef resolves and every sub-chain seals, or the whole block is
	// rejected and the input is returned for re-dispatch.
	ExecuteBlock(ctx context.Context, batch CrossChainBatch) (*MultiChainBlock, error)

	// Close releases any resources held by the builder (GPU sessions,
	// MvMemory namespaces, transport handles).
	Close() error
}

// ErrCrossRefUnresolved is returned when a declared CrossRef has no
// matching state write at seal time. Indicates the cross-chain dispatch
// failed mid-block; the caller must re-dispatch or surface the error.
var ErrCrossRefUnresolved = errors.New("multichain: CrossRef unresolved at seal")

// ErrChainKernelFailed is returned when one of the per-chain kernels
// reports a hard error (OOM, ABI mismatch, GPU device gone). Distinct
// from per-tx revert.
var ErrChainKernelFailed = errors.New("multichain: chain kernel reported hard error")
