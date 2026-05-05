// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package parallel — cevm BlockExecutor for github.com/luxfi/evm.
//
// LP-108 (2026-05-04) ENSURE step: the per-tx TransactionExecutor
// abstraction in luxfi/evm/core/parallel was the wrong shape for
// cevm. cevm.ExecuteBlockV3 is block-batched; the per-tx wrapper
// in luxfi/evm/core/parallel/backend_cevm.go always returned
// (nil, nil). This package implements luxfi/evm/core/parallel's
// BlockExecutor interface (whole-block) which is the natural shape
// for cevm dispatch.
//
// The implementation lives WITH cevm (not in luxfi/evm) so the
// import direction is correct: luxfi/evm declares the interface;
// luxfi/chains/evm/cevm/parallel imports luxfi/evm to satisfy it.
// Consumers wire it explicitly:
//
//   import _ "github.com/luxfi/chains/evm/cevm/parallel" // registers
//
// or for explicit control:
//
//   import (
//       "github.com/luxfi/evm/core/parallel"
//       cevmparallel "github.com/luxfi/chains/evm/cevm/parallel"
//       "github.com/luxfi/chains/evm/cevm"
//   )
//   parallel.RegisterExecutor(&cevmparallel.Executor{
//       CevmBackend: cevm.GPUMetal,
//       Threads:     0,
//   })
//
// Build with: `go build -tags cgo` (the cgo bridge in cevm/cevm_cgo.go
// links libcevm.a + libluxgpu).
//
// Parity contract: every receipt produced here must byte-equal the
// receipt produced by Go EVM Block-STM for the same input tuple.
// Enforced by parity_test.go in this package.

package parallel

import (
	"fmt"

	"github.com/luxfi/evm/core/state"
	evmparallel "github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	ethparams "github.com/luxfi/geth/params"
	log "github.com/luxfi/log"

	"github.com/luxfi/chains/evm/cevm"
)

// Executor is a luxfi/evm/core/parallel.BlockExecutor that dispatches
// every block to cevm.ExecuteBlockV3 in one cgo call.
//
// Compile-time interface check; the var line below ensures Executor
// satisfies BlockExecutor.
type Executor struct {
	// CevmBackend selects the cevm execution lane:
	//   cevm.CPUSequential — single-threaded CPU baseline (parity reference)
	//   cevm.CPUParallel   — Block-STM on CPU
	//   cevm.GPUMetal      — Metal kernel dispatch (M1/M2/M3)
	//   cevm.GPUCUDA       — CUDA kernel dispatch (NVIDIA)
	CevmBackend cevm.Backend

	// Threads is the worker count for parallel backends. Ignored by
	// CPUSequential; defaults to 1 when zero.
	Threads uint32
}

var _ evmparallel.BlockExecutor = (*Executor)(nil)

// ExecuteBlock implements evmparallel.BlockExecutor. Dispatches the
// whole block in one cgo call to cevm.ExecuteBlockV3 and reconstructs
// receipts.
//
// Returns (nil, nil) — the documented "fall through to sequential"
// signal — when the block contains opcodes cevm GPU can't handle yet
// (CALL/CREATE family) or non-trivial tx (Data/Code) for which cevm's
// V2 ABI doesn't yet expose per-tx logs. On hard errors it returns
// the error.
func (e *Executor) ExecuteBlock(
	config *ethparams.ChainConfig,
	header *types.Header,
	txs types.Transactions,
	statedb *state.StateDB,
	vmCfg vm.Config,
) ([]*types.Receipt, error) {
	if len(txs) == 0 {
		return nil, nil
	}

	// Stage 1: build cevm.Transaction shape from luxfi/geth Transactions.
	//
	// Sender recovery is the dominant cost of Stage 1 — secp256k1 ECDSA
	// recovery is ~50us per tx in pure Go and dominates block validation
	// for full-utilization C-Chain blocks. We batch every sender into one
	// cgo dispatch into the luxcpp/crypto first-party pipeline (see
	// cevm.BatchRecoverSenders). The batch also primes the per-tx
	// sigCache via types.CacheSender so any subsequent types.Sender call
	// is a cache hit.
	signer := types.MakeSigner(config, header.Number, header.Time)
	senders, err := cevm.BatchRecoverSenders(txs, signer)
	if err != nil {
		return nil, fmt.Errorf("cevm: batch sender recovery: %w", err)
	}
	cevmTxs := make([]cevm.Transaction, len(txs))
	for i, tx := range txs {
		ct := cevm.Transaction{
			GasLimit: tx.Gas(),
			Nonce:    tx.Nonce(),
			Data:     tx.Data(),
		}
		copy(ct.From[:], senders[i].Bytes())
		if to := tx.To(); to != nil {
			copy(ct.To[:], to.Bytes())
			ct.HasTo = true
			// For real GPU execution the receiver's bytecode must be
			// loaded so the kernel can interpret it. Skip for CALL /
			// DELEGATECALL targets — cevm GPU returns status=5 for
			// nested calls, caught at Stage 4.
			ct.Code = statedb.GetCode(*to)
		}
		// Value + GasPrice are uint64 in cevm.Transaction; transactions
		// with values exceeding uint64 (rare but legal) cannot run
		// through this backend. Fall through.
		if tx.Value().IsUint64() {
			ct.Value = tx.Value().Uint64()
		} else {
			log.Debug("cevm: tx value exceeds uint64, falling through",
				"tx_index", i, "block", header.Number)
			return nil, nil
		}
		if tx.GasPrice() != nil && tx.GasPrice().IsUint64() {
			ct.GasPrice = tx.GasPrice().Uint64()
		}
		cevmTxs[i] = ct
	}

	// Stage 2: build the BlockContext.
	blockCtx := cevm.BlockContext{
		Timestamp: header.Time,
		Number:    header.Number.Uint64(),
		GasLimit:  header.GasLimit,
		ChainID:   config.ChainID.Uint64(),
	}
	if header.BaseFee != nil && header.BaseFee.IsUint64() {
		blockCtx.BaseFee = header.BaseFee.Uint64()
	}
	if header.ExcessBlobGas != nil {
		blockCtx.BlobBaseFee = *header.ExcessBlobGas
	}
	copy(blockCtx.Coinbase[:], header.Coinbase.Bytes())
	// Prevrandao = post-merge MixDigest. Pre-merge headers carry zero
	// MixDigest; the cevm side treats zero as "not set".
	copy(blockCtx.Prevrandao[:], header.MixDigest.Bytes())

	// Stage 3: build state snapshot of touched accounts.
	//
	// The GPU CALL/CREATE path needs target nonce/balance/code on-device.
	// Walk every (caller, target) tuple, dedupe addresses, and read the
	// account data from the StateDB. Pre-V4 the kernel returned
	// CallNotSupported for every CALL → triggered the V3 → cevm CPU
	// fallback. With V4 we hand the GPU the data it needs and the call
	// completes on-device for the LP-108 P5 corpus.
	snapshot := buildStateSnapshot(cevmTxs, statedb)

	// Stage 4: dispatch.
	threads := e.Threads
	if threads == 0 {
		threads = 1
	}
	result, err := cevm.ExecuteBlockV4(e.CevmBackend, threads, cevmTxs, &blockCtx, snapshot)
	if err != nil {
		return nil, fmt.Errorf("cevm: ExecuteBlockV4: %w", err)
	}
	if len(result.GasUsed) != len(txs) || len(result.Status) != len(txs) {
		return nil, fmt.Errorf("cevm: result length mismatch (gas=%d status=%d txs=%d)",
			len(result.GasUsed), len(result.Status), len(txs))
	}

	// Stage 5: detect CallNotSupported. If any tx hit it, the cevm
	// path can't complete this block. Fall through to Go EVM rather
	// than mix backends mid-block (which would corrupt state-trie
	// progression).
	for i, st := range result.Status {
		if st == cevm.TxCallNotSupported {
			log.Debug("cevm: tx hit CALL/CREATE; falling through",
				"tx_index", i, "block", header.Number)
			return nil, nil
		}
	}

	// Stage 6: receipt reconstruction.
	//
	// IMPORTANT: this stage is the parity-critical seam. Receipt
	// fields (Status, CumulativeGasUsed, Bloom, Logs, ContractAddress,
	// GasUsed, BlockHash, BlockNumber, TransactionIndex, EffectiveGasPrice)
	// must match Go EVM byte-for-byte. The cevm V2 ABI returns
	// (gas_used, status); logs/bloom/contract-address must be derived
	// from the StateDB after cevm writes its state-trie deltas. Until
	// the cevm V3 ABI exposes per-tx logs (open work-item), we cannot
	// produce parity-compatible receipts for tx that emit LOG opcodes.
	//
	// For the safety of this commit: if any tx is non-trivial (has Data
	// or Code), fall through to Go EVM. The cevm path is enabled only
	// for value-transfer-only blocks where receipts are deterministic
	// from (status, gas_used) alone.
	allValueTransfer := true
	for _, tx := range txs {
		if len(tx.Data()) > 0 {
			allValueTransfer = false
			break
		}
		if to := tx.To(); to != nil && len(statedb.GetCode(*to)) > 0 {
			allValueTransfer = false
			break
		}
	}
	if !allValueTransfer {
		log.Debug("cevm: block has non-value-transfer txs; falling through until V3 logs ABI",
			"block", header.Number)
		return nil, nil
	}

	receipts := make([]*types.Receipt, len(txs))
	cumulativeGas := uint64(0)
	for i, tx := range txs {
		gas := result.GasUsed[i]
		cumulativeGas += gas
		var receiptStatus uint64
		switch result.Status[i] {
		case cevm.TxOK, cevm.TxReturn:
			receiptStatus = types.ReceiptStatusSuccessful
		default:
			receiptStatus = types.ReceiptStatusFailed
		}
		receipts[i] = &types.Receipt{
			Type:              tx.Type(),
			Status:            receiptStatus,
			CumulativeGasUsed: cumulativeGas,
			GasUsed:           gas,
			TxHash:            tx.Hash(),
			BlockNumber:       header.Number,
			TransactionIndex:  uint(i),
			Logs:              []*types.Log{}, // value-transfer = no logs
			Bloom:             types.Bloom{},
		}
	}

	return receipts, nil
}

// Backend returns the cevm backend lane this Executor dispatches to.
func (e *Executor) Backend() cevm.Backend { return e.CevmBackend }

// buildStateSnapshot collects every (caller, target) address touched by the
// batch and reads its account data from the StateDB. The GPU dispatch hands
// this snapshot to the kernel host so OP_CALL / OP_CREATE can resolve
// nonce / balance / code without a host trampoline.
//
// Dedupe by address: every account appears at most once in the snapshot.
// EOAs (no contract code) are emitted with empty Code — the kernel reads
// nonce / balance only.
//
// Balance encoding: 4×uint64 little-endian limbs (Balance[0] = low 64 bits)
// to match the kernel's HostStateAccount layout exactly. uint256 → limbs
// is just `Uint64()` per word; geth's uint256.Int already stores in this
// order so we copy it verbatim.
func buildStateSnapshot(txs []cevm.Transaction, statedb *state.StateDB) []cevm.StateAccount {
	if len(txs) == 0 || statedb == nil {
		return nil
	}
	seen := make(map[common.Address]struct{}, len(txs)*2)
	out := make([]cevm.StateAccount, 0, len(txs)*2)
	add := func(addr common.Address) {
		if _, ok := seen[addr]; ok {
			return
		}
		seen[addr] = struct{}{}
		acct := cevm.StateAccount{Nonce: statedb.GetNonce(addr)}
		copy(acct.Address[:], addr.Bytes())
		if bal := statedb.GetBalance(addr); bal != nil {
			// uint256.Int is stored as little-endian uint64 limbs:
			// Uint64() returns word 0; words 1-3 require array
			// access. The geth API exposes the raw words via .Bytes32
			// (BE) — we read the LE uint64 limbs through that.
			b32 := bal.Bytes32()
			// b32 is big-endian; convert to little-endian limb layout
			// matching the kernel's HostStateAccount.balance[].
			for i := 0; i < 4; i++ {
				var w uint64
				for j := 0; j < 8; j++ {
					w |= uint64(b32[31-i*8-j]) << (uint(j) * 8)
				}
				acct.Balance[i] = w
			}
		}
		acct.Code = statedb.GetCode(addr)
		hash := statedb.GetCodeHash(addr)
		copy(acct.CodeHash[:], hash.Bytes())
		out = append(out, acct)
	}
	for i := range txs {
		var caller common.Address
		copy(caller[:], txs[i].From[:])
		add(caller)
		if txs[i].HasTo {
			var target common.Address
			copy(target[:], txs[i].To[:])
			add(target)
		}
	}
	return out
}
