// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package parallel — cevm BlockExecutor for github.com/luxfi/evm.
//
// LP-108 (2026-05-04) ENSURE step: the per-tx TransactionExecutor
// abstraction in luxfi/evm/core/parallel was the wrong shape for
// cevm. cevm.ExecuteBlock is block-batched; the per-tx wrapper
// in luxfi/evm/core/parallel/backend_cevm.go always returned
// (nil, nil). This package implements luxfi/evm/core/parallel's
// BlockExecutor interface (whole-block) which is the natural shape
// for cevm dispatch.
//
// The implementation lives WITH cevm (not in luxfi/evm) so the
// import direction is correct: luxfi/evm declares the interface;
// luxfi/chains/evm/cevm/parallel imports luxfi/evm to satisfy it.
//
// # Wiring
//
// Explicit, and it has to stay explicit:
//
//	import (
//	    "github.com/luxfi/evm/core/parallel"
//	    cevmparallel "github.com/luxfi/chains/evm/cevm/parallel"
//	    "github.com/luxfi/chains/evm/cevm"
//	)
//	parallel.RegisterExecutor(&cevmparallel.Executor{
//	    CevmBackend: cevm.GPUMetal,
//	    Threads:     0,
//	})
//
// luxfi/evm/core/parallel holds ONE executor: RegisterExecutor is a plain
// assignment to a package variable, so a second call replaces the first with
// no complaint. luxfi/evm's own cevmShadowExecutor takes that slot from an
// init() when the binary is built with -tags cevm. A package that registered
// itself on import would therefore replace a consensus-gated applier with this
// one, depending only on link order — so this package has no init().
//
// This doc used to advertise `import _ ".../cevm/parallel" // registers` as an
// alternative. There is no init() and never was, so that form registers
// nothing: a caller following it got the Go EVM and no error saying otherwise.
//
// # Execution
//
// Three orthogonal steps, so that only the middle one needs the C++ library:
//
//	shape / blockContext / buildStateSnapshot — the block, in cevm's wire form
//	cevm.ExecuteBlock                         — one cgo call
//	assemble                                  — what comes back, as receipts
//
// Parity contract: every receipt produced here must byte-equal the receipt
// produced by Go EVM Block-STM for the same input tuple.
package parallel

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/luxfi/crypto/backend"
	evmparallel "github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/evm/core/state"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	ethparams "github.com/luxfi/geth/params"
	log "github.com/luxfi/log"

	"github.com/luxfi/chains/evm/cevm"
)

// ErrGPUEVMRequired is the sentinel ExecuteBlock returns when the cevm
// V4 path cannot complete a block on-device and the caller must NOT
// silently shadow-execute it on the Go EVM. Strict mode (the default)
// propagates this error; legacy mode collapses it to (nil, nil) so the
// caller falls through.
//
// Strict mode is the production target. The legacy fallback exists only
// for the V4→V5 cevm transition window; flip CEVM_STRICT=0 to re-enable
// it for emergency rollback. Once the V5 kernel implements CALL/CREATE
// on device, the strict path becomes unconditional and the env var is
// retired.
var ErrGPUEVMRequired = errors.New("cevm: GPU EVM cannot execute this block (V4 ABI); waiting for V5 kernel — Go EVM fallback disabled by CEVM_STRICT")

const envCEVMStrict = "CEVM_STRICT"

// strictGPUEVM reports whether the silent Go EVM fallback is disabled.
//
// Read on every call. It used to be memoized behind a sync.Once, which fixed
// the answer to whatever the first block that declined happened to see — and
// which made the two branches unreachable from a single process, so neither
// was ever exercised.
func strictGPUEVM() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(envCEVMStrict))) {
	case "0", "false", "no", "off":
		return false
	default:
		// Default ON: do NOT silently shadow-execute on Go EVM. The
		// fallback was the lie that hid the missing GPU CALL/CREATE.
		return true
	}
}

// declineBlock is the single fallback exit point. It records the
// fallback reason for observability, then returns either the strict
// sentinel error (default) or the legacy (nil, nil) opt-out result.
//
// Every "cevm cannot do this" leaves through here. A path that returned its
// own error instead would be a refusal CEVM_STRICT=0 cannot clear, which is
// the whole point of the flag — an operator flips it to get the Go EVM back
// and the block still fails.
func declineBlock(reason string, blockNumber, txIndex uint64) ([]*types.Receipt, error) {
	backend.RecordFallback(backend.FallbackUnsupported, "cevm:"+reason)
	if strictGPUEVM() {
		return nil, fmt.Errorf("%w: reason=%s block=%d tx_index=%d",
			ErrGPUEVMRequired, reason, blockNumber, txIndex)
	}
	log.Debug("cevm: declining block to Go EVM (CEVM_STRICT=0)",
		"reason", reason, "block", blockNumber, "tx_index", txIndex)
	return nil, nil
}

// Executor is a luxfi/evm/core/parallel.BlockExecutor that dispatches
// every block to cevm.ExecuteBlock in one cgo call.
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
// whole block in one cgo call to cevm.ExecuteBlock and reconstructs
// receipts.
//
// Returns (nil, nil) — the documented "fall through to sequential"
// signal — when CEVM_STRICT=0 and the block contains something cevm cannot
// run yet. Under the default strict mode those cases return
// ErrGPUEVMRequired instead. On hard errors it returns the error.
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

	// Sender recovery is the dominant cost of shaping the block — secp256k1
	// ECDSA recovery is ~50us per tx in pure Go and dominates block validation
	// for full-utilization C-Chain blocks. Every sender goes into one cgo
	// dispatch into the luxcpp/crypto first-party pipeline. The batch also
	// primes the per-tx sigCache via types.CacheSender so any subsequent
	// types.Sender call is a cache hit.
	signer := types.MakeSigner(config, header.Number, header.Time)
	senders, err := cevm.BatchRecoverSenders(txs, signer)
	if err != nil {
		if errors.Is(err, cevm.ErrNotLinked) {
			// This binary has no C++ EVM. That is a property of the build, not
			// of the block, so it leaves by the one door that consults
			// CEVM_STRICT. It used to return a hard error from here, which no
			// CEVM_STRICT=0 could clear: in a build without the library that is
			// every block, permanently, and the documented rollback to the Go
			// EVM did not reach this line.
			return declineBlock("native_evm_not_linked", header.Number.Uint64(), 0)
		}
		return nil, fmt.Errorf("cevm: batch sender recovery: %w", err)
	}

	cevmTxs, i := shape(txs, senders, statedb)
	if i < len(txs) {
		return declineBlock("value_overflow_uint64", header.Number.Uint64(), uint64(i))
	}
	blockCtx := blockContext(config, header)
	snapshot := buildStateSnapshot(cevmTxs, statedb)

	threads := e.Threads
	if threads == 0 {
		threads = 1
	}
	result, err := cevm.ExecuteBlock(e.CevmBackend, threads, cevmTxs, &blockCtx, snapshot)
	if err != nil {
		if errors.Is(err, cevm.ErrNotLinked) {
			return declineBlock("native_evm_not_linked", header.Number.Uint64(), 0)
		}
		return nil, fmt.Errorf("cevm: ExecuteBlock: %w", err)
	}
	return assemble(txs, statedb, result, header)
}

// Backend returns the cevm backend lane this Executor dispatches to.
func (e *Executor) Backend() cevm.Backend { return e.CevmBackend }

// shape converts the block's transactions into cevm's wire form, positionally
// paired with the recovered senders.
//
// It returns the index of the first transaction that cannot be represented, or
// len(txs) when every one can. cevm.Transaction carries Value and GasPrice as
// uint64; a value above 2^64-1 is rare but legal, and truncating it would
// execute a transaction other than the one that was signed.
func shape(txs types.Transactions, senders []common.Address, statedb *state.StateDB) ([]cevm.Transaction, int) {
	out := make([]cevm.Transaction, len(txs))
	for i, tx := range txs {
		if !tx.Value().IsUint64() {
			return out, i
		}
		ct := cevm.Transaction{
			GasLimit: tx.Gas(),
			Nonce:    tx.Nonce(),
			Data:     tx.Data(),
			Value:    tx.Value().Uint64(),
		}
		copy(ct.From[:], senders[i].Bytes())
		if to := tx.To(); to != nil {
			copy(ct.To[:], to.Bytes())
			ct.HasTo = true
			// For real GPU execution the receiver's bytecode must be
			// loaded so the kernel can interpret it.
			ct.Code = statedb.GetCode(*to)
		}
		if tx.GasPrice() != nil && tx.GasPrice().IsUint64() {
			ct.GasPrice = tx.GasPrice().Uint64()
		}
		out[i] = ct
	}
	return out, len(txs)
}

// blockContext is the block-level execution context every transaction in the
// block sees: what TIMESTAMP, NUMBER, CHAINID, BASEFEE, COINBASE, GASLIMIT,
// PREVRANDAO and BLOBBASEFEE answer.
func blockContext(config *ethparams.ChainConfig, header *types.Header) cevm.BlockContext {
	ctx := cevm.BlockContext{
		Timestamp: header.Time,
		Number:    header.Number.Uint64(),
		GasLimit:  header.GasLimit,
		ChainID:   config.ChainID.Uint64(),
	}
	if header.BaseFee != nil && header.BaseFee.IsUint64() {
		ctx.BaseFee = header.BaseFee.Uint64()
	}
	if header.ExcessBlobGas != nil {
		ctx.BlobBaseFee = *header.ExcessBlobGas
	}
	copy(ctx.Coinbase[:], header.Coinbase.Bytes())
	// Prevrandao = post-merge MixDigest. Pre-merge headers carry zero
	// MixDigest; the cevm side treats zero as "not set".
	copy(ctx.Prevrandao[:], header.MixDigest.Bytes())
	return ctx
}

// assemble turns what cevm returned into receipts, or declines the block.
//
// It needs no library — only the result — which is why it is separate from the
// dispatch: this is the parity-critical half and it has to be exercisable in
// a build that cannot execute anything.
func assemble(
	txs types.Transactions,
	statedb *state.StateDB,
	result *cevm.BlockResult,
	header *types.Header,
) ([]*types.Receipt, error) {
	if len(result.GasUsed) != len(txs) || len(result.Status) != len(txs) {
		return nil, fmt.Errorf("cevm: result length mismatch (gas=%d status=%d txs=%d)",
			len(result.GasUsed), len(result.Status), len(txs))
	}

	// The cevm V4 kernel returns TxCallNotSupported for
	// CALL/CREATE/DELEGATECALL/STATICCALL opcodes. The V5 kernel (spec at
	// chains/evm/cevm/V5_ABI.md) implements these on device; until it lands,
	// decline the block rather than mix backends mid-block.
	for i, st := range result.Status {
		if st == cevm.TxCallNotSupported {
			return declineBlock("call_or_create_unsupported_v4", header.Number.Uint64(), uint64(i))
		}
	}

	// The cevm V4 ABI returns (gas_used, status) and nothing else, so a
	// receipt is only reconstructable where (status, gas_used) determines it
	// completely. That is a plain value transfer and nothing more.
	if i := firstBeyondValueTransfer(txs, statedb); i < len(txs) {
		return declineBlock("non_value_transfer_logs_abi_pending_v5", header.Number.Uint64(), uint64(i))
	}
	return receipts(txs, result, header), nil
}

// firstBeyondValueTransfer returns the index of the first transaction whose
// receipt does not follow from (status, gas_used) alone, or len(txs) when
// every one does.
//
// Three things put a transaction beyond that:
//
//   - calldata, which can reach code that emits LOGs — and the V4 ABI carries
//     no per-tx logs, so the bloom and the log list would be reconstructed as
//     empty;
//   - a recipient that has code, for the same reason;
//   - no recipient at all, which is a contract CREATION. This one used to be
//     missed: the check asked `len(tx.Data()) > 0`, and a creation with empty
//     init code answers no. Its receipt needs a ContractAddress that this
//     reconstruction does not compute, and creation is charged 53000 intrinsic
//     gas against a transfer's 21000 — so it would have been receipted, with
//     the wrong gas, into the cumulative total the block header commits to.
func firstBeyondValueTransfer(txs types.Transactions, statedb *state.StateDB) int {
	for i, tx := range txs {
		to := tx.To()
		if to == nil || len(tx.Data()) > 0 {
			return i
		}
		if len(statedb.GetCode(*to)) > 0 {
			return i
		}
	}
	return len(txs)
}

// receipts reconstructs the block's receipts from cevm's per-tx status and gas.
//
// This is the parity-critical seam: every field must match what the Go EVM
// produces for the same transaction, because the receipt trie hash is in the
// header. It is only reached for blocks that firstBeyondValueTransfer passed,
// where there are no logs to carry and no contract address to compute.
func receipts(txs types.Transactions, result *cevm.BlockResult, header *types.Header) []*types.Receipt {
	out := make([]*types.Receipt, len(txs))
	cumulativeGas := uint64(0)
	for i, tx := range txs {
		gas := result.GasUsed[i]
		cumulativeGas += gas
		status := uint64(types.ReceiptStatusFailed)
		switch result.Status[i] {
		case cevm.TxOK, cevm.TxReturn:
			status = types.ReceiptStatusSuccessful
		}
		out[i] = &types.Receipt{
			Type:              tx.Type(),
			Status:            status,
			CumulativeGasUsed: cumulativeGas,
			GasUsed:           gas,
			TxHash:            tx.Hash(),
			BlockNumber:       header.Number,
			TransactionIndex:  uint(i),
			Logs:              []*types.Log{}, // value-transfer = no logs
			Bloom:             types.Bloom{},
		}
	}
	return out
}

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
// to match the kernel's HostStateAccount layout exactly.
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
			// uint256.Int is stored as little-endian uint64 limbs, and the
			// kernel's HostStateAccount.balance[] expects the same order.
			// Bytes32 hands them over big-endian, so read each limb back out.
			b32 := bal.Bytes32()
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
