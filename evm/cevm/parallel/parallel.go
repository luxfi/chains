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
// Nothing registers this executor, and nothing may yet: it returns receipts
// for a block cevm ran and writes no state. gpu_execute_block roots no state
// and hands none back, so a block it runs leaves the StateDB as it was, and a
// node that registered the executor would finalize that block on the parent's
// state and reject it for its root.
//
// When it is registered, it is registered explicitly, with
// parallel.RegisterExecutor(&cevmparallel.Executor{CevmBackend: ...}).
// luxfi/evm/core/parallel holds ONE executor: RegisterExecutor is a plain
// assignment to a package variable, so a second call replaces the first with
// no complaint. A package that registered itself on import would take that
// slot depending only on link order — so this package has no init().
//
// # Execution
//
// Three orthogonal steps, so that only the middle one needs the C++ library:
//
//	shape / blockContext / buildStateSnapshot — the block, in cevm's wire form
//	cevm.ExecuteBlock                         — one cgo call
//	assemble                                  — what comes back, as receipts
//
// cevm's Go entry runs nothing on the CPU lanes (no host, and code is
// declined), so only a GPU lane with a device ever returns a block.
//
// Parity contract: every receipt produced here must byte-equal the receipt
// produced by Go EVM Block-STM for the same input tuple.
//
// # Declining
//
// cevm's Go entry (go_bridge.h, ABI 7) answers ok=0 for any block it does not
// run: a batch with code, and any refusal on balance, nonce, price, block gas
// limit, revision or hashes. Such a block, and one whose values do not fit its
// 64-bit wire, is the caller's to run. Every one of them leaves through
// declineBlock as (nil, nil), which is luxfi/evm's "not handled" and sends the
// block to the sequential Go EVM. A declined result is never read.
package parallel

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/luxfi/crypto/backend"
	evmparallel "github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/evm/core/state"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/consensus/misc/eip4844"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	ethparams "github.com/luxfi/geth/params"
	log "github.com/luxfi/log"

	"github.com/luxfi/chains/evm/cevm"
)

// declineBlock is the single exit for a block this executor does not run. It
// records why, for observability, and returns (nil, nil): luxfi/evm's "not
// handled", on which the state processor runs the block on its sequential Go
// EVM.
//
// A decline is never an error: cevm's Go entry passes no host, so it runs no
// code, and go_bridge.h's contract is that the caller runs a declined block
// itself.
func declineBlock(reason string, blockNumber, txIndex uint64) ([]*types.Receipt, error) {
	backend.RecordFallback(backend.FallbackBackendUnavailable, "cevm:"+reason)
	log.Debug("cevm: declining block to the Go EVM",
		"reason", reason, "block", blockNumber, "tx_index", txIndex)
	return nil, nil
}

// execute is the one call into cevm: cevm.ExecuteBlock's signature.
type execute func(cevm.Backend, uint32, []cevm.Transaction, *cevm.BlockContext, []cevm.StateAccount) (*cevm.BlockResult, error)

// Executor is a luxfi/evm/core/parallel.BlockExecutor that dispatches
// every block to cevm.ExecuteBlock in one cgo call.
type Executor struct {
	// CevmBackend selects the cevm lane: cevm.GPUMetal (Apple silicon) or
	// cevm.GPUCUDA (NVIDIA). The CPU lanes, cevm.CPUSequential and
	// cevm.CPUParallel, decline every block through cevm's Go entry, which
	// passes no host.
	CevmBackend cevm.Backend

	// Threads is the worker count for parallel backends. Ignored by
	// CPUSequential; defaults to 1 when zero.
	Threads uint32

	// execute is the call into cevm; nil is cevm.ExecuteBlock. It is a field
	// so that what reaches cevm, and what is done with its answer, can be
	// shown without the library.
	execute execute
}

var _ evmparallel.BlockExecutor = (*Executor)(nil)

// ExecuteBlock implements evmparallel.BlockExecutor. Dispatches the
// whole block in one cgo call to cevm.ExecuteBlock and reconstructs
// receipts.
//
// Returns (nil, nil) — the documented "fall through to sequential" signal —
// for every block cevm does not run (see declineBlock). On hard errors it
// returns the error.
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
			// of the block, so the block goes to the Go EVM like any other
			// decline rather than failing: in a build without the library that
			// is every block.
			return declineBlock("native_evm_not_linked", header.Number.Uint64(), 0)
		}
		return nil, fmt.Errorf("cevm: batch sender recovery: %w", err)
	}
	return e.run(config, header, txs, senders, statedb)
}

// run takes the block from its recovered senders to receipts, or declines it.
//
// Nothing that does not fit cevm's 64-bit wire reaches cevm: a value, price,
// base fee or chain id wider than that is the caller's to run, and truncating
// it would execute a block other than the one that was signed.
func (e *Executor) run(
	config *ethparams.ChainConfig,
	header *types.Header,
	txs types.Transactions,
	senders []common.Address,
	statedb *state.StateDB,
) ([]*types.Receipt, error) {
	// cevm's Go entry runs nothing on a CPU lane: it passes no host, and a
	// CPU lane runs no plain transfer without one (go_bridge.h, ABI 7). A
	// library that answers there anyway answers something else — a gas
	// estimate — so it is not asked.
	if e.CevmBackend != cevm.GPUMetal && e.CevmBackend != cevm.GPUCUDA {
		return declineBlock("cpu_lane", header.Number.Uint64(), 0)
	}
	cevmTxs, i := shape(txs, senders, statedb)
	if i < len(txs) {
		return declineBlock("tx_not_representable", header.Number.Uint64(), uint64(i))
	}
	// cevm declines a batch with code, and its answer could not be receipted
	// past a plain value transfer anyway: neither is worth a snapshot and a
	// cgo call.
	if i := firstBeyondValueTransfer(txs, statedb); i < len(txs) {
		return declineBlock("non_value_transfer", header.Number.Uint64(), uint64(i))
	}
	blockCtx, ok := blockContext(config, header)
	if !ok {
		return declineBlock("block_context_overflow_uint64", header.Number.Uint64(), 0)
	}
	snapshot := buildStateSnapshot(cevmTxs, header.Coinbase, statedb)

	threads := e.Threads
	if threads == 0 {
		threads = 1
	}
	call := e.execute
	if call == nil {
		call = cevm.ExecuteBlock
	}
	result, err := call(e.CevmBackend, threads, cevmTxs, &blockCtx, snapshot)
	switch {
	case err == nil:
		return assemble(txs, result, header)
	case errors.Is(err, cevm.ErrDeclined):
		// ok=0: no gas or status in it is the block's, so none is read.
		return declineBlock("cevm_declined", header.Number.Uint64(), 0)
	case errors.Is(err, cevm.ErrNotLinked):
		return declineBlock("native_evm_not_linked", header.Number.Uint64(), 0)
	default:
		return nil, fmt.Errorf("cevm: ExecuteBlock: %w", err)
	}
}

// Backend returns the cevm backend lane this Executor dispatches to.
func (e *Executor) Backend() cevm.Backend { return e.CevmBackend }

// shape converts the block's transactions into cevm's wire form, positionally
// paired with the recovered senders.
//
// It returns the index of the first transaction that cannot be represented, or
// len(txs) when every one can. cevm.Transaction carries Value, GasFeeCap and
// GasTipCap as uint64; a value or fee above 2^64-1 is rare but legal, and
// truncating it would execute a transaction other than the one that was
// signed. The fee cap and tip are tx.GasFeeCap() and tx.GasTipCap(), both the
// gas price of a legacy or access-list tx: cevm charges the base fee and the
// tip, capped at the fee cap, as the EVM does, and checks the sender's balance
// at the fee cap. A tx the wire drops part of (see carried) is not
// representable either.
func shape(txs types.Transactions, senders []common.Address, statedb *state.StateDB) ([]cevm.Transaction, int) {
	out := make([]cevm.Transaction, len(txs))
	for i, tx := range txs {
		if !carried(tx) || !tx.Value().IsUint64() {
			return out, i
		}
		feeCap, ok := fits(tx.GasFeeCap())
		if !ok {
			return out, i
		}
		// The tip is at most the fee cap (carried), so it fits too.
		tipCap := tx.GasTipCap().Uint64()
		ct := cevm.Transaction{
			GasLimit:  tx.Gas(),
			Nonce:     tx.Nonce(),
			Data:      tx.Data(),
			Value:     tx.Value().Uint64(),
			GasFeeCap: feeCap,
			GasTipCap: tipCap,
		}
		copy(ct.From[:], senders[i].Bytes())
		if to := tx.To(); to != nil {
			copy(ct.To[:], to.Bytes())
			ct.HasTo = true
			// The recipient's code rides with the tx, as go_bridge.h asks:
			// cevm declines a batch that carries any, and one whose code is
			// not its recipient's.
			ct.Code = statedb.GetCode(*to)
		}
		out[i] = ct
	}
	return out, len(txs)
}

// carried reports whether cevm's wire carries everything tx's gas and status
// depend on. CGpuTx has no access list, blob hashes or authorizations: a tx
// with an access list is charged for it, and a blob or set-code tx for what it
// carries. One whose tip exceeds its fee cap is invalid (ErrTipAboveFeeCap):
// cevm declines it too, and the Go EVM says why.
func carried(tx *types.Transaction) bool {
	switch tx.Type() {
	case types.LegacyTxType, types.AccessListTxType, types.DynamicFeeTxType:
	default:
		return false
	}
	return len(tx.AccessList()) == 0 && tx.GasTipCap().Cmp(tx.GasFeeCap()) <= 0
}

// fits reads v as cevm's 64-bit wire carries it. A nil v is zero; one wider
// than 64 bits does not fit.
func fits(v *big.Int) (uint64, bool) {
	if v == nil {
		return 0, true
	}
	if !v.IsUint64() {
		return 0, false
	}
	return v.Uint64(), true
}

// blockContext is the block-level execution context every transaction in the
// block sees: what TIMESTAMP, NUMBER, CHAINID, BASEFEE, COINBASE, GASLIMIT,
// PREVRANDAO and BLOBBASEFEE answer, as luxfi/evm's NewEVMBlockContext has
// them.
//
// It reports false when the chain id, the base fee or the blob base fee does
// not fit cevm's 64-bit wire. A base fee carried as anything else would let cevm pass a tx
// priced below the real one, which the EVM rejects.
func blockContext(config *ethparams.ChainConfig, header *types.Header) (cevm.BlockContext, bool) {
	chainID, ok := fits(config.ChainID)
	if !ok {
		return cevm.BlockContext{}, false
	}
	baseFee, ok := fits(header.BaseFee)
	if !ok {
		return cevm.BlockContext{}, false
	}
	ctx := cevm.BlockContext{
		Timestamp: header.Time,
		Number:    header.Number.Uint64(),
		GasLimit:  header.GasLimit,
		ChainID:   chainID,
		BaseFee:   baseFee,
	}
	// BLOBBASEFEE is the fee the header's excess blob gas prices, under the
	// chain's blob schedule; none before Cancun.
	if header.ExcessBlobGas != nil {
		fee, ok := fits(eip4844.CalcBlobFee(config, header))
		if !ok {
			return cevm.BlockContext{}, false
		}
		ctx.BlobBaseFee = fee
	}
	copy(ctx.Coinbase[:], header.Coinbase.Bytes())
	// PREVRANDAO (0x44) is the header's difficulty as a 32-byte word:
	// NewEVMBlockContext sets Random to it from Shanghai on, and DIFFICULTY
	// before that answers the same number. A Lux header's MixDigest is zero.
	if header.Difficulty != nil {
		ctx.Prevrandao = common.BigToHash(header.Difficulty)
	}
	return ctx, true
}

// assemble turns what cevm returned for a block of plain value transfers into
// receipts, or declines the block.
//
// It needs no library — only the result — which is why it is separate from the
// dispatch: this is the parity-critical half and it has to be exercisable in
// a build that cannot execute anything.
func assemble(
	txs types.Transactions,
	result *cevm.BlockResult,
	header *types.Header,
) ([]*types.Receipt, error) {
	if len(result.GasUsed) != len(txs) || len(result.Status) != len(txs) {
		return nil, fmt.Errorf("cevm: result length mismatch (gas=%d status=%d txs=%d)",
			len(result.GasUsed), len(result.Status), len(txs))
	}

	// cevm answers ok=1 only for a batch its value-transfer paths ran through,
	// every tx a valid plain transfer that succeeded on its intrinsic gas
	// (go_bridge.h; gpu_dispatch.cpp ran_through). Any other status or gas —
	// CallNotSupported, which never reaches a caller, a gas estimate, a
	// kernel's own answer — is not that, and not the block's: decline rather
	// than receipt it. This also holds a library that answers ok=1 on other
	// terms to the one answer this executor can use.
	for i := range txs {
		if result.Status[i] != cevm.TxOK || result.GasUsed[i] != ethparams.TxGas {
			return declineBlock("result_not_value_transfer", header.Number.Uint64(), uint64(i))
		}
	}
	return receipts(txs, result, header), nil
}

// firstBeyondValueTransfer returns the index of the first transaction whose
// receipt does not follow from (status, gas_used) alone, or len(txs) when
// every one does. The ABI returns (gas_used, status) and nothing else, so a
// receipt is only reconstructable for a plain value transfer.
//
// Three things put a transaction beyond that:
//
//   - calldata, which can reach code that emits LOGs — and the ABI carries
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

// buildStateSnapshot is the state before the block for every account the
// batch touches: each tx's caller and target, and the coinbase its fee goes
// to. go_bridge.h takes an account the snapshot lacks not to exist, so a
// touched account left out would be run as an empty one.
//
// Dedupe by address: every account appears at most once in the snapshot.
// EOAs (no contract code) are emitted with empty Code.
//
// Each row names its code and its storage: CodeHash is keccak256 of its code,
// and StorageRoot its storage trie root. An account that does not exist has
// neither, and the StateDB answers zero for both, which cevm reads as "says
// nothing" and declines; so it is given the hashes of nothing,
// types.EmptyCodeHash and types.EmptyRootHash, which is what it is.
//
// Balance encoding: 4×uint64 little-endian limbs (Balance[0] = low 64 bits)
// to match the kernel's HostStateAccount layout exactly.
func buildStateSnapshot(txs []cevm.Transaction, coinbase common.Address, statedb *state.StateDB) []cevm.StateAccount {
	if len(txs) == 0 || statedb == nil {
		return nil
	}
	seen := make(map[common.Address]struct{}, len(txs)*2+1)
	out := make([]cevm.StateAccount, 0, len(txs)*2+1)
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
		codeHash := statedb.GetCodeHash(addr)
		if codeHash == (common.Hash{}) {
			codeHash = types.EmptyCodeHash
		}
		copy(acct.CodeHash[:], codeHash.Bytes())
		root := statedb.GetStorageRoot(addr)
		if root == (common.Hash{}) {
			root = types.EmptyRootHash
		}
		copy(acct.StorageRoot[:], root.Bytes())
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
	add(coinbase)
	return out
}
