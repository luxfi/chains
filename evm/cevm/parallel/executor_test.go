// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package parallel

import (
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/luxfi/chains/evm/cevm"
	evmparallel "github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/evm/core/state"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/rawdb"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	ethparams "github.com/luxfi/geth/params"
)

// -----------------------------------------------------------------------------
// The declining policy
// -----------------------------------------------------------------------------

// CEVM_STRICT decides what a block cevm cannot run does: fail loudly, or fall
// through to the Go EVM.
//
// Both answers were unreachable from one process until now, because the value
// was memoized behind a sync.Once at the first decline. That is why this test
// can exist: the two branches are the whole policy and each has to be shown.
func TestStrictModeIsWhatTheEnvironmentSays(t *testing.T) {
	for _, tc := range []struct {
		set    string
		strict bool
	}{
		{"0", false},
		{"false", false},
		{"FALSE", false},
		{"no", false},
		{"off", false},
		{"  off  ", false},
		{"", true},
		{"1", true},
		{"true", true},
		{"yes", true},
		{"maybe", true},
	} {
		t.Run(tc.set, func(t *testing.T) {
			t.Setenv(envCEVMStrict, tc.set)
			if got := strictGPUEVM(); got != tc.strict {
				t.Fatalf("CEVM_STRICT=%q → strictGPUEVM() = %v, want %v", tc.set, got, tc.strict)
			}
		})
	}
}

// Unset is not the same as set-to-empty for every reader of an environment,
// so the default is pinned against a genuinely absent variable too. Strict is
// the safe direction: a binary nobody configured must not silently execute
// blocks on a backend the operator did not choose.
func TestAnUnsetEnvironmentIsStrict(t *testing.T) {
	t.Setenv(envCEVMStrict, "0")
	if err := os.Unsetenv(envCEVMStrict); err != nil {
		t.Fatalf("unset %s: %v", envCEVMStrict, err)
	}
	if !strictGPUEVM() {
		t.Fatal("with CEVM_STRICT unset the fallback is enabled; the default must be strict")
	}
}

// A declined block is a refusal under strict mode and a fall-through under the
// legacy opt-out — and the refusal has to be recognisable, because the caller
// distinguishes "cevm cannot" from "this block is bad" by the sentinel.
func TestDecliningIsARefusalUnderStrictAndAFallThroughOtherwise(t *testing.T) {
	t.Setenv(envCEVMStrict, "1")
	receipts, err := declineBlock("call_or_create_unsupported_v4", 42, 7)
	if !errors.Is(err, ErrGPUEVMRequired) {
		t.Fatalf("strict decline = %v, want ErrGPUEVMRequired", err)
	}
	if receipts != nil {
		t.Errorf("strict decline returned %d receipts alongside its refusal", len(receipts))
	}
	// An operator reading only the log needs the reason and the position.
	for _, want := range []string{"call_or_create_unsupported_v4", "block=42", "tx_index=7"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("decline error %q does not carry %q", err, want)
		}
	}

	t.Setenv(envCEVMStrict, "0")
	receipts, err = declineBlock("call_or_create_unsupported_v4", 42, 7)
	if err != nil || receipts != nil {
		t.Fatalf("legacy decline = (%v, %v), want (nil, nil) so the caller falls through",
			receipts, err)
	}
}

// -----------------------------------------------------------------------------
// A build with no C++ EVM
// -----------------------------------------------------------------------------

// The executor in a binary that has no cevm to dispatch to must decline, not
// hard-fail: the absence of the library is a property of the build, so it
// belongs to the policy CEVM_STRICT governs.
//
// It used to return a bare error from the sender-recovery step, which meant
// CEVM_STRICT=0 — the documented emergency rollback to the Go EVM — could not
// clear it. In a build without the library that is every block, permanently.
func TestABuildWithNoLibraryDeclinesRatherThanHalting(t *testing.T) {
	e := &Executor{CevmBackend: cevm.GPUCUDA}
	sdb := newState(t)
	header := newHeader()
	txs := types.Transactions{transfer(t, 1, big.NewInt(1))}

	t.Setenv(envCEVMStrict, "0")
	receipts, err := e.ExecuteBlock(chainConfig(), header, txs, sdb, vm.Config{})
	if err != nil {
		t.Fatalf("with CEVM_STRICT=0 the block must fall through to the Go EVM, got: %v", err)
	}
	if receipts != nil {
		t.Errorf("fall-through returned %d receipts", len(receipts))
	}

	t.Setenv(envCEVMStrict, "1")
	if _, err := e.ExecuteBlock(chainConfig(), header, txs, sdb, vm.Config{}); !errors.Is(err, ErrGPUEVMRequired) {
		t.Fatalf("under strict mode the refusal must be ErrGPUEVMRequired, got: %v", err)
	}
}

// An empty block is nothing to execute, so it falls through before anything
// else is asked — no signer, no library, no policy.
func TestAnEmptyBlockIsNotThisExecutorsBusiness(t *testing.T) {
	e := &Executor{}
	receipts, err := e.ExecuteBlock(chainConfig(), newHeader(), nil, newState(t), vm.Config{})
	if err != nil || receipts != nil {
		t.Fatalf("empty block = (%v, %v), want (nil, nil)", receipts, err)
	}
}

// The lane the executor was configured with is the lane it reports. A registry
// that read a different one would dispatch elsewhere than the operator asked.
func TestTheExecutorReportsTheLaneItWasGiven(t *testing.T) {
	for _, b := range []cevm.Backend{cevm.CPUSequential, cevm.CPUParallel, cevm.GPUMetal, cevm.GPUCUDA} {
		if got := (&Executor{CevmBackend: b}).Backend(); got != b {
			t.Errorf("Backend() = %s, want %s", got, b)
		}
	}
}

// The interface this package exists to satisfy.
func TestTheExecutorIsABlockExecutor(t *testing.T) {
	var _ evmparallel.BlockExecutor = (*Executor)(nil)
}

// This package must not claim luxfi/evm's single executor slot on import.
// RegisterExecutor is a plain assignment, and luxfi/evm's own cevmShadowExecutor
// takes that slot from an init() under -tags cevm; a second registration would
// replace a consensus-gated applier with this one on link order alone.
func TestImportingThisPackageRegistersNothing(t *testing.T) {
	if _, ok := evmparallel.DefaultExecutor().(*Executor); ok {
		t.Fatal("importing this package installed its Executor as the default; " +
			"registration is explicit and must stay explicit")
	}
}

// -----------------------------------------------------------------------------
// The block, in cevm's wire form
// -----------------------------------------------------------------------------

// Every field cevm reads comes from the transaction it was paired with, and the
// pairing is positional. A shape that crossed indexes would execute each
// transaction as somebody else.
func TestShapeCarriesEachTransactionsOwnFields(t *testing.T) {
	sdb := newState(t)
	to := common.Address{0x22}
	code := []byte{0x60, 0x00}
	sdb.SetCode(to, code, tracing.CodeChangeUnspecified)

	txs := types.Transactions{
		types.NewTx(&types.LegacyTx{
			Nonce: 7, To: &to, Value: big.NewInt(1234), Gas: 21000,
			GasPrice: big.NewInt(5), Data: []byte{0xAB},
		}),
		types.NewTx(&types.LegacyTx{Nonce: 8, Value: big.NewInt(1), Gas: 53000, GasPrice: big.NewInt(9)}),
	}
	senders := []common.Address{{0x11}, {0x33}}

	got, i := shape(txs, senders, sdb)
	if i != len(txs) {
		t.Fatalf("shape declined at index %d; every transaction here is representable", i)
	}

	if got[0].Nonce != 7 || got[0].Value != 1234 || got[0].GasLimit != 21000 || got[0].GasPrice != 5 {
		t.Errorf("tx 0 shaped as %+v", got[0])
	}
	if !got[0].HasTo || common.Address(got[0].To) != to {
		t.Errorf("tx 0 lost its recipient: HasTo=%v To=%x", got[0].HasTo, got[0].To)
	}
	if common.Address(got[0].From) != senders[0] {
		t.Errorf("tx 0 sender = %x, want %x", got[0].From, senders[0])
	}
	if string(got[0].Code) != string(code) {
		t.Errorf("tx 0 did not carry the recipient's code: %x", got[0].Code)
	}
	if string(got[0].Data) != string([]byte{0xAB}) {
		t.Errorf("tx 0 calldata = %x", got[0].Data)
	}

	// A creation has no recipient, so no address and no code to load.
	if got[1].HasTo {
		t.Errorf("tx 1 has no recipient but was shaped with one: %x", got[1].To)
	}
	if len(got[1].Code) != 0 {
		t.Errorf("tx 1 has no recipient but carries code: %x", got[1].Code)
	}
	if common.Address(got[1].From) != senders[1] {
		t.Errorf("tx 1 sender = %x, want %x", got[1].From, senders[1])
	}
}

// cevm.Transaction holds Value as a uint64. A value above 2^64-1 is rare but
// legal, and truncating it would execute a transaction other than the one that
// was signed — so the block is declined at the index that cannot be carried.
func TestAValueTooLargeForTheWireIsDeclinedAtItsIndex(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64: one past what fits
	txs := types.Transactions{
		types.NewTx(&types.LegacyTx{Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)}),
		types.NewTx(&types.LegacyTx{Value: huge, Gas: 21000, GasPrice: big.NewInt(1)}),
	}
	if _, i := shape(txs, []common.Address{{}, {}}, newState(t)); i != 1 {
		t.Fatalf("shape declined at index %d, want 1 (the transaction whose value overflows)", i)
	}

	// One below the boundary still fits, so the refusal is about the width and
	// not about "large".
	max := new(big.Int).Sub(huge, big.NewInt(1))
	txs[1] = types.NewTx(&types.LegacyTx{Value: max, Gas: 21000, GasPrice: big.NewInt(1)})
	got, i := shape(txs, []common.Address{{}, {}}, newState(t))
	if i != len(txs) {
		t.Fatalf("shape declined 2^64-1 at index %d; it is exactly representable", i)
	}
	if got[1].Value != max.Uint64() {
		t.Errorf("value = %d, want %d", got[1].Value, max.Uint64())
	}
}

// A nil gas price is left at zero rather than dereferenced.
func TestANilGasPriceIsZeroAndNotAPanic(t *testing.T) {
	tx := types.NewTx(&types.LegacyTx{Value: big.NewInt(1), Gas: 21000})
	got, i := shape(types.Transactions{tx}, []common.Address{{}}, newState(t))
	if i != 1 {
		t.Fatalf("shape declined at %d", i)
	}
	if got[0].GasPrice != 0 {
		t.Errorf("gas price = %d, want 0", got[0].GasPrice)
	}
}

// The block context is what the block-level opcodes answer. Each field comes
// from the header, and a field read from the wrong place is a block that
// executes against someone else's chain, height or time.
func TestTheBlockContextIsTheHeader(t *testing.T) {
	excess := uint64(131072)
	header := &types.Header{
		Time:          1717171717,
		Number:        big.NewInt(9_000_001),
		GasLimit:      15_000_000,
		BaseFee:       big.NewInt(25_000_000_000),
		ExcessBlobGas: &excess,
		Coinbase:      common.Address{0xC0, 0xFF, 0xEE},
		MixDigest:     common.Hash{0xAB, 0xCD},
	}
	config := &ethparams.ChainConfig{ChainID: big.NewInt(96369)}

	got := blockContext(config, header)

	if got.ChainID != 96369 {
		t.Errorf("ChainID = %d, want 96369 — a block executed against the wrong chain id "+
			"is replayable on another chain", got.ChainID)
	}
	if got.Timestamp != header.Time || got.Number != header.Number.Uint64() {
		t.Errorf("time/number = %d/%d, want %d/%d",
			got.Timestamp, got.Number, header.Time, header.Number.Uint64())
	}
	if got.GasLimit != header.GasLimit {
		t.Errorf("GasLimit = %d, want %d", got.GasLimit, header.GasLimit)
	}
	if got.BaseFee != header.BaseFee.Uint64() {
		t.Errorf("BaseFee = %d, want %d", got.BaseFee, header.BaseFee.Uint64())
	}
	if got.BlobBaseFee != excess {
		t.Errorf("BlobBaseFee = %d, want %d", got.BlobBaseFee, excess)
	}
	if common.Address(got.Coinbase) != header.Coinbase {
		t.Errorf("Coinbase = %x, want %x", got.Coinbase, header.Coinbase)
	}
	if common.Hash(got.Prevrandao) != header.MixDigest {
		t.Errorf("Prevrandao = %x, want the header's MixDigest %x", got.Prevrandao, header.MixDigest)
	}
}

// A pre-merge header carries no base fee and no blob gas. Those are absent
// values, not zero ones, and reading through the nil pointer would panic on
// every historical block.
func TestAHeaderWithoutBaseFeeOrBlobGasIsNotADereference(t *testing.T) {
	header := &types.Header{Number: big.NewInt(1), Time: 1}
	got := blockContext(&ethparams.ChainConfig{ChainID: big.NewInt(1)}, header)
	if got.BaseFee != 0 || got.BlobBaseFee != 0 {
		t.Fatalf("absent base fee / blob gas became %d / %d", got.BaseFee, got.BlobBaseFee)
	}
}

// A base fee wider than uint64 cannot be carried, and is left at zero rather
// than truncated into a different fee.
func TestABaseFeeTooLargeForTheWireIsNotTruncated(t *testing.T) {
	header := &types.Header{
		Number:  big.NewInt(1),
		BaseFee: new(big.Int).Lsh(big.NewInt(1), 64),
	}
	if got := blockContext(&ethparams.ChainConfig{ChainID: big.NewInt(1)}, header); got.BaseFee != 0 {
		t.Fatalf("BaseFee = %d; a value that does not fit must not be truncated", got.BaseFee)
	}
}

// -----------------------------------------------------------------------------
// What comes back
// -----------------------------------------------------------------------------

// cevm answers positionally, so a result of a different length than the block
// cannot be matched up. Assembling it anyway would attribute one transaction's
// gas and status to another.
func TestAResultThatDoesNotMatchTheBlockIsRefused(t *testing.T) {
	txs := types.Transactions{transfer(t, 1, big.NewInt(1)), transfer(t, 2, big.NewInt(1))}

	for _, r := range []*cevm.BlockResult{
		{GasUsed: []uint64{21000}, Status: []cevm.TxStatus{cevm.TxOK, cevm.TxOK}},
		{GasUsed: []uint64{21000, 21000}, Status: []cevm.TxStatus{cevm.TxOK}},
		{},
	} {
		if _, err := assemble(txs, newState(t), r, newHeader()); err == nil {
			t.Errorf("assemble accepted a result with %d gas entries and %d statuses for %d transactions",
				len(r.GasUsed), len(r.Status), len(txs))
		}
	}
}

// The V4 kernel says CallNotSupported for the CALL/CREATE family. Mixing
// backends mid-block would execute part of it on cevm and part on the Go EVM,
// so the whole block is declined at the transaction that could not run.
func TestATransactionTheKernelCannotRunDeclinesTheWholeBlock(t *testing.T) {
	t.Setenv(envCEVMStrict, "0")
	txs := types.Transactions{transfer(t, 1, big.NewInt(1)), transfer(t, 2, big.NewInt(1))}
	result := &cevm.BlockResult{
		GasUsed: []uint64{21000, 0},
		Status:  []cevm.TxStatus{cevm.TxOK, cevm.TxCallNotSupported},
	}
	receipts, err := assemble(txs, newState(t), result, newHeader())
	if err != nil || receipts != nil {
		t.Fatalf("assemble = (%v, %v), want the block declined", receipts, err)
	}
}

// The receipt reconstruction only holds where (status, gas_used) determines
// the receipt completely. Everything else is declined at the index that broke
// it.
//
// The contract-creation case is the one that used to be missed: the check
// asked whether the transaction had calldata, and a creation with empty init
// code has none. Its receipt needs a ContractAddress this reconstruction never
// computes, and creation is charged 53000 intrinsic gas against a transfer's
// 21000 — so the block would have been receipted with the wrong cumulative gas,
// which is exactly what the header commits to.
func TestOnlyAPlainValueTransferIsReconstructable(t *testing.T) {
	sdb := newState(t)
	withCode := common.Address{0x99}
	sdb.SetCode(withCode, []byte{0x00}, tracing.CodeChangeUnspecified)
	plain := common.Address{0x11}

	transferTx := types.NewTx(&types.LegacyTx{To: &plain, Value: big.NewInt(1), Gas: 21000})

	for _, tc := range []struct {
		name string
		tx   *types.Transaction
		want int
	}{
		{"plain transfer", transferTx, 1},
		{
			"contract creation with empty init code",
			types.NewTx(&types.LegacyTx{Value: big.NewInt(1), Gas: 53000}),
			0,
		},
		{
			"contract creation with init code",
			types.NewTx(&types.LegacyTx{Value: big.NewInt(0), Gas: 53000, Data: []byte{0x60, 0x00}}),
			0,
		},
		{
			"call with calldata",
			types.NewTx(&types.LegacyTx{To: &plain, Gas: 30000, Data: []byte{0x01}}),
			0,
		},
		{
			"transfer to an account that has code",
			types.NewTx(&types.LegacyTx{To: &withCode, Value: big.NewInt(1), Gas: 21000}),
			0,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := firstBeyondValueTransfer(types.Transactions{tc.tx}, sdb); got != tc.want {
				t.Fatalf("firstBeyondValueTransfer = %d, want %d", got, tc.want)
			}
		})
	}

	// And in a block, the index reported is the offending one, not zero.
	txs := types.Transactions{transferTx, transferTx, types.NewTx(&types.LegacyTx{Gas: 53000})}
	if got := firstBeyondValueTransfer(txs, sdb); got != 2 {
		t.Fatalf("firstBeyondValueTransfer = %d, want 2", got)
	}
}

// A block cevm cannot receipt is declined, and under strict mode that refusal
// names the transaction responsible.
func TestABlockBeyondValueTransferIsDeclinedAtItsIndex(t *testing.T) {
	t.Setenv(envCEVMStrict, "1")
	to := common.Address{0x11}
	txs := types.Transactions{
		types.NewTx(&types.LegacyTx{To: &to, Value: big.NewInt(1), Gas: 21000}),
		types.NewTx(&types.LegacyTx{Gas: 53000}), // a creation
	}
	result := &cevm.BlockResult{
		GasUsed: []uint64{21000, 53000},
		Status:  []cevm.TxStatus{cevm.TxOK, cevm.TxOK},
	}
	_, err := assemble(txs, newState(t), result, newHeader())
	if !errors.Is(err, ErrGPUEVMRequired) {
		t.Fatalf("assemble = %v, want ErrGPUEVMRequired", err)
	}
	if !strings.Contains(err.Error(), "tx_index=1") {
		t.Errorf("refusal %q does not name the transaction that could not be receipted", err)
	}
}

// The receipt is the parity-critical seam: the receipt trie hash is in the
// header, so every field has to be what the Go EVM would have produced.
func TestReceiptsCarryEachTransactionsOwnResult(t *testing.T) {
	t.Setenv(envCEVMStrict, "1")
	to := common.Address{0x11}
	txs := types.Transactions{
		types.NewTx(&types.LegacyTx{Nonce: 1, To: &to, Value: big.NewInt(1), Gas: 21000}),
		types.NewTx(&types.LegacyTx{Nonce: 2, To: &to, Value: big.NewInt(2), Gas: 21000}),
		types.NewTx(&types.DynamicFeeTx{Nonce: 3, To: &to, Value: big.NewInt(3), Gas: 21000}),
	}
	result := &cevm.BlockResult{
		GasUsed: []uint64{21000, 30000, 21000},
		Status:  []cevm.TxStatus{cevm.TxOK, cevm.TxRevert, cevm.TxReturn},
	}
	header := newHeader()

	got, err := assemble(txs, newState(t), result, header)
	if err != nil {
		t.Fatalf("assemble: %v", err)
	}
	if len(got) != len(txs) {
		t.Fatalf("got %d receipts for %d transactions", len(got), len(txs))
	}

	// Cumulative gas is what the header's gasUsed is checked against, so it
	// must be the running sum and not a repeat of the per-tx figure.
	for i, want := range []uint64{21000, 51000, 72000} {
		if got[i].CumulativeGasUsed != want {
			t.Errorf("receipt %d cumulative gas = %d, want %d", i, got[i].CumulativeGasUsed, want)
		}
		if got[i].GasUsed != result.GasUsed[i] {
			t.Errorf("receipt %d gas = %d, want %d", i, got[i].GasUsed, result.GasUsed[i])
		}
	}

	// TxOK and TxReturn are both a clean exit; everything else failed. A revert
	// receipted as successful is a transaction the chain says worked and did not.
	for i, want := range []uint64{
		types.ReceiptStatusSuccessful,
		types.ReceiptStatusFailed,
		types.ReceiptStatusSuccessful,
	} {
		if got[i].Status != want {
			t.Errorf("receipt %d status = %d for cevm status %s, want %d",
				i, got[i].Status, result.Status[i], want)
		}
	}

	for i, tx := range txs {
		if got[i].TxHash != tx.Hash() {
			t.Errorf("receipt %d is for %s, want %s", i, got[i].TxHash, tx.Hash())
		}
		if got[i].Type != tx.Type() {
			t.Errorf("receipt %d type = %d, want %d", i, got[i].Type, tx.Type())
		}
		if got[i].TransactionIndex != uint(i) {
			t.Errorf("receipt %d index = %d", i, got[i].TransactionIndex)
		}
		if got[i].BlockNumber.Cmp(header.Number) != 0 {
			t.Errorf("receipt %d block = %s, want %s", i, got[i].BlockNumber, header.Number)
		}
		if len(got[i].Logs) != 0 {
			t.Errorf("receipt %d carries %d logs; only value transfers reach here", i, len(got[i].Logs))
		}
		if got[i].Bloom != (types.Bloom{}) {
			t.Errorf("receipt %d has a non-empty bloom over no logs", i)
		}
	}
}

// Every failing cevm status becomes a failed receipt. A status this package
// has not heard of must not be read as success.
func TestAnUnrecognisedStatusIsNotSuccess(t *testing.T) {
	to := common.Address{0x11}
	tx := types.NewTx(&types.LegacyTx{To: &to, Value: big.NewInt(1), Gas: 21000})

	for _, st := range []cevm.TxStatus{
		cevm.TxRevert, cevm.TxOOG, cevm.TxError, cevm.TxStatus(200),
	} {
		result := &cevm.BlockResult{GasUsed: []uint64{21000}, Status: []cevm.TxStatus{st}}
		got := receipts(types.Transactions{tx}, result, newHeader())
		if got[0].Status != types.ReceiptStatusFailed {
			t.Errorf("cevm status %s became receipt status %d, want failed", st, got[0].Status)
		}
	}
}

// -----------------------------------------------------------------------------
// The state snapshot
// -----------------------------------------------------------------------------

// The kernel resolves CALL and CREATE targets from this snapshot, so every
// address the block touches has to be in it exactly once, carrying the state
// the StateDB holds.
func TestTheSnapshotHoldsEveryTouchedAccountOnce(t *testing.T) {
	sdb := newState(t)
	from, to := common.Address{0x01}, common.Address{0x02}
	code := []byte{0x60, 0x01, 0x60, 0x02}
	sdb.SetNonce(from, 9, tracing.NonceChangeUnspecified)
	sdb.AddBalance(from, uint256.NewInt(1_000_000), tracing.BalanceChangeUnspecified)
	sdb.SetCode(to, code, tracing.CodeChangeUnspecified)

	txs := []cevm.Transaction{
		{From: [20]byte(from), To: [20]byte(to), HasTo: true},
		{From: [20]byte(from), To: [20]byte(to), HasTo: true}, // same pair again
		{From: [20]byte(from)},                                // a creation: no target
	}

	got := buildStateSnapshot(txs, sdb)
	if len(got) != 2 {
		t.Fatalf("snapshot holds %d accounts, want 2 (the caller and the target, deduped)", len(got))
	}

	byAddr := map[common.Address]cevm.StateAccount{}
	for _, a := range got {
		if _, dup := byAddr[common.Address(a.Address)]; dup {
			t.Fatalf("account %x appears twice", a.Address)
		}
		byAddr[common.Address(a.Address)] = a
	}

	caller := byAddr[from]
	if caller.Nonce != 9 {
		t.Errorf("caller nonce = %d, want 9", caller.Nonce)
	}
	if caller.Balance != [4]uint64{1_000_000, 0, 0, 0} {
		t.Errorf("caller balance limbs = %v, want [1000000 0 0 0]", caller.Balance)
	}
	if len(caller.Code) != 0 {
		t.Errorf("an account with no code carries %d bytes of it", len(caller.Code))
	}

	target := byAddr[to]
	if string(target.Code) != string(code) {
		t.Errorf("target code = %x, want %x", target.Code, code)
	}
	if common.Hash(target.CodeHash) != sdb.GetCodeHash(to) {
		t.Errorf("target code hash = %x, want %x", target.CodeHash, sdb.GetCodeHash(to))
	}
}

// Balance crosses as four little-endian uint64 limbs because that is the
// kernel's layout. A balance assembled in the wrong order is a different
// number, and the kernel would fund or starve the account by it.
func TestTheBalanceLimbsAreLittleEndian(t *testing.T) {
	sdb := newState(t)
	addr := common.Address{0x07}

	// A value with a distinct byte in every limb, so a swapped or reversed
	// order cannot coincide with the right answer.
	bal := new(uint256.Int)
	bal.SetBytes32([]byte{
		0x44, 0, 0, 0, 0, 0, 0, 0x43, // limb 3 (most significant)
		0x34, 0, 0, 0, 0, 0, 0, 0x33, // limb 2
		0x24, 0, 0, 0, 0, 0, 0, 0x23, // limb 1
		0x14, 0, 0, 0, 0, 0, 0, 0x13, // limb 0 (least significant)
	})
	sdb.AddBalance(addr, bal, tracing.BalanceChangeUnspecified)

	got := buildStateSnapshot([]cevm.Transaction{{From: [20]byte(addr)}}, sdb)
	if len(got) != 1 {
		t.Fatalf("snapshot holds %d accounts, want 1", len(got))
	}
	want := [4]uint64{
		0x1400000000000013,
		0x2400000000000023,
		0x3400000000000033,
		0x4400000000000043,
	}
	if got[0].Balance != want {
		t.Fatalf("balance limbs = %#x, want %#x", got[0].Balance, want)
	}
	// And the limbs really are the number: reassembling them gives it back.
	if reassemble(got[0].Balance).Cmp(bal) != 0 {
		t.Fatalf("limbs reassemble to %s, want %s", reassemble(got[0].Balance), bal)
	}
}

// Nothing to snapshot is not an empty snapshot to build. A nil StateDB is the
// caller having nothing to read from, which must not be a dereference.
func TestThereIsNoSnapshotWithoutTransactionsOrAState(t *testing.T) {
	if got := buildStateSnapshot(nil, newState(t)); got != nil {
		t.Errorf("snapshot of no transactions = %v, want nil", got)
	}
	if got := buildStateSnapshot([]cevm.Transaction{{}}, nil); got != nil {
		t.Errorf("snapshot with no state = %v, want nil", got)
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func newState(t *testing.T) *state.StateDB {
	t.Helper()
	sdb, err := state.New(types.EmptyRootHash, state.NewDatabase(rawdb.NewMemoryDatabase()), nil)
	if err != nil {
		t.Fatalf("state.New: %v", err)
	}
	return sdb
}

func newHeader() *types.Header {
	return &types.Header{Number: big.NewInt(1), Time: 1, GasLimit: 15_000_000}
}

func chainConfig() *ethparams.ChainConfig {
	return &ethparams.ChainConfig{ChainID: big.NewInt(96369)}
}

// transfer builds a plain value transfer to a fixed recipient.
func transfer(t *testing.T, nonce uint64, value *big.Int) *types.Transaction {
	t.Helper()
	to := common.Address{0x11}
	return types.NewTx(&types.LegacyTx{Nonce: nonce, To: &to, Value: value, Gas: 21000})
}

// reassemble rebuilds a uint256 from little-endian limbs.
func reassemble(limbs [4]uint64) *uint256.Int {
	out := new(uint256.Int)
	for i := 3; i >= 0; i-- {
		out.Lsh(out, 64)
		out.Or(out, uint256.NewInt(limbs[i]))
	}
	return out
}
