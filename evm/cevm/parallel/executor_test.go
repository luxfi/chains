// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package parallel

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/luxfi/chains/evm/cevm"
	"github.com/luxfi/crypto/backend"
	evmparallel "github.com/luxfi/evm/core/parallel"
	"github.com/luxfi/evm/core/state"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/consensus/misc/eip4844"
	"github.com/luxfi/geth/core/rawdb"
	"github.com/luxfi/geth/core/tracing"
	"github.com/luxfi/geth/core/types"
	"github.com/luxfi/geth/core/vm"
	ethparams "github.com/luxfi/geth/params"
)

// -----------------------------------------------------------------------------
// Declining
// -----------------------------------------------------------------------------

// fallbacks is how many declines crypto/backend has counted.
func fallbacks() uint64 {
	return backend.FallbackCounters()[backend.FallbackBackendUnavailable.String()]
}

// A decline is luxfi/evm's "not handled", (nil, nil), on which the state
// processor runs the block on its sequential Go EVM — never an error, which
// would say the block is bad. It is counted, so a lane that declines
// everything is visible.
func TestADeclineFallsThroughToTheGoEVMAndIsCounted(t *testing.T) {
	before := fallbacks()
	receipts, err := declineBlock("cevm_declined", 42, 7)
	if err != nil || receipts != nil {
		t.Fatalf("declineBlock = (%v, %v), want (nil, nil) so the caller runs the block", receipts, err)
	}
	if fallbacks() != before+1 {
		t.Errorf("fallback counter moved %d → %d, want one more", before, fallbacks())
	}
}

// ok=0 from the library is ErrDeclined, and the block goes to the Go EVM:
// (nil, nil). Whatever came back with the decline is not read — a declined
// result's statuses all say Error and its gas is the tx's whole limit, so
// receipting it would fail every transaction in a block that did not fail.
func TestABlockCevmDeclinesRunsOnTheGoEVM(t *testing.T) {
	txs := types.Transactions{transfer(t, 0, big.NewInt(1)), transfer(t, 1, big.NewInt(1))}
	calls := 0
	e := &Executor{
		CevmBackend: cevm.GPUCUDA,
		execute: func(cevm.Backend, uint32, []cevm.Transaction, *cevm.BlockContext, []cevm.StateAccount) (*cevm.BlockResult, error) {
			calls++
			return &cevm.BlockResult{
				GasUsed: []uint64{21000, 21000},
				Status:  []cevm.TxStatus{cevm.TxError, cevm.TxError},
			}, cevm.ErrDeclined
		},
	}
	before := fallbacks()
	receipts, err := e.run(chainConfig(), newHeader(), txs, senders(len(txs)), newState(t))
	if err != nil || receipts != nil {
		t.Fatalf("a declined block = (%v, %v), want (nil, nil): the Go EVM runs it", receipts, err)
	}
	if calls != 1 {
		t.Fatalf("cevm was called %d times, want 1", calls)
	}
	if fallbacks() != before+1 {
		t.Errorf("the decline was not counted")
	}
}

// A failure that is not a decline — a result for another ABI, say — is an
// error: the library broke its contract, which is not the same as refusing
// the block.
func TestACevmFailureThatIsNotADeclineIsAnError(t *testing.T) {
	broken := errors.New("cevm: ABI version mismatch in result")
	e := &Executor{
		CevmBackend: cevm.GPUMetal,
		execute: func(cevm.Backend, uint32, []cevm.Transaction, *cevm.BlockContext, []cevm.StateAccount) (*cevm.BlockResult, error) {
			return nil, broken
		},
	}
	txs := types.Transactions{transfer(t, 0, big.NewInt(1))}
	receipts, err := e.run(chainConfig(), newHeader(), txs, senders(len(txs)), newState(t))
	if !errors.Is(err, broken) {
		t.Fatalf("run = (%v, %v), want the library's error", receipts, err)
	}
	if receipts != nil {
		t.Errorf("an error came with %d receipts", len(receipts))
	}
}

// A block cevm ran comes back as receipts built from its result.
func TestABlockCevmRanIsReceipted(t *testing.T) {
	txs := types.Transactions{transfer(t, 0, big.NewInt(1)), transfer(t, 1, big.NewInt(1))}
	e := &Executor{
		CevmBackend: cevm.GPUMetal,
		execute: func(cevm.Backend, uint32, []cevm.Transaction, *cevm.BlockContext, []cevm.StateAccount) (*cevm.BlockResult, error) {
			return &cevm.BlockResult{
				GasUsed: []uint64{21000, 21000},
				Status:  []cevm.TxStatus{cevm.TxOK, cevm.TxOK},
			}, nil
		},
	}
	receipts, err := e.run(chainConfig(), newHeader(), txs, senders(len(txs)), newState(t))
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if len(receipts) != len(txs) || receipts[1].CumulativeGasUsed != 42000 {
		t.Fatalf("receipts = %v, want two at 21000 each", receipts)
	}
}

// Nothing wider than cevm's 64-bit wire reaches cevm. A value or a price of
// 2^64 is legal; truncated to 0 it is another transaction, so the block goes
// to the Go EVM and cevm is never called. The same holds for a tx the wire
// drops part of, and for a base fee or chain id that does not fit.
func TestWhatDoesNotFitTheWireNeverReachesCevm(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 64)
	to := common.Address{0x11}
	for _, tc := range []struct {
		name   string
		tx     *types.Transaction
		header func(*types.Header)
		config *ethparams.ChainConfig
	}{
		{name: "value 2^64", tx: types.NewTx(&types.LegacyTx{To: &to, Value: huge, Gas: 21000, GasPrice: big.NewInt(1)})},
		{name: "gas price 2^64", tx: types.NewTx(&types.LegacyTx{To: &to, Value: big.NewInt(1), Gas: 21000, GasPrice: huge})},
		{name: "fee cap 2^64", tx: types.NewTx(&types.DynamicFeeTx{To: &to, Value: big.NewInt(1), Gas: 21000, GasFeeCap: huge, GasTipCap: big.NewInt(1)})},
		{
			name: "an access list",
			tx: types.NewTx(&types.AccessListTx{
				To: &to, Value: big.NewInt(1), Gas: 23400, GasPrice: big.NewInt(1),
				AccessList: types.AccessList{{Address: common.Address{0x22}}},
			}),
		},
		{name: "tip above fee cap", tx: types.NewTx(&types.DynamicFeeTx{To: &to, Value: big.NewInt(1), Gas: 21000, GasFeeCap: big.NewInt(1), GasTipCap: big.NewInt(2)})},
		{
			name:   "base fee 2^64",
			tx:     transfer(t, 0, big.NewInt(1)),
			header: func(h *types.Header) { h.BaseFee = new(big.Int).Set(huge) },
		},
		{
			name:   "chain id 2^64",
			tx:     transfer(t, 0, big.NewInt(1)),
			config: &ethparams.ChainConfig{ChainID: new(big.Int).Set(huge)},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Executor{
				CevmBackend: cevm.GPUCUDA,
				execute: func(cevm.Backend, uint32, []cevm.Transaction, *cevm.BlockContext, []cevm.StateAccount) (*cevm.BlockResult, error) {
					t.Fatal("cevm was called with a block its wire cannot carry")
					return nil, nil
				},
			}
			header := newHeader()
			if tc.header != nil {
				tc.header(header)
			}
			config := chainConfig()
			if tc.config != nil {
				config = tc.config
			}
			txs := types.Transactions{transfer(t, 0, big.NewInt(1)), tc.tx}
			receipts, err := e.run(config, header, txs, senders(len(txs)), newState(t))
			if err != nil || receipts != nil {
				t.Fatalf("run = (%v, %v), want (nil, nil): the Go EVM runs the block", receipts, err)
			}
		})
	}
}

// A CPU lane runs nothing through cevm's Go entry, so the block goes to the Go
// EVM without asking cevm — a library that answered there would answer a gas
// estimate.
func TestACPULaneDeclinesWithoutAskingCevm(t *testing.T) {
	for _, b := range []cevm.Backend{cevm.CPUSequential, cevm.CPUParallel} {
		t.Run(b.String(), func(t *testing.T) {
			e := &Executor{
				CevmBackend: b,
				execute: func(cevm.Backend, uint32, []cevm.Transaction, *cevm.BlockContext, []cevm.StateAccount) (*cevm.BlockResult, error) {
					t.Fatal("cevm was asked to run a block on a CPU lane")
					return nil, nil
				},
			}
			txs := types.Transactions{transfer(t, 0, big.NewInt(1))}
			receipts, err := e.run(chainConfig(), newHeader(), txs, senders(len(txs)), newState(t))
			if err != nil || receipts != nil {
				t.Fatalf("run = (%v, %v), want (nil, nil)", receipts, err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// A build with no C++ EVM
// -----------------------------------------------------------------------------

// The executor in a binary that has no cevm to dispatch to must decline, not
// hard-fail: the absence of the library is a property of the build, and every
// block then belongs to the Go EVM.
func TestABuildWithNoLibraryDeclinesRatherThanHalting(t *testing.T) {
	e := &Executor{CevmBackend: cevm.GPUCUDA}
	sdb := newState(t)
	header := newHeader()
	txs := types.Transactions{transfer(t, 1, big.NewInt(1))}

	receipts, err := e.ExecuteBlock(chainConfig(), header, txs, sdb, vm.Config{})
	if err != nil {
		t.Fatalf("the block must fall through to the Go EVM, got: %v", err)
	}
	if receipts != nil {
		t.Errorf("fall-through returned %d receipts", len(receipts))
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

// cevm.Transaction holds Value and GasPrice as uint64. A value or price above
// 2^64-1 is rare but legal, and truncating it would execute a transaction
// other than the one that was signed — so the block is declined at the index
// that cannot be carried.
func TestAValueOrPriceTooLargeForTheWireIsDeclinedAtItsIndex(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 64) // 2^64: one past what fits
	max := new(big.Int).Sub(huge, big.NewInt(1))
	for _, tc := range []struct {
		name        string
		wide, exact *types.Transaction
	}{
		{
			name:  "value",
			wide:  types.NewTx(&types.LegacyTx{Value: huge, Gas: 21000, GasPrice: big.NewInt(1)}),
			exact: types.NewTx(&types.LegacyTx{Value: max, Gas: 21000, GasPrice: big.NewInt(1)}),
		},
		{
			name:  "legacy price",
			wide:  types.NewTx(&types.LegacyTx{Value: big.NewInt(1), Gas: 21000, GasPrice: huge}),
			exact: types.NewTx(&types.LegacyTx{Value: big.NewInt(1), Gas: 21000, GasPrice: max}),
		},
		{
			name:  "fee cap",
			wide:  types.NewTx(&types.DynamicFeeTx{Value: big.NewInt(1), Gas: 21000, GasFeeCap: huge, GasTipCap: big.NewInt(1)}),
			exact: types.NewTx(&types.DynamicFeeTx{Value: big.NewInt(1), Gas: 21000, GasFeeCap: max, GasTipCap: big.NewInt(1)}),
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			first := types.NewTx(&types.LegacyTx{Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)})
			if _, i := shape(types.Transactions{first, tc.wide}, senders(2), newState(t)); i != 1 {
				t.Fatalf("shape declined at index %d, want 1 (the transaction that overflows)", i)
			}

			// One below the boundary still fits, so the refusal is about the
			// width and not about "large".
			got, i := shape(types.Transactions{first, tc.exact}, senders(2), newState(t))
			if i != 2 {
				t.Fatalf("shape declined 2^64-1 at index %d; it is exactly representable", i)
			}
			if got[1].Value != tc.exact.Value().Uint64() || got[1].GasPrice != tc.exact.GasPrice().Uint64() {
				t.Errorf("shaped value/price = %d/%d, want %d/%d", got[1].Value, got[1].GasPrice,
					tc.exact.Value().Uint64(), tc.exact.GasPrice().Uint64())
			}
		})
	}
}

// CGpuTx has one price and no access list, blob hashes, authorizations or tip.
// A tx that carries any of them is charged for them, or invalid by them, where
// cevm would not see it: it is declined at its index.
func TestATransactionTheWireDropsPartOfIsDeclinedAtItsIndex(t *testing.T) {
	to := common.Address{0x11}
	plain := types.NewTx(&types.LegacyTx{To: &to, Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)})
	for _, tc := range []struct {
		name string
		tx   *types.Transaction
		want int
	}{
		{"legacy", plain, 2},
		{"access-list type, empty list", types.NewTx(&types.AccessListTx{To: &to, Gas: 21000, GasPrice: big.NewInt(1)}), 2},
		{"dynamic fee, tip at the cap", types.NewTx(&types.DynamicFeeTx{To: &to, Gas: 21000, GasFeeCap: big.NewInt(2), GasTipCap: big.NewInt(2)}), 2},
		{
			"an access list",
			types.NewTx(&types.AccessListTx{
				To: &to, Gas: 25300, GasPrice: big.NewInt(1),
				AccessList: types.AccessList{{Address: common.Address{0x22}, StorageKeys: []common.Hash{{0x01}}}},
			}),
			1,
		},
		{"tip above the fee cap", types.NewTx(&types.DynamicFeeTx{To: &to, Gas: 21000, GasFeeCap: big.NewInt(1), GasTipCap: big.NewInt(2)}), 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, i := shape(types.Transactions{plain, tc.tx}, senders(2), newState(t)); i != tc.want {
				t.Fatalf("shape stopped at %d, want %d", i, tc.want)
			}
		})
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
	excess := uint64(10_000_000)
	header := &types.Header{
		Time:          1717171717,
		Number:        big.NewInt(9_000_001),
		GasLimit:      15_000_000,
		BaseFee:       big.NewInt(25_000_000_000),
		ExcessBlobGas: &excess,
		Coinbase:      common.Address{0xC0, 0xFF, 0xEE},
		MixDigest:     common.Hash{0xAB, 0xCD},
	}
	cancun := uint64(0)
	config := &ethparams.ChainConfig{
		ChainID:            big.NewInt(96369),
		LondonBlock:        big.NewInt(0),
		CancunTime:         &cancun,
		BlobScheduleConfig: &ethparams.BlobScheduleConfig{Cancun: ethparams.DefaultCancunBlobConfig},
	}

	got, ok := blockContext(config, header)
	if !ok {
		t.Fatal("blockContext refused a header whose every field fits")
	}

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
	// BLOBBASEFEE is the fee the excess blob gas prices, not the excess.
	if want := eip4844.CalcBlobFee(config, header).Uint64(); got.BlobBaseFee != want || want == excess {
		t.Errorf("BlobBaseFee = %d, want %d (the fee %d excess blob gas prices)", got.BlobBaseFee, want, excess)
	}
	// Before a blob schedule there is no blob fee.
	if got, _ := blockContext(&ethparams.ChainConfig{ChainID: big.NewInt(96369)}, header); got.BlobBaseFee != 0 {
		t.Errorf("BlobBaseFee = %d with no blob schedule, want 0", got.BlobBaseFee)
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
	got, ok := blockContext(&ethparams.ChainConfig{ChainID: big.NewInt(1)}, header)
	if !ok {
		t.Fatal("an absent base fee was refused; absent is zero, and zero fits")
	}
	if got.BaseFee != 0 || got.BlobBaseFee != 0 {
		t.Fatalf("absent base fee / blob gas became %d / %d", got.BaseFee, got.BlobBaseFee)
	}
}

// A base fee or chain id wider than uint64 cannot be carried. Zero would be a
// different fee — one every underpriced tx clears — so the context is refused
// and the block declined, rather than truncated.
func TestABaseFeeOrChainIDTooLargeForTheWireIsRefused(t *testing.T) {
	huge := new(big.Int).Lsh(big.NewInt(1), 64)
	header := &types.Header{Number: big.NewInt(1), BaseFee: huge}
	if got, ok := blockContext(&ethparams.ChainConfig{ChainID: big.NewInt(1)}, header); ok {
		t.Fatalf("base fee 2^64 gave a context (BaseFee=%d); it must be refused", got.BaseFee)
	}
	header.BaseFee = big.NewInt(1)
	if got, ok := blockContext(&ethparams.ChainConfig{ChainID: huge}, header); ok {
		t.Fatalf("chain id 2^64 gave a context (ChainID=%d); it must be refused", got.ChainID)
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
		if _, err := assemble(txs, r, newHeader()); err == nil {
			t.Errorf("assemble accepted a result with %d gas entries and %d statuses for %d transactions",
				len(r.GasUsed), len(r.Status), len(txs))
		}
	}
}

// cevm answers ok=1 only when every tx is a valid plain transfer that
// succeeded on its 21000 intrinsic gas (gpu_dispatch.cpp ran_through). Any
// other answer — CallNotSupported, which never reaches a caller, a reverted or
// returning status, a gas estimate at the tx's limit — is not the block's, and
// the whole block is declined rather than part of it receipted.
func TestOnlyAnAnswerOfPlainTransfersIsReceipted(t *testing.T) {
	txs := types.Transactions{transfer(t, 1, big.NewInt(1)), transfer(t, 2, big.NewInt(1))}
	ok := &cevm.BlockResult{GasUsed: []uint64{21000, 21000}, Status: []cevm.TxStatus{cevm.TxOK, cevm.TxOK}}
	if got, err := assemble(txs, ok, newHeader()); err != nil || len(got) != 2 {
		t.Fatalf("assemble(two transfers at 21000) = (%v, %v), want two receipts", got, err)
	}
	for _, tc := range []struct {
		name   string
		gas    uint64
		status cevm.TxStatus
	}{
		{"call not supported", 21000, cevm.TxCallNotSupported},
		{"return", 21000, cevm.TxReturn},
		{"revert", 21000, cevm.TxRevert},
		{"error", 21000, cevm.TxError},
		{"a gas estimate at the limit", 100000, cevm.TxOK},
		{"one gas over intrinsic", 21001, cevm.TxOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := &cevm.BlockResult{
				GasUsed: []uint64{21000, tc.gas},
				Status:  []cevm.TxStatus{cevm.TxOK, tc.status},
			}
			receipts, err := assemble(txs, result, newHeader())
			if err != nil || receipts != nil {
				t.Fatalf("assemble = (%v, %v), want the block declined: (nil, nil)", receipts, err)
			}
		})
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

// A block cevm cannot receipt is declined to the Go EVM before cevm is asked:
// a creation, calldata, or a recipient with code. cevm declines code anyway,
// and no answer it gives could be receipted past a plain transfer.
func TestABlockBeyondValueTransferIsDeclinedBeforeCevm(t *testing.T) {
	sdb := newState(t)
	to, withCode := common.Address{0x11}, common.Address{0x99}
	sdb.SetCode(withCode, []byte{0x00}, tracing.CodeChangeUnspecified)
	plain := types.NewTx(&types.LegacyTx{To: &to, Value: big.NewInt(1), Gas: 21000})
	for _, tc := range []struct {
		name string
		tx   *types.Transaction
	}{
		{"a creation", types.NewTx(&types.LegacyTx{Gas: 53000})},
		{"calldata", types.NewTx(&types.LegacyTx{To: &to, Gas: 30000, Data: []byte{0x01}})},
		{"a recipient with code", types.NewTx(&types.LegacyTx{To: &withCode, Value: big.NewInt(1), Gas: 21000})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := &Executor{
				CevmBackend: cevm.GPUMetal,
				execute: func(cevm.Backend, uint32, []cevm.Transaction, *cevm.BlockContext, []cevm.StateAccount) (*cevm.BlockResult, error) {
					t.Fatal("cevm was asked to run a block it could not receipt")
					return nil, nil
				},
			}
			txs := types.Transactions{plain, tc.tx}
			receipts, err := e.run(chainConfig(), newHeader(), txs, senders(len(txs)), sdb)
			if err != nil || receipts != nil {
				t.Fatalf("run = (%v, %v), want the block declined: (nil, nil)", receipts, err)
			}
		})
	}
}

// The receipt is the parity-critical seam: the receipt trie hash is in the
// header, so every field has to be what the Go EVM would have produced. The
// reconstruction is read here for every status, though assemble only ever
// hands it plain transfers at 21000.
func TestReceiptsCarryEachTransactionsOwnResult(t *testing.T) {
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

	got := receipts(txs, result, header)
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

// cevm takes an account the snapshot lacks not to exist, so every address the
// block touches — callers, targets and the coinbase — has to be in it exactly
// once, carrying the state the StateDB holds.
func TestTheSnapshotHoldsEveryTouchedAccountOnce(t *testing.T) {
	sdb := newState(t)
	from, to, coinbase := common.Address{0x01}, common.Address{0x02}, common.Address{0xC0}
	code := []byte{0x60, 0x01, 0x60, 0x02}
	sdb.SetNonce(from, 9, tracing.NonceChangeUnspecified)
	sdb.AddBalance(from, uint256.NewInt(1_000_000), tracing.BalanceChangeUnspecified)
	sdb.SetCode(to, code, tracing.CodeChangeUnspecified)

	txs := []cevm.Transaction{
		{From: [20]byte(from), To: [20]byte(to), HasTo: true},
		{From: [20]byte(from), To: [20]byte(to), HasTo: true}, // same pair again
		{From: [20]byte(from)},                                // a creation: no target
	}

	got := buildStateSnapshot(txs, coinbase, sdb)
	if len(got) != 3 {
		t.Fatalf("snapshot holds %d accounts, want 3 (the caller, the target and the coinbase, deduped)", len(got))
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
	if _, ok := byAddr[coinbase]; !ok {
		t.Error("the coinbase, which every fee credits, is not in the snapshot")
	}

	// The coinbase is already a caller: it is not added twice.
	if got := buildStateSnapshot(txs, from, sdb); len(got) != 2 {
		t.Errorf("snapshot with the caller as coinbase holds %d accounts, want 2", len(got))
	}
}

// An account that does not exist has no code and no storage, and its row says
// so with the hashes of nothing. The StateDB answers zero for both, which cevm
// reads as "says nothing" and declines: a sender or recipient that has never
// been seen — the usual first transfer to a fresh address — would decline
// every block it is in.
func TestAnAccountThatDoesNotExistSaysItHasNoCodeAndNoStorage(t *testing.T) {
	sdb := newState(t)
	absent := common.Address{0xAB}
	if sdb.Exist(absent) {
		t.Fatal("test setup: the account exists")
	}
	got := buildStateSnapshot([]cevm.Transaction{{From: [20]byte(absent)}}, absent, sdb)
	if len(got) != 1 {
		t.Fatalf("snapshot holds %d accounts, want 1", len(got))
	}
	if common.Hash(got[0].CodeHash) != types.EmptyCodeHash {
		t.Errorf("code hash = %x, want keccak256 of nothing %x", got[0].CodeHash, types.EmptyCodeHash)
	}
	if common.Hash(got[0].StorageRoot) != types.EmptyRootHash {
		t.Errorf("storage root = %x, want the empty trie root %x", got[0].StorageRoot, types.EmptyRootHash)
	}
}

// An account with storage carries its storage trie root, not zero and not the
// empty root.
func TestAnAccountCarriesItsStorageRoot(t *testing.T) {
	sdb := newState(t)
	addr := common.Address{0x0D}
	sdb.AddBalance(addr, uint256.NewInt(1), tracing.BalanceChangeUnspecified)
	sdb.SetState(addr, common.Hash{0x01}, common.Hash{0x02})
	sdb.IntermediateRoot(false)

	root := sdb.GetStorageRoot(addr)
	if root == (common.Hash{}) || root == types.EmptyRootHash {
		t.Fatalf("test setup: storage root %x is not a written trie's", root)
	}
	got := buildStateSnapshot([]cevm.Transaction{{From: [20]byte(addr)}}, addr, sdb)
	if len(got) != 1 {
		t.Fatalf("snapshot holds %d accounts, want 1", len(got))
	}
	if common.Hash(got[0].StorageRoot) != root {
		t.Errorf("storage root = %x, want %x", got[0].StorageRoot, root)
	}
	if common.Hash(got[0].CodeHash) != types.EmptyCodeHash {
		t.Errorf("code hash = %x, want %x for an account with no code", got[0].CodeHash, types.EmptyCodeHash)
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

	got := buildStateSnapshot([]cevm.Transaction{{From: [20]byte(addr)}}, addr, sdb)
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
	if got := buildStateSnapshot(nil, common.Address{}, newState(t)); got != nil {
		t.Errorf("snapshot of no transactions = %v, want nil", got)
	}
	if got := buildStateSnapshot([]cevm.Transaction{{}}, common.Address{}, nil); got != nil {
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

// senders is n distinct sender addresses, positionally paired with a block.
func senders(n int) []common.Address {
	out := make([]common.Address, n)
	for i := range out {
		out[i] = common.Address{0xA0, byte(i + 1)}
	}
	return out
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
