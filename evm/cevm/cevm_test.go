// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cevm

import (
	"strings"
	"testing"
	"unsafe"

	"github.com/luxfi/geth/core/types"
)

// Tests in this file run under every build. They cover the parts of the API
// that do not depend on the C++ library: the enum stringers, the wire layout
// the C ABI reads by memcpy, and — the part that matters — what the package
// does when the native library is NOT linked, which is the default build and
// the only one that works on a host without the lux-cevm bundle.

func TestBackendString(t *testing.T) {
	tests := []struct {
		b    Backend
		want string
	}{
		{CPUSequential, "cpu-sequential"},
		{CPUParallel, "cpu-parallel"},
		{GPUMetal, "gpu-metal"},
		{GPUCUDA, "gpu-cuda"},
		{Backend(99), "unknown(99)"},
	}

	for _, tt := range tests {
		if got := tt.b.String(); got != tt.want {
			t.Errorf("Backend(%d).String() = %q, want %q", int(tt.b), got, tt.want)
		}
	}
}

func TestTxStatusString(t *testing.T) {
	tests := []struct {
		s    TxStatus
		want string
	}{
		{TxOK, "ok"},
		{TxReturn, "return"},
		{TxRevert, "revert"},
		{TxOOG, "oog"},
		{TxError, "error"},
		{TxCallNotSupported, "call-not-supported"},
		{TxStatus(99), "status(99)"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("TxStatus(%d).String() = %q, want %q", int(tt.s), got, tt.want)
		}
	}
}

// -----------------------------------------------------------------------------
// Refusing, rather than pretending to execute
// -----------------------------------------------------------------------------

// The one property that matters when the native EVM is not linked: a block
// with transactions in it must NOT come back as a result.
//
// A successful-looking BlockResult here is a block whose transactions were
// never applied. The caller writes the state root and the gas, consensus
// accepts it, and the chain has diverged from every node that did link the
// library — silently, because nothing errored. So the refusal is the
// consensus-relevant behaviour, not a convenience.
func TestABlockWithTransactionsIsRefusedRatherThanFaked(t *testing.T) {
	for _, backend := range []Backend{CPUSequential, CPUParallel, GPUMetal, GPUCUDA} {
		result, err := ExecuteBlock(backend, 4, []Transaction{{GasLimit: 21000}}, nil, nil)
		if err == nil {
			t.Fatalf("ExecuteBlock(%s, 1 tx) returned no error; a block that was never "+
				"executed must not come back as a result", backend)
		}
		if result != nil {
			t.Errorf("ExecuteBlock(%s, 1 tx) returned a result (%+v) alongside its refusal",
				backend, result)
		}
		// The message has to say what to do about it: an operator reading a
		// bare "not supported" cannot tell a missing build tag from a missing
		// GPU.
		if !strings.Contains(err.Error(), "lux_cevm_native") {
			t.Errorf("ExecuteBlock error %q does not name the build tag that fixes it", err)
		}
	}
}

// A block context and a state snapshot do not change the refusal. They are the
// V4 arguments; accepting them and then not executing would be the same
// divergence with more ceremony.
func TestContextAndSnapshotDoNotBuyExecution(t *testing.T) {
	ctx := &BlockContext{ChainID: 96369, Number: 7}
	snapshot := []StateAccount{{Nonce: 1}}

	if _, err := ExecuteBlock(GPUCUDA, 8, []Transaction{{GasLimit: 21000}}, ctx, snapshot); err == nil {
		t.Fatal("ExecuteBlock accepted a block once it was handed a context and a snapshot")
	}
}

// An empty block is the documented exception: there is nothing to execute, so
// there is nothing to get wrong, and the caller gets the ABI the linked library
// reports rather than an error it would have to special-case.
func TestAnEmptyBlockIsTheOneThingThatCanBeAnswered(t *testing.T) {
	for _, txs := range [][]Transaction{nil, {}} {
		result, err := ExecuteBlock(CPUSequential, 0, txs, nil, nil)
		if err != nil {
			t.Fatalf("ExecuteBlock(%v): %v", txs, err)
		}
		if result == nil {
			t.Fatal("ExecuteBlock returned neither a result nor an error")
		}
		if result.TotalGas != 0 {
			t.Errorf("TotalGas = %d, want 0 for an empty block", result.TotalGas)
		}
		if len(result.GasUsed) != 0 || len(result.Status) != 0 {
			t.Errorf("empty block reported %d gas entries and %d statuses",
				len(result.GasUsed), len(result.Status))
		}
		if result.ABIVersion != ABIVersion {
			t.Errorf("ABIVersion = %d, want %d", result.ABIVersion, ABIVersion)
		}
	}
}

// BatchRecoverSenders is the same shape: no transactions is not a failure, and
// any transaction is a refusal. Its doc tells the caller to fall back to
// per-tx types.Sender, which is only actionable if the caller can tell the two
// apart — so the empty case must not error.
func TestBatchRecoveryRefusesWorkAndNotEmptiness(t *testing.T) {
	signer := types.LatestSignerForChainID(nil)

	senders, err := BatchRecoverSenders(nil, signer)
	if err != nil {
		t.Fatalf("BatchRecoverSenders(nil) = %v, want no error", err)
	}
	if senders != nil {
		t.Errorf("BatchRecoverSenders(nil) returned %d senders", len(senders))
	}

	txs := types.Transactions{types.NewTx(&types.LegacyTx{Gas: 21000})}
	senders, err = BatchRecoverSenders(txs, signer)
	if err == nil {
		t.Fatal("BatchRecoverSenders returned no error with the native library unlinked; " +
			"a caller would read the zero addresses as recovered senders")
	}
	if senders != nil {
		t.Errorf("BatchRecoverSenders returned %d senders alongside its refusal", len(senders))
	}
	if !strings.Contains(err.Error(), "lux_cevm_native") {
		t.Errorf("BatchRecoverSenders error %q does not name the build tag that fixes it", err)
	}
}

// -----------------------------------------------------------------------------
// What this build reports about itself
// -----------------------------------------------------------------------------

// Every build exposes at least one backend and names it. A caller that reads
// an empty list has no lane to dispatch to and no way to say why.
func TestThisBuildReportsExactlyTheBackendItCanRun(t *testing.T) {
	got := AvailableBackends()
	if len(got) == 0 {
		t.Fatal("AvailableBackends() returned an empty list")
	}
	for _, b := range got {
		if BackendName(b) == "" {
			t.Errorf("BackendName(%d) is empty", int(b))
		}
	}
	// AutoDetect must pick from the list it just published, not from the enum.
	auto := AutoDetect()
	found := false
	for _, b := range got {
		if b == auto {
			found = true
		}
	}
	if !found {
		t.Fatalf("AutoDetect() = %s, which is not in AvailableBackends() = %v", auto, got)
	}
}

// The name is the Backend's own String under this build — there is no library
// to ask — so the two cannot drift into two vocabularies for one lane.
func TestBackendNameAgreesWithTheStringer(t *testing.T) {
	for _, b := range []Backend{CPUSequential, CPUParallel, GPUMetal, GPUCUDA, Backend(99)} {
		if got, want := BackendName(b), b.String(); got != want {
			t.Errorf("BackendName(%d) = %q, Backend.String() = %q", int(b), got, want)
		}
	}
}

// The ABI the Go module expects and the ABI the loaded library reports are
// compared at process start, and a mismatch panics on purpose: a silent skew
// produces wrong gas and wrong state roots, which is a consensus fault. With
// no library linked there is nothing to compare against, and LibraryABIVersion
// must say so by agreeing with the Go-side constant rather than inventing a
// number that would pass a check it never made.
func TestWithNoLibraryTheReportedABIIsTheGoSideConstant(t *testing.T) {
	if got := LibraryABIVersion(); got != ABIVersion {
		t.Fatalf("LibraryABIVersion() = %d, want ABIVersion = %d", got, ABIVersion)
	}
}

// Health never returns nothing. A caller that reads an empty report cannot
// distinguish "every backend is fine" from "nobody looked", and this one runs
// at node start-up where that difference decides whether the chain runs.
func TestHealthAlwaysAnswersAndSaysWhyWhenItCannotRun(t *testing.T) {
	reports := Health()
	if len(reports) == 0 {
		t.Fatal("Health() returned no reports — even a build with no library must report status")
	}
	for _, r := range reports {
		if r.Name == "" {
			t.Errorf("health report for backend %d has no name", int(r.Backend))
		}
		if r.OK {
			continue
		}
		if r.Err == nil {
			t.Errorf("health report %q is not OK and does not say why", r.Name)
		}
	}
}

// -----------------------------------------------------------------------------
// The one struct that crosses the C ABI by memcpy
// -----------------------------------------------------------------------------

// BlockContext is copied to the C side field-for-field by address, so its Go
// layout IS the wire format. Every offset is pinned.
//
// The previous test here assigned each field and read it back, which is a
// property of Go's assignment rather than of the layout: reordering the struct
// left it passing. Offsets are what a reorder changes.
//
// A change to any number below means the C side's CBlockContext must move in
// lockstep AND ABIVersion must be bumped on both sides — the mismatch check at
// process start is the only thing that catches a skew, and it can only catch a
// skew that was declared.
func TestBlockContextIsTheWireLayout(t *testing.T) {
	var c BlockContext

	if got, want := unsafe.Sizeof(c), uintptr(392); got != want {
		t.Errorf("sizeof(BlockContext) = %d, want %d", got, want)
	}

	for _, f := range []struct {
		name string
		off  uintptr
		want uintptr
	}{
		{"Origin", unsafe.Offsetof(c.Origin), 0},
		{"GasPrice", unsafe.Offsetof(c.GasPrice), 24},
		{"Timestamp", unsafe.Offsetof(c.Timestamp), 32},
		{"Number", unsafe.Offsetof(c.Number), 40},
		{"Prevrandao", unsafe.Offsetof(c.Prevrandao), 48},
		{"GasLimit", unsafe.Offsetof(c.GasLimit), 80},
		{"ChainID", unsafe.Offsetof(c.ChainID), 88},
		{"BaseFee", unsafe.Offsetof(c.BaseFee), 96},
		{"BlobBaseFee", unsafe.Offsetof(c.BlobBaseFee), 104},
		{"Coinbase", unsafe.Offsetof(c.Coinbase), 112},
		{"BlobHashes", unsafe.Offsetof(c.BlobHashes), 132},
		{"NumBlobHashes", unsafe.Offsetof(c.NumBlobHashes), 388},
	} {
		if f.off != f.want {
			t.Errorf("offsetof(BlockContext.%s) = %d, want %d", f.name, f.off, f.want)
		}
	}
}
