// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !lux_cevm_native

package cevm

import (
	"errors"
	"strings"
	"testing"

	"github.com/luxfi/geth/core/types"
)

// Tests in this file run in every build that does not link the native
// library — the default build, and the only one that works on a host without
// the lux-cevm bundle — and pin what the package does there: refuse every
// block with transactions in it, and say which build tag fixes that.

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

// The name is the Backend's own String under this build — there is no library
// to ask — so the two cannot drift into two vocabularies for one lane.
func TestBackendNameAgreesWithTheStringer(t *testing.T) {
	for _, b := range []Backend{CPUSequential, CPUParallel, GPUMetal, GPUCUDA, Backend(99)} {
		if got, want := BackendName(b), b.String(); got != want {
			t.Errorf("BackendName(%d) = %q, Backend.String() = %q", int(b), got, want)
		}
	}
}

// The ABI the Go module reads and the ABI the loaded library reports are
// compared at process start, and against a mismatch nothing is executed: a
// silent skew produces wrong gas and wrong state roots, which is a consensus
// fault. With no library linked there is nothing to compare against, and
// LibraryABIVersion must say so by agreeing with the Go-side constant rather
// than inventing a number that would pass a check it never made.
func TestWithNoLibraryTheReportedABIIsTheGoSideConstant(t *testing.T) {
	if got := LibraryABIVersion(); got != ABIVersion {
		t.Fatalf("LibraryABIVersion() = %d, want ABIVersion = %d", got, ABIVersion)
	}
}

// With no library linked, the one health report says the library is what is
// missing. It used to blame CGo, which is enabled on the default build; an
// operator who followed that checked CGO_ENABLED and found it already 1.
func TestAHealthReportWithNoLibraryBlamesTheLibrary(t *testing.T) {
	reports := Health()
	if len(reports) != 1 {
		t.Fatalf("Health() gave %d reports, want the one lane this build has", len(reports))
	}
	if h := reports[0]; h.OK || !errors.Is(h.Err, ErrNotLinked) {
		t.Errorf("backend %q: ok=%v err=%v, want not ok with cevm.ErrNotLinked", h.Name, h.OK, h.Err)
	}
}
