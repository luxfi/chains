// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cevm

import (
	"testing"
	"unsafe"
)

// Tests in this file run under every build, the native one included. They
// cover the parts of the API that answer the same with or without the C++
// library: the enum stringers, the wire layout the C ABI reads by memcpy, an
// empty block, and what a build says about its own lanes. What the package
// does when the library is NOT linked is in cevm_nolib_test.go.

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
// An empty block
// -----------------------------------------------------------------------------

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
// lockstep AND ABIVersion must be bumped on both sides — the ABI checks (the
// header's number at build time, the library's at start) are the only thing
// that catches a skew, and they can only catch a skew that was declared.
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
