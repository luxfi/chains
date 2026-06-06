// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// aivm_gpu_parity_test.go — locks in the one-and-only-one-way invariant
// that the cgo bridge and the nocgo bridge produce byte-identical
// output on every fixture. The test runs unconditionally (no build
// tag) so it executes in both modes; under cgo + no plugin, the
// bridge falls through to the same CPU helpers the nocgo bridge calls
// directly, so both paths terminate at aivm_gpu_cpu.go.
//
// Strategy: for each public bridge method, run the method via a
// zero-value *GPUBackend (the production "no plugin loaded" handle on
// both build modes), capture the mutated arena + result, and compare
// against the canonical Go reference invoked directly. They must be
// byte-equal — that is the GPU-bridge correctness contract.

package aivm

import (
	"bytes"
	"reflect"
	"testing"
)

// =============================================================================
// Fixture helpers — small, deterministic builders for non-trivial inputs.
// =============================================================================

func mkDigest32(b byte) [32]byte {
	var d [32]byte
	for i := range d {
		d[i] = b + byte(i)
	}
	return d
}

func mkKey48(b byte) [48]byte {
	var d [48]byte
	for i := range d {
		d[i] = b + byte(i)
	}
	return d
}

func mkSig96(b byte) [96]byte {
	var d [96]byte
	for i := range d {
		d[i] = b + byte(i)
	}
	return d
}

func mkAddr20(b byte) [20]byte {
	var d [20]byte
	for i := range d {
		d[i] = b + byte(i)
	}
	return d
}

// mkRoundDescriptor returns a non-trivial descriptor with op-counts wired
// for the chosen op type. The chain-id / round / timestamp / epoch fields
// matter for downstream leaf hashes; we use stable values so the test is
// deterministic.
func mkRoundDescriptor(attCount, modelCount, anchorCount uint32) *AIVMRoundDescriptor {
	return &AIVMRoundDescriptor{
		ChainID:            1337,
		Round:              42,
		TimestampNS:        1_700_000_000_000_000_000,
		Epoch:              7,
		Mode:               modeFullRound,
		AttestationOpCount: attCount,
		ModelOpCount:       modelCount,
		AnchorOpCount:      anchorCount,
		ClosingFlag:        1,
		ParentAIVMRoot:     mkDigest32(0xa0),
	}
}

func mkAttestationOps() []AttestationOp {
	return []AttestationOp{
		{
			TEEQuoteDigest: mkDigest32(0x10),
			Measurement:    mkDigest32(0x20),
			AttestingKey:   mkKey48(0x30),
			ExpiryNS:       2_000_000_000_000_000_000, // way in the future, not expired
			Kind:           0,                          // SGX
			EvidenceOffset: 0,
			EvidenceLen:    256,
		},
		{
			// Expired one — expiry_ns <= desc.TimestampNS
			TEEQuoteDigest: mkDigest32(0x11),
			Measurement:    mkDigest32(0x21),
			AttestingKey:   mkKey48(0x31),
			ExpiryNS:       1_500_000_000_000_000_000, // before desc.TimestampNS
			Kind:           1,                          // SEV
			EvidenceOffset: 256,
			EvidenceLen:    512,
		},
		{
			// Zero attesting key — must be rejected by both paths.
			TEEQuoteDigest: mkDigest32(0x12),
			Measurement:    mkDigest32(0x22),
			AttestingKey:   [48]byte{},
			ExpiryNS:       2_000_000_000_000_000_000,
		},
	}
}

func mkModelOps() []ModelOp {
	return []ModelOp{
		{
			ModelRoot:      mkDigest32(0x40),
			WeightHash:     mkDigest32(0x50),
			LicenseRoot:    mkDigest32(0x60),
			OwnerAddr:      mkAddr20(0x70),
			ParameterCount: 70_000_000_000,
			Modality:       0, // Text
			Kind:           modelOpRegister,
			Epoch:          7,
		},
		{
			// Same model_root — rotates weights.
			ModelRoot:      mkDigest32(0x40),
			WeightHash:     mkDigest32(0x51),
			LicenseRoot:    mkDigest32(0x60),
			OwnerAddr:      mkAddr20(0x70),
			ParameterCount: 0,
			Modality:       0,
			Kind:           modelOpUpdateWeights,
			Epoch:          7,
		},
		{
			// Zero model_root — must be rejected by both paths.
			ModelRoot:  [32]byte{},
			WeightHash: mkDigest32(0x52),
			Kind:       modelOpRegister,
		},
	}
}

// mkAnchorOps returns three anchor ops in canonical chain order
// (parent_root[i+1] == commit_root[i]).
func mkAnchorOps() []AnchorOp {
	r1 := mkDigest32(0x80)
	r2 := mkDigest32(0x81)
	r3 := mkDigest32(0x82)
	v := mkDigest32(0x90)
	return []AnchorOp{
		{
			CommitRoot:               r1,
			ParentRoot:               [32]byte{}, // first anchor — empty parent
			ValidatorSetRootAtCommit: v,
			Height:                   1,
			TimestampNS:              1_600_000_000_000_000_000,
		},
		{
			CommitRoot:               r2,
			ParentRoot:               r1,
			ValidatorSetRootAtCommit: v,
			Height:                   2,
			TimestampNS:              1_650_000_000_000_000_000,
		},
		{
			CommitRoot:               r3,
			ParentRoot:               r2,
			ValidatorSetRootAtCommit: v,
			Height:                   3,
			TimestampNS:              1_700_000_000_000_000_000,
		},
	}
}

// =============================================================================
// Inference fixture — non-trivial int8 weights + multiple ops.
// =============================================================================

func mkInferenceWeights() *InferenceWeights {
	var w InferenceWeights
	// Deterministic, non-zero weights. Spread in [-4, 4] so the int32
	// accumulator's saturation behaviour is exercised by some inputs.
	for i := range w.W1 {
		w.W1[i] = int8((i % 9) - 4)
	}
	for i := range w.B1 {
		w.B1[i] = int32(i*10 - 50)
	}
	for i := range w.W2 {
		w.W2[i] = int8((i % 7) - 3)
	}
	for i := range w.B2 {
		w.B2[i] = int32(i*5 - 10)
	}
	w.Shift1 = 4
	w.Shift2 = 3
	// Non-zero model hash so the kernel's hash-match path succeeds.
	w.ModelHash = mkDigest32(0xc0)
	w.ModelConfigHash = mkDigest32(0xd0)
	return &w
}

func mkInferenceOps(n int, modelHash [32]byte) []InferenceOp {
	ops := make([]InferenceOp, n)
	for i := range ops {
		ops[i] = InferenceOp{
			ModelHash:      modelHash,
			PolicyHash:     mkDigest32(0xe0),
			Salt:           mkDigest32(byte(0xf0 + i)),
			Mode:           uint32(i % 3), // 0 deterministic, 1 confidential, 2 verifiable
			InputOffset:    uint32(i * InferenceInDim),
			InputLen:       InferenceInDim,
			OutputOffset:   uint32(i * InferenceOutDim),
			OutputCapacity: 4,
			RoundID:        uint64(i + 1),
			TimestampNS:    1_700_000_000_000_000_000 + uint64(i),
		}
	}
	return ops
}

func mkInferenceInputs(n int) []int8 {
	in := make([]int8, n*InferenceInDim)
	for i := range in {
		// Spread inputs in [-32, 31] so the int8 GEMM produces values
		// across the [-128, 127] saturation range.
		in[i] = int8((i % 64) - 32)
	}
	return in
}

// =============================================================================
// Proof-verify fixture — covers Ok / SigCheck / Expired / KeyZero /
// MeasureCheck branches.
// =============================================================================

func mkProofVerifyOps() []ProofVerifyOp {
	return []ProofVerifyOp{
		{
			Measurement:  mkDigest32(0x40),
			AttestingKey: mkKey48(0x50),
			Signature:    mkSig96(0x60),
			MessageHash:  mkDigest32(0x70),
			ExpiryNS:     2_000_000_000_000_000_000,
			TimestampNS:  1_700_000_000_000_000_000,
			Kind:         0,
			Nonce:        7,
		},
		{
			// Expired
			Measurement:  mkDigest32(0x41),
			AttestingKey: mkKey48(0x51),
			Signature:    mkSig96(0x61),
			MessageHash:  mkDigest32(0x71),
			ExpiryNS:     1_500_000_000_000_000_000,
			TimestampNS:  1_700_000_000_000_000_000,
			Kind:         1,
			Nonce:        8,
		},
		{
			// SigCheck — all-zero signature
			Measurement:  mkDigest32(0x42),
			AttestingKey: mkKey48(0x52),
			Signature:    [96]byte{},
			MessageHash:  mkDigest32(0x72),
			ExpiryNS:     2_000_000_000_000_000_000,
			TimestampNS:  1_700_000_000_000_000_000,
			Kind:         2,
			Nonce:        9,
		},
		{
			// KeyZero — all-zero attesting key
			Measurement:  mkDigest32(0x43),
			AttestingKey: [48]byte{},
			Signature:    mkSig96(0x63),
			MessageHash:  mkDigest32(0x73),
			ExpiryNS:     2_000_000_000_000_000_000,
			TimestampNS:  1_700_000_000_000_000_000,
			Kind:         3,
			Nonce:        10,
		},
		{
			// MeasureCheck — all-zero measurement
			Measurement:  [32]byte{},
			AttestingKey: mkKey48(0x54),
			Signature:    mkSig96(0x64),
			MessageHash:  mkDigest32(0x74),
			ExpiryNS:     2_000_000_000_000_000_000,
			TimestampNS:  1_700_000_000_000_000_000,
			Kind:         0,
			Nonce:        11,
		},
	}
}

// =============================================================================
// TestGPUBridgeCgoNocgoParity — the one-and-only-one-way invariant.
//
// This test asserts that every public bridge method on *GPUBackend
// (used under both build modes) produces output byte-equal to the
// canonical Go reference invoked directly. Since the cgo bridge falls
// through to the same Go reference on plugin error / absent plugin,
// the two paths terminate at the same bytes; this test makes that
// invariant a runtime contract.
//
// `&GPUBackend{}` is the zero-value handle production code carries
// when no plugin loaded. On cgo it triggers the fall-through; on
// nocgo it's the only available handle. Either way, the bridge method
// is the API surface external callers use — that is the surface this
// test pins.
// =============================================================================

func TestGPUBridgeCgoNocgoParity(t *testing.T) {
	t.Run("AttestationApply", testParityAttestationApply)
	t.Run("ProvenanceApply", testParityProvenanceApply)
	t.Run("AnchorApply", testParityAnchorApply)
	t.Run("EpochTransition", testParityEpochTransition)
	t.Run("InferenceStep", testParityInferenceStep)
	t.Run("ProofVerify", testParityProofVerify)
}

func testParityAttestationApply(t *testing.T) {
	const tableSize = 16
	ops := mkAttestationOps()
	desc := mkRoundDescriptor(uint32(len(ops)), 0, 0)

	// Reference path — call attestationApplyCPU directly on a fresh
	// table; this is the canonical answer.
	refTab := make([]Attestation, tableSize)
	var refApplied uint32
	attestationApplyCPU(desc, ops, refTab, &refApplied)

	// Bridge path — call the public method on a zero-value handle.
	gotTab := make([]Attestation, tableSize)
	var gotApplied uint32
	if err := (&GPUBackend{}).AttestationApply(desc, ops, gotTab, &gotApplied); err != nil {
		t.Fatalf("GPUBackend.AttestationApply: unexpected error: %v", err)
	}

	if refApplied != gotApplied {
		t.Errorf("applied count: bridge=%d ref=%d", gotApplied, refApplied)
	}
	if !reflect.DeepEqual(refTab, gotTab) {
		t.Errorf("attestation table differs between bridge and reference")
	}
	// Sanity: at least 1 op (the SGX one) MUST be applied, and at least
	// 1 op (the zero-key one) MUST be rejected.
	if gotApplied == 0 {
		t.Errorf("expected at least one op applied, got %d", gotApplied)
	}
	if gotApplied == uint32(len(ops)) {
		t.Errorf("expected at least one op rejected (zero-key entry), got applied=%d for ops=%d",
			gotApplied, len(ops))
	}
}

func testParityProvenanceApply(t *testing.T) {
	const tableSize = 16
	ops := mkModelOps()
	desc := mkRoundDescriptor(0, uint32(len(ops)), 0)

	refTab := make([]ModelRegistryEntry, tableSize)
	var refApplied uint32
	provenanceApplyCPU(desc, ops, refTab, &refApplied)

	gotTab := make([]ModelRegistryEntry, tableSize)
	var gotApplied uint32
	if err := (&GPUBackend{}).ProvenanceApply(desc, ops, gotTab, &gotApplied); err != nil {
		t.Fatalf("GPUBackend.ProvenanceApply: unexpected error: %v", err)
	}

	if refApplied != gotApplied {
		t.Errorf("applied count: bridge=%d ref=%d", gotApplied, refApplied)
	}
	if !reflect.DeepEqual(refTab, gotTab) {
		t.Errorf("model table differs between bridge and reference")
	}
	if gotApplied != 2 {
		t.Errorf("expected exactly 2 ops applied (Register + UpdateWeights), got %d", gotApplied)
	}
}

func testParityAnchorApply(t *testing.T) {
	const tableSize = 16
	ops := mkAnchorOps()
	desc := mkRoundDescriptor(0, 0, uint32(len(ops)))

	refTab := make([]AuditAnchor, tableSize)
	var refApplied uint32
	anchorApplyCPU(desc, ops, refTab, &refApplied)

	gotTab := make([]AuditAnchor, tableSize)
	var gotApplied uint32
	if err := (&GPUBackend{}).AnchorApply(desc, ops, gotTab, &gotApplied); err != nil {
		t.Fatalf("GPUBackend.AnchorApply: unexpected error: %v", err)
	}

	if refApplied != gotApplied {
		t.Errorf("applied count: bridge=%d ref=%d", gotApplied, refApplied)
	}
	if !reflect.DeepEqual(refTab, gotTab) {
		t.Errorf("anchor table differs between bridge and reference")
	}
	if gotApplied != 3 {
		t.Errorf("expected exactly 3 chained anchors applied, got %d", gotApplied)
	}
}

func testParityEpochTransition(t *testing.T) {
	const (
		attSize    = 16
		modelSize  = 8
		anchorSize = 8
	)
	desc := mkRoundDescriptor(0, 0, 0) // FullRound, ClosingFlag=1
	desc.Mode = modeEpoch

	// Pre-populate the arenas via the per-op kernels so we have a
	// non-trivial state to fold. Same procedure on both paths.
	attOps := mkAttestationOps()
	modelOps := mkModelOps()
	anchorOps := mkAnchorOps()
	popDesc := mkRoundDescriptor(uint32(len(attOps)), uint32(len(modelOps)), uint32(len(anchorOps)))

	mkArenas := func() (
		atts []Attestation,
		models []ModelRegistryEntry,
		anchors []AuditAnchor,
	) {
		atts = make([]Attestation, attSize)
		models = make([]ModelRegistryEntry, modelSize)
		anchors = make([]AuditAnchor, anchorSize)
		var dummy uint32
		attestationApplyCPU(popDesc, attOps, atts, &dummy)
		provenanceApplyCPU(popDesc, modelOps, models, &dummy)
		anchorApplyCPU(popDesc, anchorOps, anchors, &dummy)
		return
	}

	// Reference run.
	refAtts, refModels, refAnchors := mkArenas()
	var refEpoch AIVMEpochState
	var refResult AIVMTransitionResult
	epochTransitionCPU(desc, refAtts, refModels, refAnchors, &refEpoch, &refResult)

	// Bridge run on a fresh (independently-populated) set of arenas.
	gotAtts, gotModels, gotAnchors := mkArenas()
	var gotEpoch AIVMEpochState
	var gotResult AIVMTransitionResult
	if err := (&GPUBackend{}).EpochTransition(desc, gotAtts, gotModels, gotAnchors, &gotEpoch, &gotResult); err != nil {
		t.Fatalf("GPUBackend.EpochTransition: unexpected error: %v", err)
	}

	if !reflect.DeepEqual(refAtts, gotAtts) {
		t.Errorf("attestation table differs after EpochTransition")
	}
	if !reflect.DeepEqual(refModels, gotModels) {
		t.Errorf("model table differs after EpochTransition")
	}
	if !reflect.DeepEqual(refAnchors, gotAnchors) {
		t.Errorf("anchor table differs after EpochTransition")
	}
	if !reflect.DeepEqual(refEpoch, gotEpoch) {
		t.Errorf("epoch state differs after EpochTransition")
	}
	if !reflect.DeepEqual(refResult, gotResult) {
		t.Errorf("result differs after EpochTransition")
	}
	// Sanity: all four roots MUST be non-zero on a non-trivial fixture.
	if bytes.Equal(gotResult.AttestationRoot[:], make([]byte, 32)) {
		t.Errorf("attestation root is zero on non-trivial fixture")
	}
	if bytes.Equal(gotResult.ModelRegistryRoot[:], make([]byte, 32)) {
		t.Errorf("model registry root is zero on non-trivial fixture")
	}
	if bytes.Equal(gotResult.AuditRoot[:], make([]byte, 32)) {
		t.Errorf("audit root is zero on non-trivial fixture")
	}
	if bytes.Equal(gotResult.AIVMStateRoot[:], make([]byte, 32)) {
		t.Errorf("aivm state root is zero on non-trivial fixture")
	}
}

func testParityInferenceStep(t *testing.T) {
	const n = 4
	weights := mkInferenceWeights()
	ops := mkInferenceOps(n, weights.ModelHash)
	in := mkInferenceInputs(n)

	// Reference run.
	refOut := make([]int8, n*InferenceOutDim)
	refRes := make([]InferenceResult, n)
	inferenceStepCPU(weights, ops, in, refOut, refRes)

	// Bridge run.
	gotOut := make([]int8, n*InferenceOutDim)
	gotRes := make([]InferenceResult, n)
	if err := (&GPUBackend{}).InferenceStep(weights, ops, in, gotOut, gotRes); err != nil {
		t.Fatalf("GPUBackend.InferenceStep: unexpected error: %v", err)
	}

	if !bytes.Equal(byteSlice(refOut), byteSlice(gotOut)) {
		t.Errorf("inference output differs: ref=% x got=% x", refOut, gotOut)
	}
	if !reflect.DeepEqual(refRes, gotRes) {
		t.Errorf("inference results differ between bridge and reference")
	}
	// Sanity: every result must be Status=0 (success).
	for i, r := range gotRes {
		if r.Status != 0 {
			t.Errorf("InferenceStep result[%d].Status = %d, want 0", i, r.Status)
		}
	}
}

func testParityProofVerify(t *testing.T) {
	ops := mkProofVerifyOps()

	refRes := make([]ProofVerifyResult, len(ops))
	proofVerifyCPU(ops, refRes)

	gotRes := make([]ProofVerifyResult, len(ops))
	if err := (&GPUBackend{}).ProofVerify(ops, gotRes); err != nil {
		t.Fatalf("GPUBackend.ProofVerify: unexpected error: %v", err)
	}

	if !reflect.DeepEqual(refRes, gotRes) {
		t.Errorf("proof verify results differ between bridge and reference")
	}
	// Sanity: the five fixtures cover the five expected status outcomes.
	wantStatus := []uint32{
		proofStatusOk,
		proofStatusExpired,
		proofStatusSigCheck,
		proofStatusKeyZero,
		proofStatusMeasureCheck,
	}
	for i, w := range wantStatus {
		if gotRes[i].Status != w {
			t.Errorf("ProofVerify result[%d].Status = 0x%x, want 0x%x",
				i, gotRes[i].Status, w)
		}
	}
	// Binding hash on every result must be non-zero — the kernel emits
	// it unconditionally regardless of fail bits.
	for i, r := range gotRes {
		if bytes.Equal(r.BindingHash[:], make([]byte, 32)) {
			t.Errorf("ProofVerify result[%d].BindingHash is zero", i)
		}
	}
}

// byteSlice reinterprets an int8 slice as a byte slice (no copy). Used
// for bytes.Equal comparisons on int8 inference outputs. Safe: int8
// and byte share the same size + alignment.
func byteSlice(s []int8) []byte {
	if len(s) == 0 {
		return nil
	}
	b := make([]byte, len(s))
	for i, v := range s {
		b[i] = byte(v)
	}
	return b
}
