// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// aivm_gpu_cpu.go — pure-Go reference implementation of the six AIVM
// transition kernels. ONE implementation, called unconditionally by
// both build modes:
//
//   - aivm_gpu_nocgo.go (!cgo) calls these helpers directly: no plugin
//     can ever load on a nocgo build, so the Go path IS the path.
//
//   - aivm_gpu.go (cgo) tries the GPU plugin first; on ErrGPUNotAvailable
//     (no plugin loaded), `LUX_BACKEND_ERROR_NOT_SUPPORTED`, or any
//     plugin-side rc != 0 it falls through to the same Go helper.
//     Both build modes therefore produce byte-identical output on every
//     fixture — GPU is a strict positive overlay, the CPU answer is
//     canonical.
//
// Byte-equality reference:
//
//   ~/work/luxcpp/aivm/src/aivm_cpu_reference.cpp — the canonical CPU
//   oracle for the 4 transition kernels (attestation / provenance /
//   anchor / epoch). Every GPU backend's kernel is byte-equal to this
//   recipe; so is this Go translation.
//
//   ~/work/luxcpp/aivm/src/ai_precompile.cpp — canonical CPU oracle
//   for the 2 inference kernels (inference_step / proof_verify).
//   Same byte-equality contract.
//
// Determinism contract: fixed iteration order, sign-aware int32
// arithmetic, no floating point, no parallel reductions. Keccak-256
// is the Ethereum legacy variant (Keccak-f[1600] with 0x01 / 0x80
// padding) — sourced via `luxfi/crypto.Keccak256`, which is the same
// hasher every other Lux chain uses.

package aivm

import (
	"encoding/binary"

	"github.com/luxfi/crypto"
)

// =============================================================================
// keccak256 helpers. luxfi/crypto.Keccak256 is the Ethereum legacy variant
// (Keccak-f[1600] + 0x01 / 0x80 padding), byte-identical to the GPU
// kernel's keccak256 and to ~/work/luxcpp/aivm/src/aivm_cpu_reference.cpp.
// =============================================================================

// keccak256 returns the 32-byte keccak-256 digest of buf. Tiny wrapper
// over luxfi/crypto.Keccak256 — kept so call sites read like the C++
// oracle: `keccak256(buf, out)` instead of `copy(out[:], Keccak256(buf))`.
func keccak256(buf []byte, out *[32]byte) {
	digest := crypto.Keccak256(buf)
	copy(out[:], digest)
}

// le32 writes `v` into `dst[off:off+4]` little-endian. Matches the
// `absorb_u32` helper in the C++ oracle and the on-device kernels.
func le32(dst []byte, off int, v uint32) {
	binary.LittleEndian.PutUint32(dst[off:off+4], v)
}

// le64 writes `v` into `dst[off:off+8]` little-endian. Matches the
// `absorb_u64` helper in the C++ oracle and the on-device kernels.
func le64(dst []byte, off int, v uint64) {
	binary.LittleEndian.PutUint64(dst[off:off+8], v)
}

// digestZero reports whether a 32-byte digest is all zeros. Used as a
// CPU-side stand-in for the kernel's "no quote" predicate.
func digestZero(d [32]byte) bool {
	for _, b := range d {
		if b != 0 {
			return false
		}
	}
	return true
}

// key48Zero reports whether a 48-byte attesting-key blob is all zeros.
// Matches the kernel predicate `key48_zero`.
func key48Zero(k [48]byte) bool {
	for _, b := range k {
		if b != 0 {
			return false
		}
	}
	return true
}

// digest32SliceZero reports whether a 32-byte digest slice is all
// zeros. Used by the proof-verify CPU helper for op.Measurement (which
// is a fixed-size [32]byte but the loop is simpler over a slice).
func digest32SliceZero(d []byte) bool {
	for _, b := range d {
		if b != 0 {
			return false
		}
	}
	return true
}

// digest96Zero reports whether a 96-byte signature blob is all zeros.
func digest96Zero(sig [96]byte) bool {
	for _, b := range sig {
		if b != 0 {
			return false
		}
	}
	return true
}

// =============================================================================
// Open-addressing hash table helpers — byte-equal to the kernel's
// `hash_index` and `*_locate` functions. The kernel iterates power-of-two
// table sizes with FNV-style hashing on the first 8 bytes of the key, so
// the Go translation MUST use the same recipe.
// =============================================================================

// keyFromDigest reads the first 8 bytes of `d` little-endian as a uint64.
// Matches the kernel helper of the same name.
func keyFromDigest(d [32]byte) uint64 {
	return binary.LittleEndian.Uint64(d[:8])
}

// hashIndex returns FNV-1a of `k` masked by `mask` (which must be
// `count - 1` for a power-of-two `count`). Matches the kernel's
// `hash_index`.
func hashIndex(k uint64, mask uint32) uint32 {
	h := uint64(0xcbf29ce484222325)
	h = (h ^ k) * 0x100000001b3
	return uint32(h) & mask
}

// attestationLocate finds (or inserts, when `insertIfMissing`) the slot
// for `digest` in `tab`. Returns the slot index or 0xFFFFFFFF if the
// table is full. Byte-equal to the kernel's `attestation_locate`.
//
// `tab` is modified in place when the slot is empty and `insertIfMissing`
// is true — the kernel zeroes the slot, writes the digest, and sets
// Occupied=1 before returning the index, so the Go path does the same.
func attestationLocate(tab []Attestation, digest [32]byte, insertIfMissing bool) uint32 {
	if len(tab) == 0 {
		return 0xFFFFFFFF
	}
	mask := uint32(len(tab)) - 1
	key := keyFromDigest(digest)
	idx := hashIndex(key, mask)
	for probe := 0; probe < len(tab); probe++ {
		s := &tab[idx]
		if s.Occupied == 0 {
			if insertIfMissing {
				*s = Attestation{TEEQuoteDigest: digest, Occupied: 1}
				return idx
			}
			return 0xFFFFFFFF
		}
		if s.TEEQuoteDigest == digest {
			return idx
		}
		idx = (idx + 1) & mask
	}
	return 0xFFFFFFFF
}

// modelLocate is the model-registry analogue of attestationLocate.
// Returns the slot index for `modelRoot` or 0xFFFFFFFF if not found
// (and not inserted, when the table is full). Byte-equal to the
// kernel's `model_locate`.
func modelLocate(tab []ModelRegistryEntry, modelRoot [32]byte, insertIfMissing bool) uint32 {
	if len(tab) == 0 {
		return 0xFFFFFFFF
	}
	mask := uint32(len(tab)) - 1
	key := keyFromDigest(modelRoot)
	idx := hashIndex(key, mask)
	for probe := 0; probe < len(tab); probe++ {
		s := &tab[idx]
		if s.Occupied == 0 {
			if insertIfMissing {
				*s = ModelRegistryEntry{ModelRoot: modelRoot, Occupied: 1}
				return idx
			}
			return 0xFFFFFFFF
		}
		if s.ModelRoot == modelRoot {
			return idx
		}
		idx = (idx + 1) & mask
	}
	return 0xFFFFFFFF
}

// =============================================================================
// Kernel 1: AttestationApply (CPU reference)
//
// For each op:
//   - reject if attesting_key is zero (CPU verifier stand-in)
//   - reject if tee_quote_digest is zero
//   - insert/update the attestation entry; mark Verified
//   - mark Expired immediately if expiry_ns != 0 and expiry_ns <= desc.timestamp_ns
//
// Byte-equal to ~/work/luxcpp/aivm/src/aivm_cpu_reference.cpp::apply_attestation_ops
// and to ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_attestation.cu.
// =============================================================================

// attestationApplyCPU runs the attestation kernel on the Go CPU path.
// `attestations` is the registry table (open-addressed, power-of-two
// length); it is mutated in place. `appliedOut` receives the count of
// successfully applied ops. Matches the kernel's contract: ops past
// desc.AttestationOpCount are ignored, missing-slot is silent.
func attestationApplyCPU(
	desc *AIVMRoundDescriptor,
	ops []AttestationOp,
	attestations []Attestation,
	appliedOut *uint32,
) {
	if appliedOut != nil {
		*appliedOut = 0
	}
	if desc == nil || len(attestations) == 0 || appliedOut == nil {
		return
	}
	count := int(desc.AttestationOpCount)
	if count > len(ops) {
		count = len(ops)
	}
	var applied uint32
	for i := 0; i < count; i++ {
		op := ops[i]
		if key48Zero(op.AttestingKey) {
			continue
		}
		if digestZero(op.TEEQuoteDigest) {
			continue
		}
		idx := attestationLocate(attestations, op.TEEQuoteDigest, true)
		if idx == 0xFFFFFFFF {
			continue
		}
		s := &attestations[idx]
		s.Measurement = op.Measurement
		s.AttestingKey = op.AttestingKey
		s.ExpiryNS = op.ExpiryNS
		s.Kind = op.Kind
		s.EvidenceOffset = op.EvidenceOffset
		s.EvidenceLen = op.EvidenceLen
		s.Status = attStatusVerified
		if op.ExpiryNS != 0 && op.ExpiryNS <= desc.TimestampNS {
			s.Status |= attStatusExpired
		}
		applied++
	}
	*appliedOut = applied
}

// =============================================================================
// Kernel 2: ProvenanceApply (CPU reference)
//
// Per ModelOp.Kind:
//   Register      — insert new entry, version = 1
//   UpdateWeights — bump version (saturating), refresh weight_hash and
//                   optional parameter_count
//   UpdateLicense — refresh license_root
//   Transfer      — refresh owner_addr
//
// Byte-equal to ~/work/luxcpp/aivm/src/aivm_cpu_reference.cpp::apply_model_ops
// and to ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_provenance.cu.
// =============================================================================

// provenanceApplyCPU runs the provenance kernel on the Go CPU path.
// `models` is the model-registry table (open-addressed); mutated in
// place. `appliedOut` receives the count of successfully applied ops.
func provenanceApplyCPU(
	desc *AIVMRoundDescriptor,
	ops []ModelOp,
	models []ModelRegistryEntry,
	appliedOut *uint32,
) {
	if appliedOut != nil {
		*appliedOut = 0
	}
	if desc == nil || len(models) == 0 || appliedOut == nil {
		return
	}
	count := int(desc.ModelOpCount)
	if count > len(ops) {
		count = len(ops)
	}
	var applied uint32
	for i := 0; i < count; i++ {
		op := ops[i]
		if digestZero(op.ModelRoot) {
			continue
		}
		if digestZero(op.WeightHash) {
			continue
		}
		switch op.Kind {
		case modelOpRegister:
			idx := modelLocate(models, op.ModelRoot, true)
			if idx == 0xFFFFFFFF {
				continue
			}
			s := &models[idx]
			s.WeightHash = op.WeightHash
			s.LicenseRoot = op.LicenseRoot
			s.OwnerAddr = op.OwnerAddr
			s.ParameterCount = op.ParameterCount
			s.Modality = op.Modality
			s.Version = 1
			applied++
		case modelOpUpdateWeights:
			idx := modelLocate(models, op.ModelRoot, false)
			if idx == 0xFFFFFFFF {
				continue
			}
			s := &models[idx]
			s.WeightHash = op.WeightHash
			// Saturating increment — matches the kernel exactly.
			if s.Version != ^uint64(0) {
				s.Version++
			}
			if op.ParameterCount != 0 {
				s.ParameterCount = op.ParameterCount
			}
			applied++
		case modelOpUpdateLicense:
			idx := modelLocate(models, op.ModelRoot, false)
			if idx == 0xFFFFFFFF {
				continue
			}
			models[idx].LicenseRoot = op.LicenseRoot
			applied++
		case modelOpTransfer:
			idx := modelLocate(models, op.ModelRoot, false)
			if idx == 0xFFFFFFFF {
				continue
			}
			models[idx].OwnerAddr = op.OwnerAddr
			applied++
		}
	}
	*appliedOut = applied
}

// =============================================================================
// Kernel 3: AnchorApply (CPU reference)
//
// Append-only ring buffer. A new anchor is accepted iff:
//   - commit_root is non-zero, AND
//   - if there is a previous occupied slot, parent_root must equal the
//     previous slot's commit_root (chain integrity), AND
//   - height > previous height (monotonic).
//
// The "cursor" is the index of the first free slot, found by scanning
// the table from index 0 in canonical order.
//
// Byte-equal to ~/work/luxcpp/aivm/src/aivm_cpu_reference.cpp::apply_anchor_ops
// and to ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_anchor.cu.
// =============================================================================

// anchorApplyCPU runs the anchor kernel on the Go CPU path.
func anchorApplyCPU(
	desc *AIVMRoundDescriptor,
	ops []AnchorOp,
	anchors []AuditAnchor,
	appliedOut *uint32,
) {
	if appliedOut != nil {
		*appliedOut = 0
	}
	if desc == nil || len(anchors) == 0 || appliedOut == nil {
		return
	}
	// Find first-free slot.
	cursor := 0
	for cursor < len(anchors) && anchors[cursor].Occupied != 0 {
		cursor++
	}
	count := int(desc.AnchorOpCount)
	if count > len(ops) {
		count = len(ops)
	}
	var applied uint32
	for i := 0; i < count; i++ {
		op := ops[i]
		if digestZero(op.CommitRoot) {
			continue
		}
		if cursor >= len(anchors) {
			break
		}
		if cursor > 0 {
			prev := &anchors[cursor-1]
			if op.ParentRoot != prev.CommitRoot {
				continue
			}
			if op.Height <= prev.Height {
				continue
			}
		}
		dst := &anchors[cursor]
		dst.CommitRoot = op.CommitRoot
		dst.ParentRoot = op.ParentRoot
		dst.ValidatorSetRootAtCommit = op.ValidatorSetRootAtCommit
		dst.Height = op.Height
		dst.TimestampNS = op.TimestampNS
		dst.Occupied = 1
		cursor++
		applied++
	}
	*appliedOut = applied
}

// =============================================================================
// Kernel 4: EpochTransition (CPU reference)
//
// Closes the epoch: marks expired attestations, computes
// (attestation_root, model_registry_root, audit_root), composes
// aivm_state_root, and (when desc.ClosingFlag != 0) bumps current_epoch.
//
// Byte-equal to ~/work/luxcpp/aivm/src/aivm_cpu_reference.cpp::close_epoch
// and to ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_transition.cu.
//
// Leaf-hash recipes (keccak inputs in declaration order):
//
//   attestation leaf =
//       tee_quote_digest || measurement || attesting_key || expiry_ns
//       || kind || evidence_offset || evidence_len || status
//       || expired_flag || index
//
//   model leaf =
//       model_root || weight_hash || license_root || owner_addr
//       || version || parameter_count || modality || index
//
//   audit leaf =
//       commit_root || parent_root || validator_set_root_at_commit
//       || height || timestamp_ns || index
//
//   aivm_state_root =
//       parent_aivm_root || attestation_root || model_registry_root
//       || audit_root || current_epoch || active || model_count
//       || anchor_count
//
// The fold is `acc = keccak(acc || leaf_hash)` over occupied slots in
// canonical index order, with `acc` initialised to zero.
// =============================================================================

// computeAttestationRoot computes the attestation root and side counts
// (active vs expired). The kernel and the C++ oracle iterate `i` over
// the table in slot order, skip unoccupied slots, and fold the keccak
// of each leaf into a single accumulator.
func computeAttestationRoot(atts []Attestation, timestampNS uint64) (root [32]byte, active, expired uint32) {
	var acc [32]byte
	buf := make([]byte, 32+32+48+8+4+4+4+4+4+4)
	for i, a := range atts {
		if a.Occupied == 0 {
			continue
		}
		exp := (a.ExpiryNS != 0 && a.ExpiryNS <= timestampNS) ||
			(a.Status&attStatusExpired) != 0
		ver := (a.Status & attStatusVerified) != 0
		if exp {
			expired++
		} else if ver {
			active++
		}

		o := 0
		copy(buf[o:o+32], a.TEEQuoteDigest[:])
		o += 32
		copy(buf[o:o+32], a.Measurement[:])
		o += 32
		copy(buf[o:o+48], a.AttestingKey[:])
		o += 48
		le64(buf, o, a.ExpiryNS)
		o += 8
		le32(buf, o, a.Kind)
		o += 4
		le32(buf, o, a.EvidenceOffset)
		o += 4
		le32(buf, o, a.EvidenceLen)
		o += 4
		le32(buf, o, a.Status)
		o += 4
		if exp {
			le32(buf, o, 1)
		} else {
			le32(buf, o, 0)
		}
		o += 4
		le32(buf, o, uint32(i))
		o += 4

		var leafHash [32]byte
		keccak256(buf[:o], &leafHash)
		var foldBuf [64]byte
		copy(foldBuf[:32], acc[:])
		copy(foldBuf[32:], leafHash[:])
		keccak256(foldBuf[:], &acc)
	}
	root = acc
	return
}

// computeModelRegistryRoot computes the model-registry root and the count
// of occupied slots.
func computeModelRegistryRoot(models []ModelRegistryEntry) (root [32]byte, count uint32) {
	var acc [32]byte
	buf := make([]byte, 32+32+32+20+8+8+4+4)
	for i, m := range models {
		if m.Occupied == 0 {
			continue
		}
		count++
		o := 0
		copy(buf[o:o+32], m.ModelRoot[:])
		o += 32
		copy(buf[o:o+32], m.WeightHash[:])
		o += 32
		copy(buf[o:o+32], m.LicenseRoot[:])
		o += 32
		copy(buf[o:o+20], m.OwnerAddr[:])
		o += 20
		le64(buf, o, m.Version)
		o += 8
		le64(buf, o, m.ParameterCount)
		o += 8
		le32(buf, o, m.Modality)
		o += 4
		le32(buf, o, uint32(i))
		o += 4

		var leafHash [32]byte
		keccak256(buf[:o], &leafHash)
		var foldBuf [64]byte
		copy(foldBuf[:32], acc[:])
		copy(foldBuf[32:], leafHash[:])
		keccak256(foldBuf[:], &acc)
	}
	root = acc
	return
}

// computeAuditRoot computes the audit (anchor) root and the count of
// occupied slots.
func computeAuditRoot(anchors []AuditAnchor) (root [32]byte, count uint32) {
	var acc [32]byte
	buf := make([]byte, 32+32+32+8+8+4)
	for i, a := range anchors {
		if a.Occupied == 0 {
			continue
		}
		count++
		o := 0
		copy(buf[o:o+32], a.CommitRoot[:])
		o += 32
		copy(buf[o:o+32], a.ParentRoot[:])
		o += 32
		copy(buf[o:o+32], a.ValidatorSetRootAtCommit[:])
		o += 32
		le64(buf, o, a.Height)
		o += 8
		le64(buf, o, a.TimestampNS)
		o += 8
		le32(buf, o, uint32(i))
		o += 4

		var leafHash [32]byte
		keccak256(buf[:o], &leafHash)
		var foldBuf [64]byte
		copy(foldBuf[:32], acc[:])
		copy(foldBuf[32:], leafHash[:])
		keccak256(foldBuf[:], &acc)
	}
	root = acc
	return
}

// epochTransitionCPU runs the epoch-finalisation kernel on the Go CPU
// path. Marks expired attestations (parallel-mark phase in the kernel,
// sequential here since the Go translation is single-threaded), then
// folds the three sub-roots and composes aivm_state_root. Closes the
// epoch by bumping current_epoch when desc.ClosingFlag != 0.
//
// Byte-equal to ~/work/luxcpp/aivm/src/aivm_cpu_reference.cpp::close_epoch
// and to the GPU kernel at ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_transition.cu.
func epochTransitionCPU(
	desc *AIVMRoundDescriptor,
	attestations []Attestation,
	models []ModelRegistryEntry,
	anchors []AuditAnchor,
	epoch *AIVMEpochState,
	result *AIVMTransitionResult,
) {
	if desc == nil || epoch == nil || result == nil {
		return
	}
	// Phase 1: mark expired attestations against round timestamp so the
	// root reflects the post-epoch state. Slot-local mutation only.
	for i := range attestations {
		if attestations[i].Occupied == 0 {
			continue
		}
		if attestations[i].ExpiryNS != 0 && attestations[i].ExpiryNS <= desc.TimestampNS {
			attestations[i].Status |= attStatusExpired
		}
	}

	attRoot, active, expired := computeAttestationRoot(attestations, desc.TimestampNS)
	modelRoot, mcount := computeModelRegistryRoot(models)
	auditRoot, acount := computeAuditRoot(anchors)

	epoch.AttestationRoot = attRoot
	epoch.ModelRegistryRoot = modelRoot
	epoch.AuditRoot = auditRoot
	epoch.ActiveModelCount = mcount
	epoch.ExpiredAttestationCount = expired
	epoch.TotalActiveAttestations = uint64(active)
	if desc.ClosingFlag != 0 {
		epoch.CurrentEpoch = desc.Epoch + 1
	}

	// Compose aivm_state_root.
	composed := make([]byte, 32+32+32+32+8+4+4+4)
	o := 0
	copy(composed[o:o+32], desc.ParentAIVMRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.AttestationRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.ModelRegistryRoot[:])
	o += 32
	copy(composed[o:o+32], epoch.AuditRoot[:])
	o += 32
	le64(composed, o, epoch.CurrentEpoch)
	o += 8
	le32(composed, o, active)
	o += 4
	le32(composed, o, mcount)
	o += 4
	le32(composed, o, acount)
	o += 4

	keccak256(composed[:o], &epoch.AIVMStateRoot)

	result.AttestationRoot = epoch.AttestationRoot
	result.ModelRegistryRoot = epoch.ModelRegistryRoot
	result.AuditRoot = epoch.AuditRoot
	result.AIVMStateRoot = epoch.AIVMStateRoot
	result.ActiveAttestations = active
	result.ExpiredAttestations = expired
	result.ModelCount = mcount
	result.AnchorCount = acount
	result.TotalModels = uint64(mcount)
	result.TotalAnchors = uint64(acount)
	result.Epoch = epoch.CurrentEpoch
	result.Status = 1
}

// =============================================================================
// Kernel 5: InferenceStep (CPU reference)
//
// Deterministic int8 32→16→1 forward pass plus keccak commitments over
// (salt || input) and (salt || output). Mode 1 and Mode 2 also fold an
// attestation root over (model_hash || in_c || out_c || policy || ts).
//
// Byte-equal to ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_inference.cu
// and the CPU reference at ~/work/luxcpp/aivm/src/ai_precompile.cpp.
//
// Fixed reduction order, sign-aware int32 arithmetic right-shift,
// [-128, 127] saturation. No floating point, no parallel reductions —
// deterministic by construction.
// =============================================================================

// satInt8 clamps `v` to [-128, 127] and returns it as int8. Matches the
// `sat_i8` helper in the kernel.
func satInt8(v int32) int8 {
	if v > 127 {
		return 127
	}
	if v < -128 {
		return -128
	}
	return int8(v)
}

// inferenceForward runs the int8 32→16→1 forward pass. Byte-equal to
// the kernel's `inference_int8_forward`.
func inferenceForward(w *InferenceWeights, x *[InferenceInDim]int8, y *[InferenceOutDim]int8) {
	var hidden [InferenceHidden]int8
	for i := 0; i < InferenceHidden; i++ {
		acc := w.B1[i]
		for k := 0; k < InferenceInDim; k++ {
			wv := int32(w.W1[i*InferenceInDim+k])
			xv := int32(x[k])
			acc += wv * xv
		}
		acc >>= uint(w.Shift1)
		hidden[i] = satInt8(acc)
	}
	for i := 0; i < InferenceOutDim; i++ {
		acc := w.B2[i]
		for k := 0; k < InferenceHidden; k++ {
			wv := int32(w.W2[i*InferenceHidden+k])
			hv := int32(hidden[k])
			acc += wv * hv
		}
		acc >>= uint(w.Shift2)
		y[i] = satInt8(acc)
	}
}

// inferenceStepCPU runs the inference kernel on the Go CPU path.
// `batchInputs` holds op_count × InferenceInDim bytes of input rows;
// `batchOutputs` receives op_count × InferenceOutDim output bytes.
//
// Status codes (mirror the kernel):
//   0 — success
//   1 — model_hash mismatch (op.ModelHash != weights.ModelHash)
//   2 — input_len != InferenceInDim
//   3 — output_capacity < InferenceOutDim
func inferenceStepCPU(
	weights *InferenceWeights,
	ops []InferenceOp,
	batchInputs []int8,
	batchOutputs []int8,
	results []InferenceResult,
) {
	if weights == nil {
		return
	}
	for tid, op := range ops {
		res := &results[tid]
		*res = InferenceResult{}

		if weights.ModelHash != op.ModelHash {
			res.Status = 1
			continue
		}
		if op.InputLen != uint32(InferenceInDim) {
			res.Status = 2
			continue
		}
		if op.OutputCapacity < uint32(InferenceOutDim) {
			res.Status = 3
			continue
		}

		var x [InferenceInDim]int8
		for k := 0; k < InferenceInDim; k++ {
			x[k] = batchInputs[int(op.InputOffset)+k]
		}
		var y [InferenceOutDim]int8
		inferenceForward(weights, &x, &y)
		for k := 0; k < InferenceOutDim; k++ {
			batchOutputs[int(op.OutputOffset)+k] = y[k]
		}
		res.OutputLen = uint32(InferenceOutDim)

		// input_commitment = keccak(salt || input)
		{
			buf := make([]byte, 32+InferenceInDim)
			copy(buf[:32], op.Salt[:])
			for k := 0; k < InferenceInDim; k++ {
				buf[32+k] = byte(x[k])
			}
			keccak256(buf, &res.InputCommitment)
		}
		// output_commitment = keccak(salt || output)
		{
			buf := make([]byte, 32+InferenceOutDim)
			copy(buf[:32], op.Salt[:])
			for k := 0; k < InferenceOutDim; k++ {
				buf[32+k] = byte(y[k])
			}
			keccak256(buf, &res.OutputCommitment)
		}
		// Mode 0 — deterministic, no attestation root.
		// Mode 1/2 — fold attestation root over
		//   model_hash || in_c || out_c || policy_hash || timestamp_ns.
		if op.Mode != 0 {
			buf := make([]byte, 32+32+32+32+8)
			o := 0
			copy(buf[o:o+32], op.ModelHash[:])
			o += 32
			copy(buf[o:o+32], res.InputCommitment[:])
			o += 32
			copy(buf[o:o+32], res.OutputCommitment[:])
			o += 32
			copy(buf[o:o+32], op.PolicyHash[:])
			o += 32
			le64(buf, o, op.TimestampNS)
			o += 8
			keccak256(buf[:o], &res.AttestationRoot)
		}
		res.Status = 0
	}
}

// =============================================================================
// Kernel 6: ProofVerify (CPU reference)
//
// TEE-attestation envelope check. Validates measurement / attesting_key /
// signature / expiry and emits a binding hash over
//   keccak(measurement || attesting_key || signature || message_hash || nonce).
//
// Status bits (mirror kProofStatus*):
//   0x01 — Ok (set when no fail bit is set)
//   0x02 — SigCheck      (signature all-zero)
//   0x04 — MeasureCheck  (measurement all-zero)
//   0x08 — Expired       (expiry_ns != 0 && expiry_ns <= timestamp_ns)
//   0x10 — KeyZero       (attesting_key all-zero)
//
// Byte-equal to ~/work/lux-private/gpu-kernels/ops/aivm/cuda/aivm_proof_verify.cu.
// =============================================================================

// proofVerifyCPU runs the proof-verify kernel on the Go CPU path.
func proofVerifyCPU(ops []ProofVerifyOp, results []ProofVerifyResult) {
	for tid, op := range ops {
		res := &results[tid]
		*res = ProofVerifyResult{}

		var status uint32
		if digest32SliceZero(op.Measurement[:]) {
			status |= proofStatusMeasureCheck
		}
		if key48Zero(op.AttestingKey) {
			status |= proofStatusKeyZero
		}
		if op.ExpiryNS != 0 && op.ExpiryNS <= op.TimestampNS {
			status |= proofStatusExpired
		}
		if digest96Zero(op.Signature) {
			status |= proofStatusSigCheck
		}

		// Binding hash is computed unconditionally — the kernel emits
		// it on every call regardless of fail bits.
		buf := make([]byte, 32+48+96+32+4)
		o := 0
		copy(buf[o:o+32], op.Measurement[:])
		o += 32
		copy(buf[o:o+48], op.AttestingKey[:])
		o += 48
		copy(buf[o:o+96], op.Signature[:])
		o += 96
		copy(buf[o:o+32], op.MessageHash[:])
		o += 32
		le32(buf, o, op.Nonce)
		o += 4
		keccak256(buf[:o], &res.BindingHash)

		const failMask = proofStatusMeasureCheck |
			proofStatusKeyZero |
			proofStatusExpired |
			proofStatusSigCheck
		if status&failMask == 0 {
			status |= proofStatusOk
		}
		res.Status = status
		res.Kind = op.Kind
	}
}
