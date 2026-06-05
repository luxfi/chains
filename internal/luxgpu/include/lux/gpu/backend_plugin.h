// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Backend Plugin ABI - Stable C interface for runtime-loaded GPU backends
//
// Each backend shared library exports one symbol: lux_gpu_backend_init
// The core library dlopen()s backends and calls this to get the vtable.
//
// One vtbl, one cross-backend contract. Each plugin is self-contained — there
// is no parallel crypto vtbl, no extension struct. Crypto types live in
// <lux/gpu/crypto.h>. The curve enum lives in <lux/gpu.h> as LuxCurve.

#ifndef LUX_GPU_BACKEND_PLUGIN_H
#define LUX_GPU_BACKEND_PLUGIN_H

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "lux/gpu/crypto.h"

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// ABI Version - bump on breaking changes
// =============================================================================

// ABI v5: FHE ops take explicit base_log; k=0 and degenerate gadgets are
// rejected with INVALID_ARGUMENT. CUDA/WGSL bootstrap+blind_rotate now run the
// canonical CPU PBS body via cpu_fhe_helpers.hpp (no more rotation-only fakes).
//
// ABI v6: adds op_bn254_pairing + op_modexp. Slots may be NULL — the public
// lux_bn254_pairing / lux_modexp helpers in gpu_core.cpp fall back to the
// canonical CPU pairing / modexp implementation when the backend hasn't
// specialized the slot. Out-of-tree plugins must rebuild against this header.
//
// ABI v7: adds the EIP-2537 BLS12-381 surface (7 ops matching EVM precompile
// addresses 0x0b..0x11), the EIP-4844 KZG verifier (op_kzg_verify_eip4844),
// and the CLOB DEX matcher (op_dex_match_clob). The first 8 wrap the
// canonical CPU c-abi in luxcpp/crypto/{bls,kzg}; op_dex_match_clob has no
// CPU c-abi today and returns NOT_SUPPORTED — the cevm wrapper falls back
// to dex_match_cpu. Out-of-tree plugins must rebuild against this header.
//
// ABI v8: adds the FIPS 202 SHA3-256 (op_sha3_256_hash) and SHAKE256 XOF
// (op_shake256_hash) primitives, distinct from the Ethereum keccak256
// already at op_keccak256_hash (different padding domain separator —
// 0x06/0x1F vs 0x01). Needed for PQ-safe Merkle (MERKLE_SHA3) walks and
// the p3q transcript path in lux-private/multichain-cpp. Slots may be
// NULL — public lux_gpu_sha3_256_batch / lux_gpu_shake256_batch surface
// returns LUX_ERROR_NOT_SUPPORTED if the backend hasn't wired them.
//
// ABI v9: adds NIST SP 800-185 cSHAKE256 (op_cshake256_hash). Customisable
// SHAKE256 with per-batch (function_name N, customisation S). All entries
// in a batch share the same (N, S) — the loader assembles the bytepad-
// aligned prefix once, then the backend absorbs it before each entry's
// input. Padding domain separator is 0x04 (NOT 0x1F); when both N and S
// are empty the call degenerates to SHAKE256 per the spec. Used by p3q
// Fiat-Shamir transcript hashing and the kmac/parallelhash variants on
// top. Public surface: gpu_cshake256_batch (brand-neutral). Slot may be
// NULL — returns LUX_ERROR_NOT_SUPPORTED. Out-of-tree plugins must
// rebuild against this header.
//
// ABI v10: adds the ML "steel" surface — fused GEMM, FlashAttention
// forward, and tiled 2-D convolution. The three slots wrap the existing
// host launchers under ops/steel/{gemm,attention,conv}/cuda/ which were
// already compiled into libluxgpu_backend_cuda.so but had no public
// dispatch path.
//   * op_gemm  : C = alpha * A @ B + beta * C   (row-major FP32)
//   * op_attention : O = softmax(Q K^T / sqrt(D)) V using FlashAttention
//                    (online softmax, FP32, optional causal mask)
//   * op_conv  : tiled 2-D conv (NCHW, FP32, stride/pad/dilation,
//                optional bias)
// Each takes raw host pointers — the backend stages H2D/D2H exactly like
// op_ntt_forward / op_modexp. Slots may be NULL — public surface returns
// LUX_ERROR_NOT_SUPPORTED. Public surface: gpu_gemm / gpu_attention /
// gpu_conv2d (brand-neutral, no lux_ prefix). Out-of-tree plugins must
// rebuild against this header.
//
// ABI v11: adds the 25 C-Chain EVM math/bitwise/shift/cmp opcodes plus
// op_cevm_conflict_detect (Block-STM read-write set conflict pair
// extraction). Every slot takes the canonical CEVM word layout —
// 4 × uint64_t LE limbs in host byte order, matching holiman/uint256.Int
// (which the Lux Go EVM uses directly: ~/work/lux/geth/core/vm/
// instructions.go). Inputs and outputs are host pointers — backend
// stages H2D/D2H exactly like op_modexp / op_tfhe_*.
//   * Binary  (a, b) → out:  add, sub, mul, div, sdiv, mod, smod, exp,
//                            signextend, and, or, xor, byte, shl, shr,
//                            sar, lt, gt, slt, sgt, eq
//   * Unary   (a)    → out:  not, iszero
//   * Ternary (a,b,c)→ out:  addmod, mulmod
//   * Block-STM:             conflict_detect
// Slot is NULL → public lux_gpu_cevm_<op>_batch falls back to the
// canonical CPU oracle in ops/cevm/common/cevm_cpu.hpp (byte-equal to
// holiman/uint256.Int — every legal call produces the same answer
// regardless of LUX_GPU_BACKEND; GPU is a strict positive overlay).
// NOT_SUPPORTED from a non-null slot also falls back to CPU — this is
// how a backend signals "this batch shape exceeds my pipeline" (e.g.
// out-of-memory under contention) without compromising consensus.
// INVALID_ARGUMENT remains a real "input violates contract" signal and
// propagates to the caller. v11 plugins are backward-compatible with
// v10 hosts (host ignores unknown trailing slots — the loader compares
// vtbl_size before reading any slot). v10 plugins remain forward-
// compatible with v11 hosts (host sees the new slots as NULL and falls
// back to CPU oracle — already the current behavior). Out-of-tree
// plugins must rebuild against this header to advertise the cevm slots.
//
// ABI v12: adds the four FIPS 205 SLH-DSA "magnetar" hash-tree
// primitives shipped as GPU kernels at lux-private/gpu-kernels commit
// 0d94c0b (see ops/crypto/slhdsa/{cuda,hip,metal,wgsl}/ and
// backends/vulkan/ops/crypto/slhdsa/). These are the GPU-accelerable
// substrate operations of an SLH-DSA-SHAKE signature scheme — not the
// full verify (that's op_slhdsa_verify_batch in ABI v6) but the four
// hash-tree shapes that dominate signing/verifying cost:
//   * op_magnetar_wotsplus_chain_batch — FIPS 205 §5 Algorithm 5
//       "chain". WOTS+ hash-chain over s steps with mutable address
//       word per step. One element per WOTS+ chain index.
//   * op_magnetar_fors_subtree_batch — FIPS 205 §8.2 Algorithm 15
//       "fors_node". FORS subtree root over 2^height secret-derived
//       leaves via F (leaf) + H (internal) reductions.
//   * op_magnetar_xmss_subtree_batch — FIPS 205 §6.1 Algorithm 9
//       "xmss_node". XMSS subtree root over 2^height precomputed
//       WOTS+ public-key leaves via H reductions.
//   * op_magnetar_hmsg_prfmsg_batch — FIPS 205 §11.2 H_msg + PRF_msg
//       SHAKE primitives. One SHAKE256 absorb-and-squeeze per element
//       over variable-length message input; two distinct sub-batches
//       (h_elems[h_batch] and p_elems[p_batch]) dispatched in one call
//       to amortize launch overhead.
//
// Wire format (each vtbl slot — host pointer interface, mirrors
// op_modexp / op_tfhe_* / op_cevm_* host-staging convention):
//   * elems_data points at a packed C-layout array of N elements; each
//     element struct is declared in <lux/gpu/crypto.h> as
//     LuxMagnetarWotsChainElem / LuxMagnetarForsSubtreeElem /
//     LuxMagnetarXmssSubtreeElem / LuxMagnetarHmsgElem /
//     LuxMagnetarPrfmsgElem. Each elem stores byte offsets into its
//     corresponding pool plus parameters (n, height, s, addr[32], etc.).
//   * pk_seed_pool / x_pool / sk_leaves_pool / wots_pk_pool / msg_pool /
//     r_pool / pk_root_pool / sk_prf_pool / opt_rand_pool are flat byte
//     buffers concatenating per-element payloads. The offsets in the
//     elem struct index into these pools.
//   * out_pool is a contiguous batch_size × 32-byte buffer (32 bytes
//     per element — bytes beyond n are zero, allowing predictable
//     consumer reads). For hmsg the out stride is 64 bytes (m ≤ 47);
//     for prfmsg the out stride is 32 bytes.
//
// Byte-equal to the magnetar Go reference at
// ~/work/lux/magnetar/ref/go/pkg/magnetar/slhdsa_internal.go (KAT vectors
// cross-checked PASS 2026-06-03). Slot may be NULL — public
// lux_gpu_magnetar_*_batch falls back to the CPU oracle at
// ops/crypto/slhdsa/tests/slhdsa_cpu_oracle.hpp (the canonical SHAKE-
// mode F / H / SHAKE256 sponge byte-equal to PQClean fips202.c). v12
// plugins are backward-compatible with v11 hosts (host ignores unknown
// trailing slots — the loader compares vtbl_size before reading). v11
// plugins remain forward-compatible with v12 hosts (host sees the new
// slots as NULL and falls back to CPU oracle — strict positive
// overlay, never a correctness compromise). Out-of-tree plugins must
// rebuild against this header to advertise the magnetar slots.
//
// ABI v13: per-element msg_len for SLH-DSA verify. The v12 slot
// `op_slhdsa_verify_batch` (SHAKE-128f) and its sibling extern-C
// symbol for SHAKE-192f hardcoded msg_len = 32 inside the wrapper —
// safe ONLY when the caller pre-hashes its message to a 32-byte
// digest, which is NOT the ACVP / FIPS 205 contract. FIPS 205
// Algorithm 24 (slh_verify) takes the raw message of arbitrary
// length (ACVP vectors range 1 B to 8 KiB). Any real caller that
// hands the wrapper a non-32-byte message hits UB on the H_msg
// digest computation — wrong digest, wrong verdict, silently.
//
// v13 fixes this by retrofitting the verify slot signature with a
// `const size_t* msg_lens` parameter and adding a SHAKE-192f-typed
// sibling slot:
//   * op_slhdsa_verify_batch          — SHAKE-128f (pk 32, sig 17088)
//   * op_slhdsa_verify_batch_shake192f — SHAKE-192f (pk 48, sig 35664)
// Each takes per-element message length so the wrapper can build
// the device elem array with the true byte count, not 32.
//
// Length contract: msg_lens[i] is the byte length of messages[i],
// matching the slh_verify_internal CPU reference signature. The
// kernel preamble rejects on pk_len/sig_len mismatch (canonical
// values per variant); message length is consumed verbatim by the
// streaming SHAKE-256 sponge so any value is legal (0 included).
//
// Breaking change: v12 callers that relied on the hardcoded msg_len
// = 32 must update to pass an explicit msg_lens array. There is no
// silent fallback — if a v12 caller links against a v13 plugin, the
// loader's vtbl_size + abi_version cookies trip the mismatch and
// reject the plugin. This is the design intent ("forwards perfection,
// no backwards compat layers").
//
// ABI v14: ML-DSA full GPU plumbing — three coordinated changes.
//
//   1. `op_mldsa_verify_batch` gains the per-element `msg_lens` +
//      `msg_width_hint` parameters that v13 added to the SLH-DSA verify
//      slots. The v13 wrapper at lux-private/gpu-kernels backends/cuda/
//      src/plugin.cpp::cuda_op_mldsa_verify_batch hardcoded msg_len =
//      kMldsaMsgBytesAbi (= 64) inside an mp_pool builder; every caller
//      that handed a non-64-byte message (the ACVP 12-byte SHAKE256
//      stream, the FIPS 204 raw-M streaming hash, lux-accel's
//      try_gpu_verify_mldsa65 8-byte digest) silently UB'd on the H_msg
//      digest computation. v14 plumbs the true per-element length
//      through to the orchestrator pool builder — exactly the SLH-DSA
//      v13 fix shape, applied to ML-DSA.
//
//      `msg_lens` is NULL-tolerant: when the caller has uniform message
//      width and passes msg_lens=NULL, the wrapper uses
//      msg_width_hint for every element. This keeps the call site for
//      uniform-batch callers (lux-accel's mldsa_batch.cpp, which feeds
//      every ML-DSA tensor with shape [n, msg_width]) one allocation
//      cheaper.
//
//   2. `op_mldsa_sign_batch` — new vtbl slot. Wraps the FIPS 204
//      Algorithm 7 batched signer in
//      lux-private/gpu-kernels/ops/crypto/mldsa/cuda/
//      mldsa_sign_orchestrator.cu (extern "C"
//      lux_cuda_mldsa_sign_batch_gpu). Per-element message length via
//      the same msg_lens/msg_width_hint contract as verify. ML-DSA-65
//      (mode 3) only at v14 — the orchestrator hard-codes K=6, L=5,
//      η=4, γ1=2^19, γ2=(q-1)/32 to match Dilithium3.
//
//   3. `op_lattice_ntt_mldsa_batch` — new vtbl slot. Wraps the
//      stateless ML-DSA forward/inverse NTT batched kernel at
//      lux-private/gpu-kernels/ops/crypto/mldsa/cuda/mldsa_ntt.cu
//      (extern "C" lux_cuda_mldsa_poly_ntt_batch /
//      lux_cuda_mldsa_poly_invntt_batch). The slot folds fwd+inv into
//      one entry point via a `direction` parameter (0 = forward, 1 =
//      inverse). Operates over Z_q[X]/(X^256+1) with q = 8380417 (the
//      ML-DSA prime); each polynomial is exactly 256 int32 coefficients
//      contiguous in memory.
//
//      This is intentionally a separate slot from the existing FHE-aimed
//      `op_ntt_forward` / `op_ntt_inverse` (which are uint64 + runtime
//      modulus + N up to 32768). Decomplecting the two surfaces: FHE
//      callers stay on the existing slots; ML-DSA callers (FIPS 204
//      verify orchestrator, P3Q kernels, Pulsar Round-2) get this
//      dedicated int32 / N=256 / q=8380417 surface that matches PQClean
//      byte-for-byte. One value, one slot.
//
// Length-safety preamble: every elem with `msg_len > INT32_MAX` is
// rejected at entry (preamble inherited from the Magnetar / SLH-DSA
// v13 pattern). `msg_len == 0` is a legal edge case (empty message —
// SHAKE256 absorb-zero is a defined operation); the orchestrator
// handles it without a special branch.
//
// Constant-time: per-element msg_lens MUST NOT introduce data-dependent
// branches inside the GPU warps. The CUDA orchestrator at
// mldsa_verify_orchestrator.cu / mldsa_sign_orchestrator.cu absorbs the
// per-elem message via the streaming SHAKE-256 sponge; sponge state
// transitions are length-uniform per FIPS 202. The host-side pool
// builder is the only place where length appears outside the sponge,
// and it copies the length-prefix verbatim into the pool with no
// branches on element identity.
//
// Backwards / forwards: v14 plugins reject any v13 loader and vice
// versa via the abi_version + vtbl_size cookies — strict version lock.
// Out-of-tree plugins must rebuild against this header. No compat
// shims, no extension structs.
#define LUX_GPU_BACKEND_ABI_VERSION 14

// Red C-3 invariant: this static_assert is a WITHIN-HEADER consistency
// check. It pins the literal "14" in lockstep with
// LUX_GPU_BACKEND_ABI_VERSION above so a half-applied ABI bump (where a
// contributor edits the version number on one line but forgets a sibling
// assertion) fails to compile.
//
// What this is NOT: a stale-header detector. A stale system-installed
// header (e.g. /usr/local v5 or /opt/homebrew v8) has the version
// number "5"/"8" on both lines and compiles cleanly. The defense
// against stale headers is the RUNTIME cookie check in
// src/plugin_loader.hpp::validate_backend_desc — it reads
// abi_version + vtbl_size off the loaded plugin descriptor and refuses
// to dispatch when they don't match the host's expected ABI version.
// So the runtime check is what stops UB on a stale-header link, not
// this assertion.
//
// Update this literal on EVERY ABI bump (v15, v16, …) in step with
// LUX_GPU_BACKEND_ABI_VERSION above. Drift between the two = the
// invariant is dead, fix it.
#if defined(__cplusplus)
static_assert(LUX_GPU_BACKEND_ABI_VERSION == 14,
    "lux-gpu header is from a different ABI version than the runtime "
    "expects. Re-install lux-gpu headers (cd luxcpp && cmake --install "
    "build). If you see this against a v15+ header, your consumer code "
    "needs to update its v14 assertion site.");
#elif defined(__STDC_VERSION__) && __STDC_VERSION__ >= 201112L
_Static_assert(LUX_GPU_BACKEND_ABI_VERSION == 14,
    "lux-gpu header is from a different ABI version than the runtime "
    "expects. Re-install lux-gpu headers.");
#endif

// =============================================================================
// FIPS 204 ML-DSA message length cap — one source of truth.
// =============================================================================
//
// Red H-1 normalization (LP-fixes, v0.30.11): every ABI v14 plugin that
// implements op_mldsa_verify_batch / op_mldsa_sign_batch rejects
// individual message lengths exceeding this cap with
// LUX_BACKEND_ERROR_INVALID_ARGUMENT.
//
// Value = INT32_MAX - 2 (= 0x7FFFFFFD). The "-2" reserves headroom for
// a +2-byte prefix (0x00 || ctxlen) that a future caller may reintroduce
// on an int32 path; without the headroom, mlen + 2 would overflow to a
// negative int and any caller that performed an `int` cast (mlen) would
// loop on a negative bound — zero-bytes absorbed — producing an
// empty-message-signature universal forge (Red C-1 shape).
//
// Today the absorb path in shake256_inc.cuh + shake128_inc.cuh + the
// orchestrator is size_t end-to-end and this cap is defense in depth.
// If a future contributor reintroduces an int cast on mlen, the cap
// stops the truncation from ever reaching the absorb loop.
//
// EVERY plugin (cpu_backend / luxcpp-metal / lux-private cuda /
// lux-private metal) MUST use this macro. If any plugin diverges, a
// host with two backends present (e.g. Apple Silicon w/ both
// luxcpp/metal AND lux-private/metal compiled in) could accept on one
// backend and reject on the other for the same input → consensus split.
#define LUX_GPU_MLDSA_MSG_LEN_CAP ((size_t)0x7FFFFFFD)

// =============================================================================
// FIPS 205 SLH-DSA message length cap — one source of truth.
// =============================================================================
//
// Red CRITICAL #176 (v14 retrofit): every ABI v14 plugin that
// implements op_slhdsa_verify_batch / op_slhdsa_verify_batch_shake192f
// rejects individual message lengths exceeding this cap with
// LUX_BACKEND_ERROR_INVALID_ARGUMENT.
//
// Value = INT32_MAX - 2 (= 0x7FFFFFFD) — matches LUX_GPU_MLDSA_MSG_LEN_CAP.
// The "-2" reserves headroom for a +2-byte prefix that a future caller
// may reintroduce on an int32 path; without the headroom, mlen + 2 would
// overflow to a negative int and any caller that performed an `int` cast
// (mlen) would loop on a negative bound — zero-bytes absorbed — producing
// the same empty-message-signature universal forge as the ML-DSA C-1
// shape.
//
// Today the SLH-DSA orchestrators stage msg_lens[i] via `(uint32_t)`
// casts to fit the device elem struct's u32 msg_len field. A caller that
// passes msg_lens[i] = 0x100000003 (4 GiB + 3) would see the u32 cast
// truncate to 3 on the GPU path while the CPU oracle absorbs the full
// 4 GiB — direct consensus split per Red #176. This cap rejects such
// inputs at the plugin entry, BEFORE the truncating cast can occur.
//
// EVERY plugin that supports SLH-DSA (cpu_backend / lux-private cuda /
// lux-private metal / lux-private hip / lux-private webgpu) MUST use
// this macro. WebGPU returns NOT_SUPPORTED today; no cap needed there
// until a real WGSL kernel lands.
#define LUX_GPU_SLHDSA_MSG_LEN_CAP ((size_t)0x7FFFFFFD)

// =============================================================================
// Forward declarations (opaque handles)
// =============================================================================

typedef struct LuxBackendContext LuxBackendContext;
typedef struct LuxBackendBuffer  LuxBackendBuffer;

// =============================================================================
// Error codes
// =============================================================================

typedef enum {
    LUX_BACKEND_OK                    = 0,
    LUX_BACKEND_ERROR_INVALID_ARGUMENT = 1,
    LUX_BACKEND_ERROR_OUT_OF_MEMORY    = 2,
    LUX_BACKEND_ERROR_NOT_SUPPORTED    = 3,
    LUX_BACKEND_ERROR_DEVICE_LOST      = 4,
    LUX_BACKEND_ERROR_INTERNAL         = 5,
} LuxBackendError;

typedef struct {
    const char* name;
    const char* vendor;
    uint64_t memory_total;
    uint64_t memory_available;
    int compute_units;
    int max_workgroup_size;
    bool is_discrete;
    bool is_unified_memory;
} LuxBackendDeviceInfo;

// =============================================================================
// Backend vtbl — the single cross-backend contract.
//
// Layout: lifecycle -> device info -> sync -> buffers -> tensor ops ->
// FHE/NTT -> crypto. No designated initializers required; missing trailing
// fields are nullptr by virtue of static zero-init in the plugin.
// =============================================================================

typedef struct lux_gpu_backend_vtbl {
    // -------- Lifecycle --------
    LuxBackendContext* (*create_context)(int device_index);
    void               (*destroy_context)(LuxBackendContext* ctx);

    // -------- Device info & sync --------
    LuxBackendError (*get_device_count)(int* count);
    LuxBackendError (*get_device_info)(LuxBackendContext* ctx, LuxBackendDeviceInfo* info);
    LuxBackendError (*sync)(LuxBackendContext* ctx);

    // -------- Buffer management --------
    LuxBackendBuffer* (*buffer_alloc)(LuxBackendContext* ctx, size_t bytes);
    LuxBackendBuffer* (*buffer_alloc_with_data)(LuxBackendContext* ctx, const void* data, size_t bytes);
    void              (*buffer_free)(LuxBackendContext* ctx, LuxBackendBuffer* buf);
    LuxBackendError   (*buffer_copy_to_host)(LuxBackendContext* ctx, LuxBackendBuffer* buf, void* dst, size_t bytes);
    LuxBackendError   (*buffer_copy_from_host)(LuxBackendContext* ctx, LuxBackendBuffer* buf, const void* src, size_t bytes);
    void*             (*buffer_get_host_ptr)(LuxBackendContext* ctx, LuxBackendBuffer* buf);

    // -------- Tensor ops (f32) --------
    LuxBackendError (*op_add_f32)(LuxBackendContext* ctx, LuxBackendBuffer* a, LuxBackendBuffer* b, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_sub_f32)(LuxBackendContext* ctx, LuxBackendBuffer* a, LuxBackendBuffer* b, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_mul_f32)(LuxBackendContext* ctx, LuxBackendBuffer* a, LuxBackendBuffer* b, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_div_f32)(LuxBackendContext* ctx, LuxBackendBuffer* a, LuxBackendBuffer* b, LuxBackendBuffer* out, size_t n);

    LuxBackendError (*op_matmul_f32)(LuxBackendContext* ctx, LuxBackendBuffer* a, LuxBackendBuffer* b, LuxBackendBuffer* out, int M, int K, int N);
    LuxBackendError (*op_transpose_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, int rows, int cols);

    LuxBackendError (*op_reduce_sum_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_reduce_max_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_reduce_min_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_reduce_mean_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_reduce_sum_axis_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t outer_size, size_t inner_size);
    LuxBackendError (*op_reduce_max_axis_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t outer_size, size_t inner_size);

    LuxBackendError (*op_softmax_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t batch_size, size_t dim);
    LuxBackendError (*op_log_softmax_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t batch_size, size_t dim);

    LuxBackendError (*op_exp_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_log_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_sqrt_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_neg_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_abs_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_tanh_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_sigmoid_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_relu_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);
    LuxBackendError (*op_gelu_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, size_t n);

    LuxBackendError (*op_copy_f32)(LuxBackendContext* ctx, LuxBackendBuffer* src, LuxBackendBuffer* dst, size_t n);

    LuxBackendError (*op_layer_norm_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, LuxBackendBuffer* gamma, LuxBackendBuffer* beta, size_t batch_size, size_t dim, float eps);
    LuxBackendError (*op_rms_norm_f32)(LuxBackendContext* ctx, LuxBackendBuffer* in, LuxBackendBuffer* out, LuxBackendBuffer* weight, size_t batch_size, size_t dim, float eps);

    // -------- NTT (host-pointer interface; backend manages staging) --------
    LuxBackendError (*op_ntt_forward)(LuxBackendContext* ctx, uint64_t* data, size_t n, uint64_t modulus);
    LuxBackendError (*op_ntt_inverse)(LuxBackendContext* ctx, uint64_t* data, size_t n, uint64_t modulus);

    // -------- FHE (host-pointer interface; backend manages staging) --------
    LuxBackendError (*op_poly_mul)(
        LuxBackendContext* ctx,
        const uint64_t* a, const uint64_t* b, uint64_t* result,
        size_t n, uint64_t modulus
    );

    // TFHE-AP programmable bootstrap. BSK layout per input LWE coordinate:
    //   [n_lwe][(k+1)*l][k+1][N] uint64_t  (TRGSW row-major).
    // Gadget contract: B = 2^base_log; the caller MUST choose (l, base_log)
    // so that l × base_log ≤ log2(q). Otherwise q / B^l collapses to zero on
    // the bottom row and that gadget level encrypts only noise. Backends
    // reject l × base_log > 64 with INVALID_ARGUMENT.
    // k = 0 is rejected: lwe_out length is documented as k*N + 1 = 1 yet the
    // sample-extract writes N entries — silent OOB. INVALID_ARGUMENT instead.
    LuxBackendError (*op_tfhe_bootstrap)(
        LuxBackendContext* ctx,
        const uint64_t* lwe_in, uint64_t* lwe_out,
        const uint64_t* bsk, const uint64_t* test_poly,
        uint32_t n_lwe, uint32_t N, uint32_t k, uint32_t l,
        uint32_t base_log, uint64_t q
    );

    // TFHE keyswitch. KSK rows encode an LWE encryption (under the OUT key)
    // of  +s_{in_idx} · q / B^{level+1}  where B = 2^base_log and
    // s_{in_idx} is the IN secret-key coordinate (OpenFHE convention).
    // Accumulating  −digit · KSK[in_idx][level]  over the signed-base-B
    // decomposition of lwe_in[in_idx] yields the keyswitched ciphertext
    // under the OUT key. Callers MUST follow this convention; the
    // canonical CPU impl at lux::fhe::run_tfhe_keyswitch
    // (cpu_fhe_helpers.hpp:629) and the parity-test KSK construction at
    // test/test_backend_parity.cpp:3651-3675 both use this sign.
    //
    // Equivalence note: the negated convention (KSK encodes −s·gadget,
    // accumulate +digit·KSK) is mathematically the same up to
    // simultaneous sign-flips of every row body and every accumulation
    // step. Prior versions of this comment described that negated
    // convention; callers building against ABI v6 must regenerate KSK
    // using the +s encoding to stay parity-equal with the canonical CPU
    // body.
    LuxBackendError (*op_tfhe_keyswitch)(
        LuxBackendContext* ctx,
        const uint64_t* lwe_in, uint64_t* lwe_out,
        const uint64_t* ksk,
        uint32_t n_in, uint32_t n_out, uint32_t l, uint32_t base_log, uint64_t q
    );

    // AP-style blind rotation. Same gadget contract as op_tfhe_bootstrap.
    LuxBackendError (*op_blind_rotate)(
        LuxBackendContext* ctx,
        uint64_t* acc, const uint64_t* bsk, const uint64_t* lwe_a,
        uint32_t n_lwe, uint32_t N, uint32_t k, uint32_t l,
        uint32_t base_log, uint64_t q
    );

    // -------- Crypto: hashes --------
    LuxBackendError (*op_poseidon2_hash)(
        LuxBackendContext* ctx,
        const uint64_t* inputs, uint64_t* outputs,
        size_t rate, size_t num_hashes
    );

    LuxBackendError (*op_blake3_hash)(
        LuxBackendContext* ctx,
        const uint8_t* inputs, uint8_t* outputs,
        const size_t* input_lens, size_t num_hashes
    );

    LuxBackendError (*op_keccak256_hash)(
        LuxBackendContext* ctx,
        const uint8_t* inputs, uint8_t* outputs,
        const size_t* input_lens, size_t num_inputs
    );

    // -------- Crypto: BLS12-381 (G1 or G2 selected by is_g2) --------
    LuxBackendError (*op_bls12_381_add)(
        LuxBackendContext* ctx,
        const void* a, const void* b, void* out, size_t n, bool is_g2
    );
    LuxBackendError (*op_bls12_381_mul)(
        LuxBackendContext* ctx,
        const void* points, const void* scalars, void* out, size_t n, bool is_g2
    );
    LuxBackendError (*op_bls12_381_pairing)(
        LuxBackendContext* ctx,
        const void* g1_points, const void* g2_points, void* out, size_t n
    );

    // -------- Crypto: BN254 (G1 or G2 selected by is_g2) --------
    LuxBackendError (*op_bn254_add)(
        LuxBackendContext* ctx,
        const void* a, const void* b, void* out, size_t n, bool is_g2
    );
    LuxBackendError (*op_bn254_mul)(
        LuxBackendContext* ctx,
        const void* points, const void* scalars, void* out, size_t n, bool is_g2
    );
    // BN254 multi-pairing (EIP-197). pairs: n × 192 B; out_result: 32 B
    // (big-endian uint256 of 0 or 1, EVM precompile convention).
    // May be NULL — public API falls back to canonical CPU pairing.
    LuxBackendError (*op_bn254_pairing)(
        LuxBackendContext* ctx,
        const void* pairs, uint8_t out_result[32], size_t n
    );

    // -------- Crypto: Big-integer modexp (EVM 0x05) --------
    // May be NULL — public API falls back to canonical CPU modexp.
    LuxBackendError (*op_modexp)(
        LuxBackendContext* ctx,
        const uint8_t* base, size_t base_len,
        const uint8_t* exp,  size_t exp_len,
        const uint8_t* mod,  size_t mod_len,
        uint8_t*       out
    );

    // -------- Crypto: BLS12-381 EIP-2537 precompiles (EVM 0x0b..0x11) --------
    //
    // Every input is in canonical EVM byte format (16-byte zero-padded
    // 48-byte field elements; G1 affine = 128 B, G2 affine = 256 B).
    // Output buffer sizes are pinned per address. May be NULL — public
    // API falls back to canonical CPU c-abi (luxcpp/crypto/bls).
    //
    // 0x0b BLS12_G1ADD            in 256  → out 128
    // 0x0c BLS12_G1MSM            in N*160→ out 128
    // 0x0d BLS12_G2ADD            in 512  → out 256
    // 0x0e BLS12_G2MSM            in N*288→ out 256
    // 0x0f BLS12_PAIRING          in N*384→ out  32
    // 0x10 BLS12_MAP_FP_TO_G1     in 64   → out 128
    // 0x11 BLS12_MAP_FP2_TO_G2    in 128  → out 256
    LuxBackendError (*op_bls12_381_g1add_eip2537)(
        LuxBackendContext* ctx,
        const uint8_t in[256], uint8_t out[128]);
    LuxBackendError (*op_bls12_381_g1msm_eip2537)(
        LuxBackendContext* ctx,
        const uint8_t* in, size_t in_len, uint8_t out[128]);
    LuxBackendError (*op_bls12_381_g2add_eip2537)(
        LuxBackendContext* ctx,
        const uint8_t in[512], uint8_t out[256]);
    LuxBackendError (*op_bls12_381_g2msm_eip2537)(
        LuxBackendContext* ctx,
        const uint8_t* in, size_t in_len, uint8_t out[256]);
    LuxBackendError (*op_bls12_381_pairing_eip2537)(
        LuxBackendContext* ctx,
        const uint8_t* in, size_t in_len, uint8_t out[32]);
    LuxBackendError (*op_bls12_381_map_fp_to_g1_eip2537)(
        LuxBackendContext* ctx,
        const uint8_t in[64], uint8_t out[128]);
    LuxBackendError (*op_bls12_381_map_fp2_to_g2_eip2537)(
        LuxBackendContext* ctx,
        const uint8_t in[128], uint8_t out[256]);

    // -------- Crypto: KZG point evaluation (EIP-4844, EVM 0x0a) --------
    // Trusted-setup G2 element baked in by the CPU c-abi.
    // May be NULL — public API falls back to canonical CPU c-abi
    // (luxcpp/crypto/kzg/c_kzg.cpp).
    LuxBackendError (*op_kzg_verify_eip4844)(
        LuxBackendContext* ctx,
        const uint8_t commit[48], const uint8_t z[32],
        const uint8_t y[32],      const uint8_t proof[48],
        bool* out_valid);

    // -------- DEX: CLOB matcher (EVM 0x100, Lux custom precompile) --------
    // Input is the raw EVM calldata layout; output is the matched-trade
    // tuple per dex_match_cpu. May be NULL — public API returns
    // NOT_SUPPORTED, the cevm wrapper falls back to dex_match_cpu.
    LuxBackendError (*op_dex_match_clob)(
        LuxBackendContext* ctx,
        const uint8_t* in, size_t in_len,
        uint8_t* out, size_t out_cap, size_t* out_len);

    // -------- Crypto: MSM (curve_type is LuxCurve from <lux/gpu.h>) --------
    LuxBackendError (*op_msm)(
        LuxBackendContext* ctx,
        const void* scalars, const void* points, void* result,
        size_t n, int curve_type
    );

    // -------- Crypto: KZG polynomial commitments --------
    LuxBackendError (*op_kzg_commit)(
        LuxBackendContext* ctx,
        const void* coeffs, const void* srs, void* commitment,
        size_t degree, int curve_type
    );
    LuxBackendError (*op_kzg_open)(
        LuxBackendContext* ctx,
        const void* coeffs, const void* srs, const void* point, void* proof,
        size_t degree, int curve_type
    );
    LuxBackendError (*op_kzg_verify)(
        LuxBackendContext* ctx,
        const void* commitment, const void* proof,
        const void* point, const void* value, const void* srs_g2,
        bool* result, int curve_type
    );

    // -------- Crypto: secp256k1 ecrecover (Ethereum) --------
    LuxBackendError (*op_ecrecover_batch)(
        LuxBackendContext* ctx,
        const void* signatures, void* addresses, size_t num_signatures
    );

    // -------- Crypto: Post-quantum signatures (FIPS 203/204/205) --------
    //
    // ML-DSA-65 (Dilithium3) batch verify. pubkeys: 1952B each, signatures:
    // 3309B each (FIPS 204 mode-65 wire-encoded), messages: variable length
    // per element via `msg_lens[i]` (ABI v14: was hardcoded to 64 in v13's
    // wrapper, silently UB'ing every non-64-byte caller).
    //
    // Length contract (mirrors v13 SLH-DSA verify shape exactly):
    //   * msg_lens != NULL → messages[i] reads msg_lens[i] bytes.
    //     msg_width_hint is ignored.
    //   * msg_lens == NULL → messages[i] reads msg_width_hint bytes for
    //     every element. Convenience path for uniform-batch callers that
    //     would otherwise allocate a {msg_width_hint, …, msg_width_hint}
    //     array of `count` entries just to hand it back to the wrapper.
    //   * Every msg_len value must satisfy `msg_len <= INT32_MAX - 2`
    //     (the -2 reserves headroom for the 0x00 || ctx_len pre-pended
    //     to each element on the M' pool — Red C-1 truncation defense).
    //     The orchestrator preamble at lux_cuda_mldsa_verify_batch_gpu
    //     rejects out-of-range lengths with INVALID_ARGUMENT. msg_len
    //     == 0 is a legal edge case (empty message — SHAKE256 absorbs
    //     zero bytes cleanly).
    //
    // FIPS 204 Algorithm 3 (Verify) wraps the message into the M' shape
    // `0x00 || ctx_len || ctx || msg` before deriving μ = SHAKE256(tr ||
    // M', 64). This wrapper passes the raw msg through to the orchestrator;
    // the orchestrator builds the M' wrapping with ctx_len = 0 (the
    // lux-accel session API does not expose a ctx slot — pure-mode only).
    //
    // results[i] = true iff verification succeeded. Per-element pointer-
    // null is INVALID_ARGUMENT unless msg_lens[i] == 0 (in which case
    // messages[i] may be NULL — nothing is read).
    LuxBackendError (*op_mldsa_verify_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* pubkeys,
        const uint8_t* const* messages,
        const size_t*         msg_lens,
        uint32_t              msg_width_hint,
        const uint8_t* const* signatures,
        bool* results,
        size_t count
    );

    // ML-KEM-768 (Kyber768) batch decapsulation. secret_keys: 2400B each,
    // ciphertexts: 1088B each, shared_secrets: 32B each (output).
    LuxBackendError (*op_mlkem_decapsulate_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* secret_keys,
        const uint8_t* const* ciphertexts,
        uint8_t** shared_secrets,
        size_t count
    );

    // SLH-DSA (SPHINCS+) SHAKE-128f batch verify. ABI v13: per-element
    // msg_len so the wrapper builds the device elem array with the true
    // message byte count. Pubkeys 32B each, sigs 17088B each, messages
    // are variable length (ACVP range 1 B to 8 KiB; 0 is legal).
    // results[i] = true iff verification succeeded.
    LuxBackendError (*op_slhdsa_verify_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* pubkeys,
        const uint8_t* const* messages,
        const size_t*         msg_lens,
        const uint8_t* const* signatures,
        bool* results,
        size_t count
    );

    // SLH-DSA (SPHINCS+) SHAKE-192f batch verify. ABI v13 new slot.
    // Pubkeys 48B each, sigs 35664B each, messages variable length.
    // Same msg_lens contract as the 128f slot above.
    LuxBackendError (*op_slhdsa_verify_batch_shake192f)(
        LuxBackendContext* ctx,
        const uint8_t* const* pubkeys,
        const uint8_t* const* messages,
        const size_t*         msg_lens,
        const uint8_t* const* signatures,
        bool* results,
        size_t count
    );

    // -------- Crypto: Threshold signature primitives --------
    //
    // Corona lattice-based threshold: per-party partial signing pass.
    // shares: 1024B each (per-party secret share), messages: 32B each,
    // partial_sigs: 1024B each (output). Returns NOT_SUPPORTED on backends
    // that do not implement the full ceremony pipeline.
    LuxBackendError (*op_corona_partial_sign_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* shares,
        const uint8_t* const* messages,
        uint8_t** partial_sigs,
        size_t count
    );

    // Corona threshold combine: merge `threshold` partial sigs into one
    // combined signature using Lagrange interpolation coefficients.
    LuxBackendError (*op_corona_combine_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* partial_sigs,
        const int32_t* lagrange_coeffs,
        uint8_t** combined_sigs,
        size_t threshold,
        size_t count
    );

    // FROST threshold Schnorr partial-signature verification. commitments:
    // 66B each, signatures: 32B each, pubkeys: 33B each, challenges: 32B
    // each (pre-computed c*lambda_i scalars).
    LuxBackendError (*op_frost_partial_verify_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* commitments,
        const uint8_t* const* signatures,
        const uint8_t* const* pubkeys,
        const uint8_t* const* challenges,
        bool* results,
        size_t count
    );

    // CGGMP21 threshold ECDSA partial-signing pass. Each entry packs:
    // k_share[32] || chi_share[32] || msg_hash[32] || gamma_share[32].
    // r_x is the x-coordinate of the combined nonce R shared across the
    // batch. partial_sigs[i] is the per-party sigma_i (32B).
    LuxBackendError (*op_cggmp21_partial_sign_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* inputs,
        const uint8_t* r_x,
        uint8_t** partial_sigs,
        size_t count
    );

    // -------- Crypto: Classical Schnorr (Ed25519 / sr25519) --------
    //
    // Ed25519 (RFC 8032) batch verify. Messages are 64-byte digests by
    // contract (host pre-hashes if larger; consumers must commit to a
    // fixed-width input). pubkeys: 32B each, signatures: 64B each,
    // results[i] = true iff verify(pk, msg, sig) succeeds.
    LuxBackendError (*op_ed25519_verify_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* pubkeys,
        const uint8_t* const* messages,
        const uint8_t* const* signatures,
        bool* results,
        size_t count
    );

    // sr25519 (Schnorrkel/Ristretto255) batch verify. Same shape and
    // 64-byte message contract as Ed25519, but uses the Substrate-style
    // schnorrkel transcript.
    LuxBackendError (*op_sr25519_verify_batch)(
        LuxBackendContext* ctx,
        const uint8_t* const* pubkeys,
        const uint8_t* const* messages,
        const uint8_t* const* signatures,
        bool* results,
        size_t count
    );

    // -------- Crypto: FIPS 202 SHA3-256 + SHAKE256 (ABI v8) --------
    //
    // SHA3-256: FIPS 202 fixed-output 32-byte hash; padding domain
    // separator 0x06. Distinct from the Ethereum keccak256 already at
    // op_keccak256_hash (which uses 0x01). One concatenated input slab,
    // one 32-byte output per input.
    LuxBackendError (*op_sha3_256_hash)(
        LuxBackendContext* ctx,
        const uint8_t* inputs, uint8_t* outputs,
        const size_t* input_lens, size_t num_inputs
    );

    // SHAKE256: FIPS 202 XOF; padding domain separator 0x1F. Caller-
    // specified output length per input. The outputs slab is the
    // concatenation of every per-input squeeze (total bytes = sum of
    // output_lens).
    LuxBackendError (*op_shake256_hash)(
        LuxBackendContext* ctx,
        const uint8_t* inputs, uint8_t* outputs,
        const size_t* input_lens, const size_t* output_lens,
        size_t num_inputs
    );

    // cSHAKE256: NIST SP 800-185 customisable SHAKE256. Per-batch
    // (function_name, customisation) — every entry shares the same
    // prefix bytes (caller-supplied bytepad-aligned). When both are
    // empty, degenerates to SHAKE256 per the spec (padding 0x1F);
    // otherwise uses cSHAKE padding 0x04 with the bytepad prefix
    // absorbed before the per-entry input. ABI v9.
    LuxBackendError (*op_cshake256_hash)(
        LuxBackendContext* ctx,
        const uint8_t* function_name, size_t function_name_len,
        const uint8_t* customisation, size_t customisation_len,
        const uint8_t* inputs, uint8_t* outputs,
        const size_t* input_lens, const size_t* output_lens,
        size_t num_inputs
    );

    // -------- ML steel: GEMM / FlashAttention / Conv2D (ABI v10) --------
    //
    // Single-precision (FP32) row-major matrix multiply with alpha/beta.
    //   C[M x N] = alpha * A[M x K] @ B[K x N] + beta * C[M x N]
    // All three buffers are host pointers — backend manages staging.
    // Validation: a, b, c non-null AND M*N, M*K, K*N do not overflow.
    LuxBackendError (*op_gemm)(
        LuxBackendContext* ctx,
        const float* a, const float* b, float* c,
        float alpha, float beta,
        uint32_t M, uint32_t N, uint32_t K
    );

    // FlashAttention forward (FP32). Online-softmax tile pipeline; O(N)
    // memory instead of O(N^2). All buffers row-major NHWC-style layout
    // [B x H x S x D] for Q/K/V/output. `lse` is optional [B x H x S]
    // log-sum-exp scratch for backward — pass NULL when not training.
    //   O[i] = sum_j softmax_j( Q_i · K_j^T * scale ) · V_j  (for j ≤ i if causal)
    // scale is the standard 1/sqrt(D) precomputed by the caller.
    LuxBackendError (*op_attention)(
        LuxBackendContext* ctx,
        const float* q, const float* k, const float* v,
        float* output, float* lse,
        float scale,
        uint32_t batch_size, uint32_t num_heads,
        uint32_t seq_len, uint32_t head_dim,
        bool is_causal
    );

    // Tiled 2-D convolution (FP32, NCHW). Output shape:
    //   out_h = (in_h + 2*pad_h - dilation_h*(kernel_h-1) - 1) / stride_h + 1
    //   out_w = analogous
    // input:  [batch_size, in_channels,  in_h,  in_w]
    // weight: [out_channels, in_channels, kernel_h, kernel_w]
    // bias:   [out_channels] or NULL
    // output: [batch_size, out_channels, out_h, out_w] (caller-allocated)
    LuxBackendError (*op_conv)(
        LuxBackendContext* ctx,
        const float* input, const float* weight, const float* bias,
        float* output,
        uint32_t batch_size,
        uint32_t in_channels, uint32_t out_channels,
        uint32_t in_height, uint32_t in_width,
        uint32_t kernel_h, uint32_t kernel_w,
        uint32_t stride_h, uint32_t stride_w,
        uint32_t pad_h, uint32_t pad_w,
        uint32_t dilation_h, uint32_t dilation_w
    );

    // -------- C-Chain EVM opcodes (ABI v11) --------
    //
    // Per-opcode batched dispatch over arrays of 4×uint64_t LE-limb words
    // (the canonical CEVM word layout — matches holiman/uint256.Int). Each
    // input/output buffer is `n` words contiguous (32 bytes per word).
    // Backend stages H2D/D2H; caller passes host pointers. Slot may be
    // NULL — public lux_gpu_cevm_<op>_batch falls back to the canonical
    // CPU oracle. NOT_SUPPORTED from a non-null slot also falls back to
    // CPU (consensus-safe overlay). INVALID_ARGUMENT propagates.
    //
    // Binary (a, b → out): out[i] = a[i] OP b[i] for i in [0, n).
    LuxBackendError (*op_cevm_add)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_sub)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_mul)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_div)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_sdiv)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_mod)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_smod)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_exp)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_signextend)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_and)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_or)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_xor)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_byte)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    // Shift ops: operand order matches EVM stack semantics — first operand
    // is the shift amount (a), second is the value (b).
    LuxBackendError (*op_cevm_shl)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_shr)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_sar)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_lt)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_gt)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_slt)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_sgt)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_eq)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, uint64_t* out, size_t n);

    // Unary (a → out): out[i] = OP a[i].
    LuxBackendError (*op_cevm_not)(LuxBackendContext* ctx, const uint64_t* a, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_iszero)(LuxBackendContext* ctx, const uint64_t* a, uint64_t* out, size_t n);

    // Ternary (a, b, c → out): out[i] = (a[i] OP b[i]) mod c[i]. The "+"/
    // "*" is done at 257/512-bit width before reduction (EVM semantics).
    // c[i] == 0 yields out[i] == 0 (canonical EVM behavior).
    LuxBackendError (*op_cevm_addmod)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, const uint64_t* c, uint64_t* out, size_t n);
    LuxBackendError (*op_cevm_mulmod)(LuxBackendContext* ctx, const uint64_t* a, const uint64_t* b, const uint64_t* c, uint64_t* out, size_t n);

    // Block-STM conflict pair extraction. packed_sets, tx_offsets layout
    // and conflicts output match lux_gpu_cevm_conflict_detect in
    // <lux/gpu/cevm.h>. The kernel is embarrassingly parallel over
    // candidate (lo, hi) tx pairs; the CPU consumes the edge list to
    // schedule commit order. Slot may be NULL → CPU fallback.
    LuxBackendError (*op_cevm_conflict_detect)(
        LuxBackendContext* ctx,
        const uint8_t*  packed_sets,
        const uint32_t* tx_offsets,
        uint32_t        num_txs,
        uint32_t*       conflicts,
        uint32_t        conflicts_cap,
        uint32_t*       out_count);

    // -------- SLH-DSA magnetar hash-tree primitives (ABI v12) --------
    //
    // Four FIPS 205 hash-tree primitives shipped as GPU kernels at
    // lux-private/gpu-kernels commit 0d94c0b. See the ABI v12 block at
    // the top of this file for the rationale, the pool layout, and the
    // referenced LuxMagnetar*Elem types in <lux/gpu/crypto.h>. Each
    // slot stages H2D/D2H host-pointer arrays: elems_data is the packed
    // descriptor array, the pools are flat byte buffers, out is a
    // contiguous batch × {32,64,32}-byte buffer per kernel.
    //
    // Byte-equal to:
    //   * ops/crypto/slhdsa/tests/slhdsa_cpu_oracle.hpp (CPU oracle).
    //   * magnetar Go reference slhdsa_internal.go (KAT 6/6 PASS
    //     cross-checked 2026-06-03).
    //
    // Slot may be NULL → public lux_gpu_magnetar_* surface falls back
    // to the CPU oracle. NOT_SUPPORTED also falls back. INVALID_ARGUMENT
    // propagates to the caller.

    // FIPS 205 §5 Algorithm 5 chain: out_pool stride 32 B per elem
    //   (upper bytes zero for n < 32).
    LuxBackendError (*op_magnetar_wotsplus_chain_batch)(
        LuxBackendContext* ctx,
        const void*  elems_data,         // LuxMagnetarWotsChainElem[batch_size]
        const void*  pk_seed_pool,
        const void*  x_pool,
        void*        out_pool,           // batch_size * 32 bytes
        size_t       batch_size);

    // FIPS 205 §8.2 Algorithm 15 fors_node: out_pool stride 32 B.
    LuxBackendError (*op_magnetar_fors_subtree_batch)(
        LuxBackendContext* ctx,
        const void*  elems_data,         // LuxMagnetarForsSubtreeElem[batch_size]
        const void*  pk_seed_pool,
        const void*  sk_leaves_pool,
        void*        out_pool,           // batch_size * 32 bytes
        size_t       batch_size);

    // FIPS 205 §6.1 Algorithm 9 xmss_node: out_pool stride 32 B.
    LuxBackendError (*op_magnetar_xmss_subtree_batch)(
        LuxBackendContext* ctx,
        const void*  elems_data,         // LuxMagnetarXmssSubtreeElem[batch_size]
        const void*  pk_seed_pool,
        const void*  wots_pk_pool,
        void*        out_pool,           // batch_size * 32 bytes
        size_t       batch_size);

    // FIPS 205 §11.2 SHAKE H_msg + PRF_msg. Two independent sub-batches
    // dispatched in one call:
    //   h_out_pool stride 64 B per elem (digest_len ≤ 47, upper bytes zero).
    //   p_out_pool stride 32 B per elem.
    // Either sub-batch may be empty (h_batch == 0 or p_batch == 0); the
    // backend skips the empty side and still returns OK.
    LuxBackendError (*op_magnetar_hmsg_prfmsg_batch)(
        LuxBackendContext* ctx,
        const void*  h_elems_data,       // LuxMagnetarHmsgElem[h_batch]
        const void*  r_pool,
        const void*  hmsg_pk_seed_pool,
        const void*  pk_root_pool,
        const void*  hmsg_msg_pool,
        void*        h_out_pool,         // h_batch * 64 bytes
        size_t       h_batch,
        const void*  p_elems_data,       // LuxMagnetarPrfmsgElem[p_batch]
        const void*  sk_prf_pool,
        const void*  opt_rand_pool,
        const void*  prfmsg_msg_pool,
        void*        p_out_pool,         // p_batch * 32 bytes
        size_t       p_batch);

    // -------- Crypto: ML-DSA-65 batch sign (ABI v14) --------
    //
    // FIPS 204 Algorithm 7 (Sign_internal) batched signer. Wraps the
    // orchestrator at lux-private/gpu-kernels/ops/crypto/mldsa/cuda/
    // mldsa_sign_orchestrator.cu (extern "C"
    // lux_cuda_mldsa_sign_batch_gpu).
    //
    // Inputs:
    //   * skeys      : `count * sk_stride` bytes of packed secret keys
    //                  (ML-DSA-65 sk_stride = 4032 per FIPS 204 §4 width
    //                  table). The orchestrator skDecode pass rips
    //                  ρ, K, tr, s1, s2, t0 from each sk; this wrapper
    //                  cudaMemcpy2D's the contiguous pool into device
    //                  memory in one shot.
    //   * sk_stride  : per-element sk pitch in bytes. Must equal 4032 for
    //                  the v14 ML-DSA-65 surface; future modes (44, 87)
    //                  will gain new vtbl slots rather than overloading
    //                  this one.
    //   * msgs       : flat host buffer of per-element messages, packed
    //                  contiguously without padding. Element i reads
    //                  msg_lens[i] bytes starting at msgs +
    //                  sum(msg_lens[0..i-1]).
    //   * msg_lens   : per-element message length array of `count`
    //                  entries. NULL → use msg_width_hint for every elem
    //                  (uniform-batch convenience path identical to the
    //                  verify slot's contract). Every length must satisfy
    //                  `msg_len <= INT32_MAX`.
    //   * msg_width_hint : per-element message length when msg_lens ==
    //                  NULL. Ignored when msg_lens != NULL.
    //   * count      : batch size.
    //
    // Outputs:
    //   * sigs_out     : `count * 3309` bytes of packed signatures
    //                    (ML-DSA-65 sig_stride = 3309 per FIPS 204).
    //                    Element i writes 3309 bytes at sigs_out + i *
    //                    3309. Every byte of every accepted slot is
    //                    written; rejected slots (kappa-cap exhausted —
    //                    defensive only, FIPS 204 mandates acceptance
    //                    within 1024 iters with negligible probability of
    //                    rejection) are filled with the last-iter pack_sig
    //                    output (which the host MUST treat as invalid; see
    //                    sig_lens_out).
    //   * sig_lens_out : per-element actual signature length, in bytes.
    //                    On accept, equals 3309. On kappa-cap reject,
    //                    equals 0 — caller treats this as a hard error.
    //                    May be NULL if caller does not need per-element
    //                    accept/reject feedback (the host will fall back
    //                    to a per-element verify pass to detect rejects).
    //
    // The orchestrator is hedged (FIPS 204 §3.4): random 32-byte hedge
    // rnd is drawn per signature via the orchestrator's internal
    // randombytes helper. There is no zero-randomness deterministic
    // fallback at this slot — callers that need byte-determinism MUST
    // route to the lux-accel CPU oracle (PQClean deterministic mode
    // through MLDSA_DET_SIGN env knob outside this surface).
    //
    // Slot may be NULL — public lux_gpu_mldsa_sign_batch surface returns
    // LUX_ERROR_NOT_SUPPORTED, lux-accel mldsa_batch.cpp falls back to
    // the PQClean hedged-sign CPU path.
    LuxBackendError (*op_mldsa_sign_batch)(
        LuxBackendContext* ctx,
        const uint8_t* skeys,
        size_t         sk_stride,
        const uint8_t* msgs,
        const size_t*  msg_lens,
        uint32_t       msg_width_hint,
        size_t         count,
        uint8_t*       sigs_out,
        uint32_t*      sig_lens_out
    );

    // -------- Crypto: ML-DSA lattice NTT batch (ABI v14) --------
    //
    // Forward or inverse Number-Theoretic Transform over Z_q[X]/(X^256+1)
    // with q = 8380417 (FIPS 204 ML-DSA prime), batched across `n_polys`
    // contiguous int32 coefficient arrays. Wraps the kernels at
    // lux-private/gpu-kernels/ops/crypto/mldsa/cuda/mldsa_ntt.cu
    // (extern "C" lux_cuda_mldsa_poly_ntt_batch /
    // lux_cuda_mldsa_poly_invntt_batch).
    //
    // Layout: `coeffs_in` is `n_polys * 256` int32 coefficients, packed
    // contiguous in memory (no per-poly stride argument — every
    // polynomial in the ML-DSA ring is exactly 256 coefficients). The
    // transform is NOT in-place via this wrapper — the device backend
    // stages H2D, runs the kernel, and writes the result to `ntt_out`
    // (which must be a separate buffer of identical size).
    //
    //   * direction = 0 : forward NTT (poly → poly_hat in Montgomery
    //                     domain, bit-reversed order). Byte-equal to
    //                     PQCLEAN_MLDSA65_CLEAN_poly_ntt.
    //   * direction = 1 : inverse NTT-to-Montgomery (poly_hat → poly,
    //                     normal order, Montgomery domain — caller
    //                     de-Montgomery's at the appropriate boundary).
    //                     Byte-equal to
    //                     PQCLEAN_MLDSA65_CLEAN_poly_invntt_tomont.
    //
    // The wrapper is decoupled from the existing FHE-aimed
    // `op_ntt_forward` / `op_ntt_inverse` slots (uint64 + runtime
    // modulus + N up to 32768). Each surface stays in its own lane:
    //   * FHE callers — uint64 coefficients, runtime modulus, large N —
    //     route to op_ntt_forward / op_ntt_inverse.
    //   * ML-DSA / P3Q / Pulsar callers — int32 coefficients, q =
    //     8380417 baked in, N = 256 — route here.
    //
    // Slot may be NULL — public lux_gpu_lattice_ntt_mldsa_batch surface
    // returns LUX_ERROR_NOT_SUPPORTED, lux-accel mldsa_batch.cpp falls
    // back to the per-poly PQClean CPU NTT.
    LuxBackendError (*op_lattice_ntt_mldsa_batch)(
        LuxBackendContext* ctx,
        const int32_t* coeffs_in,
        size_t         n_polys,
        int32_t*       ntt_out,
        uint32_t       direction
    );
} lux_gpu_backend_vtbl;

// =============================================================================
// Backend Descriptor (returned by plugin init)
//
// vtbl_size is a hard-required cookie that lets the loader detect a plugin
// that lies about its abi_version while shipping a truncated vtable. Each
// plugin MUST set this to sizeof(lux_gpu_backend_vtbl) as compiled against
// THIS header. The loader MUST reject any plugin whose vtbl_size does not
// match the consumer's compile-time sizeof. This protects consumers from
// reading past the end of an undersized vtable and dispatching through a
// junk function pointer.
// =============================================================================

typedef struct {
    uint32_t                     abi_version;     // Must be LUX_GPU_BACKEND_ABI_VERSION
    uint32_t                     vtbl_size;       // Must equal sizeof(lux_gpu_backend_vtbl)
    const char*                  backend_name;    // "cpu" | "metal" | "cuda" | "webgpu"
    const char*                  backend_version; // e.g., "0.1.0"
    uint32_t                     capabilities;    // Bitmask of supported features
    const lux_gpu_backend_vtbl*  vtbl;
} lux_gpu_backend_desc;

// =============================================================================
// Capability flags (advisory, for feature gating in consumers)
// =============================================================================

#define LUX_CAP_TENSOR_OPS      (1u << 0)
#define LUX_CAP_MATMUL          (1u << 1)
#define LUX_CAP_NTT             (1u << 2)
#define LUX_CAP_MSM             (1u << 3)
#define LUX_CAP_UNIFIED_MEMORY  (1u << 4)
#define LUX_CAP_FHE             (1u << 5)
#define LUX_CAP_TFHE            (1u << 6)
#define LUX_CAP_REDUCE          (1u << 7)
#define LUX_CAP_SOFTMAX         (1u << 8)
#define LUX_CAP_UNARY           (1u << 9)
#define LUX_CAP_NORMALIZATION   (1u << 10)
#define LUX_CAP_BLS12_381       (1u << 11)
#define LUX_CAP_BN254           (1u << 12)
#define LUX_CAP_KZG             (1u << 13)
#define LUX_CAP_POSEIDON2       (1u << 14)
#define LUX_CAP_BLAKE3          (1u << 15)
#define LUX_CAP_KECCAK256       (1u << 16)
#define LUX_CAP_ECRECOVER       (1u << 17)
#define LUX_CAP_BLIND_ROTATE    (1u << 18)
#define LUX_CAP_POLY_MUL        (1u << 19)
#define LUX_CAP_MLDSA           (1u << 20)
#define LUX_CAP_MLKEM           (1u << 21)
#define LUX_CAP_SLHDSA          (1u << 22)
#define LUX_CAP_CORONA        (1u << 23)
#define LUX_CAP_FROST           (1u << 24)
#define LUX_CAP_CGGMP21         (1u << 25)
#define LUX_CAP_ED25519         (1u << 26)
#define LUX_CAP_SR25519         (1u << 27)
#define LUX_CAP_SHA3            (1u << 28)   // FIPS 202 SHA3-256 + SHAKE256 (ABI v8)
#define LUX_CAP_STEEL           (1u << 29)   // op_gemm + op_attention + op_conv (ABI v10)
#define LUX_CAP_CEVM            (1u << 30)   // op_cevm_* — 25 opcodes + STM conflict_detect (ABI v11)
#define LUX_CAP_MAGNETAR        (1u << 31)   // op_magnetar_* — FIPS 205 SLH-DSA hash-tree (ABI v12)

// =============================================================================
// Plugin Entry Point
// =============================================================================

// Every backend shared library must export this symbol.
// Returns true on success, false if backend unavailable on this system.
typedef bool (*lux_gpu_backend_init_fn)(lux_gpu_backend_desc* out);

#define LUX_GPU_BACKEND_INIT_SYMBOL "lux_gpu_backend_init"

#ifdef _WIN32
#define LUX_GPU_BACKEND_EXPORT __declspec(dllexport)
#else
#define LUX_GPU_BACKEND_EXPORT __attribute__((visibility("default")))
#endif

#ifdef __cplusplus
#define LUX_GPU_DECLARE_BACKEND(init_func)                                     \
    extern "C" LUX_GPU_BACKEND_EXPORT bool                                     \
    lux_gpu_backend_init(lux_gpu_backend_desc* out) { return init_func(out); }
#else
#define LUX_GPU_DECLARE_BACKEND(init_func)                                     \
    LUX_GPU_BACKEND_EXPORT bool                                                \
    lux_gpu_backend_init(lux_gpu_backend_desc* out) { return init_func(out); }
#endif

#ifdef __cplusplus
}
#endif

#endif // LUX_GPU_BACKEND_PLUGIN_H
