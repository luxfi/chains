// Copyright (c) 2024-2026 Lux Industries Inc.
// SPDX-License-Identifier: BSD-3-Clause-Eco
//
// Lux GPU crypto types
//
// Shared types for cryptographic kernels (MSM, KZG, Poseidon2, Shamir, ...).
// The curve enum lives in <lux/gpu.h> as LuxCurve and is the single source of
// truth — int curve_type fields in the vtbl ABI are LuxCurve values cast to int.

#ifndef LUX_GPU_CRYPTO_H
#define LUX_GPU_CRYPTO_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

// =============================================================================
// Field Types
// =============================================================================

// 256-bit scalar (BN254 base/scalar, BLS12-381 scalar, secp256k1, ed25519)
typedef struct {
    uint64_t limbs[4];
} LuxScalar256;

// 384-bit base field element (BLS12-381)
typedef struct {
    uint64_t limbs[6];
} LuxFp384;

// 64-bit Goldilocks field element (2^64 - 2^32 + 1)
typedef uint64_t LuxGoldilocks;

// =============================================================================
// Point Types
// =============================================================================

// G1 affine point (BN254) — Fp254 is encoded as 4×u64 to match shader layout
typedef struct {
    LuxScalar256 x;
    LuxScalar256 y;
    uint32_t infinity;
    uint32_t _pad;
} LuxG1Affine254;

// G1 projective (Jacobian) point (BN254)
typedef struct {
    LuxScalar256 x;
    LuxScalar256 y;
    LuxScalar256 z;
} LuxG1Projective254;

// 512-bit quadratic-extension Fp2 = Fp[u]/(u^2 + 1) over BN254 Fp.
// Limbs are in Montgomery form (R = 2^256 mod p). Layout: c0 first, then c1.
typedef struct {
    LuxScalar256 c0;
    LuxScalar256 c1;
} LuxFp2_254;

// G2 affine point on the BN254 sextic twist E'(Fp2): y^2 = x^3 + 3/(9+u).
typedef struct {
    LuxFp2_254 x;
    LuxFp2_254 y;
    uint32_t infinity;
    uint32_t _pad;
} LuxG2Affine254;

// G2 projective (Jacobian) point (BN254). 192 bytes = 3 * Fp2.
typedef struct {
    LuxFp2_254 x;
    LuxFp2_254 y;
    LuxFp2_254 z;
} LuxG2Projective254;

// G1 affine point (BLS12-381) — Fp384 is 6×u64
typedef struct {
    LuxFp384 x;
    LuxFp384 y;
    uint32_t infinity;
    uint32_t _pad;
} LuxG1Affine381;

// G1 projective (Jacobian) point (BLS12-381)
typedef struct {
    LuxFp384 x;
    LuxFp384 y;
    LuxFp384 z;
} LuxG1Projective381;

// 768-bit quadratic-extension element Fp2 = Fp[u]/(u² + 1). Layout matches
// blst's `blst_fp2 { blst_fp fp[2]; }` byte-for-byte: c0 first, then c1.
// All limbs are in Montgomery form (R = 2^384 mod p), same convention as
// LuxFp384.
typedef struct {
    LuxFp384 c0;
    LuxFp384 c1;
} LuxFp2_381;

// G2 affine point on the BLS12-381 sextic twist E'(Fp2): y² = x³ + 4(1+u).
// Layout matches blst's `blst_p2_affine { blst_fp2 x, y; }` and adds the
// infinity flag word for ABI symmetry with LuxG1Affine381.
typedef struct {
    LuxFp2_381 x;
    LuxFp2_381 y;
    uint32_t infinity;
    uint32_t _pad;
} LuxG2Affine381;

// G2 projective (Jacobian) point. Layout matches blst's
// `blst_p2 { blst_fp2 x, y, z; }`.
typedef struct {
    LuxFp2_381 x;
    LuxFp2_381 y;
    LuxFp2_381 z;
} LuxG2Projective381;

// Fp12 element — the pairing target group GT lives here. Layout matches
// blst byte-for-byte: 12 Fp limbs grouped as c0 ‖ c1 with c_i = Fp6 =
// (Fp2)³. Total size = 576 bytes (12 × 6 × u64).
typedef struct {
    LuxFp2_381 fp2[6];
} LuxFp12_381;

// =============================================================================
// Pairing batch caps — canonical, ABI-stable, single source of truth.
// =============================================================================
//
// LUX_BN254_MAX_PAIRS_PER_BATCH is the maximum n_pairs a backend's
// op_bn254_pairing may accept in one call. Backends with a stack-allocated
// scratch (CUDA / HIP / Vulkan / Metal) reject n_pairs > this cap with
// LUX_BACKEND_ERROR_NOT_SUPPORTED at the launcher boundary; the public
// dispatcher then falls back to the CPU oracle (gpu_core.cpp:lux_bn254_pairing),
// which has no cap. NOT_SUPPORTED specifically (not INVALID_ARGUMENT) is the
// trigger for the fallback path; INVALID_ARGUMENT propagates to the caller.
//
// Picked at 16 to fit the per-pair scratch (Fp/Fp2/Fp6/Fp12 tower state +
// projective Q + negated Q) inside the device-local register/shared-memory
// envelope while still covering typical EVM EIP-197 call shapes (1..16
// pairs is the overwhelming majority of mainnet traffic; ZK-rollup batch
// verifiers that exceed 16 pairs are correctly handled by the CPU oracle).
//
// Changing this constant requires re-checking the per-pair scratch size in
// every backend's pairing kernel — do not raise without verifying device
// limits.
#define LUX_BN254_MAX_PAIRS_PER_BATCH 16

// =============================================================================
// SLH-DSA (FIPS 205) magnetar hash-tree per-element descriptors — ABI v12
// =============================================================================
//
// One row per batch element. Pointer-free: every payload is resolved as a
// byte offset into a flat host-side pool that the vtbl slot also receives.
// Layout / field order is the single source of truth across all backends
// (CUDA / HIP / Metal / Vulkan / WebGPU) and the CPU oracle. Sizes are
// pinned so that the elem array can be memcpy'd device-side as-is.
//
// FIPS 205 §4.2 address layout is 32 bytes BE; the addr field carries
// the per-element address template (caller sets type/key-pair/etc before
// the call; the kernel mutates the hash-address / tree-height / tree-
// index slots internally).

// FIPS 205 §5 Algorithm 5 "chain" element.
//   tmp ← x; for j ∈ [i, i+s): addr.setHashAddress(j); tmp ← F(pk_seed, addr, tmp).
typedef struct {
    uint32_t pk_seed_off;   // byte offset into pk_seed_pool (reads n bytes)
    uint32_t x_off;         // byte offset into x_pool (reads n bytes)
    uint32_t i;             // starting chain index
    uint32_t s;             // chain length
    uint8_t  addr[32];      // FIPS 205 §4.2 address template
    uint32_t n;             // hash output size in bytes (24 / 32)
    uint32_t _pad0;
    uint32_t _pad1;
    uint32_t _pad2;
} LuxMagnetarWotsChainElem;

// FIPS 205 §8.2 Algorithm 15 "fors_node" element.
//   2^height secret-derived leaves at sk_leaves_pool[leaves_off ..],
//   each n bytes; root reduced via F (leaf) + H (internal).
typedef struct {
    uint32_t pk_seed_off;
    uint32_t leaves_off;    // byte offset into sk_leaves_pool ((1<<height) × n bytes)
    uint32_t leaf_idx;      // subtree leaf index
    uint32_t height;        // subtree height (a for full FORS subtree; ≤ 16)
    uint8_t  addr[32];
    uint32_t n;
    uint32_t _pad0;
    uint32_t _pad1;
    uint32_t _pad2;
} LuxMagnetarForsSubtreeElem;

// FIPS 205 §6.1 Algorithm 9 "xmss_node" element.
//   2^height precomputed WOTS+ pk leaves at wots_pk_pool[leaves_off ..],
//   each n bytes; root reduced via H.
typedef struct {
    uint32_t pk_seed_off;
    uint32_t wots_pk_leaves_off;
    uint32_t leaf_idx;
    uint32_t height;        // ≤ 16
    uint8_t  addr[32];
    uint32_t n;
    uint32_t _pad0;
    uint32_t _pad1;
    uint32_t _pad2;
} LuxMagnetarXmssSubtreeElem;

// FIPS 205 §11.2 SHAKE H_msg element.
//   SHAKE256(r || pk_seed || pk_root || msg)[:digest_len].
typedef struct {
    uint32_t r_off;         // byte offset into r_pool (reads n bytes)
    uint32_t pk_seed_off;   // byte offset into pk_seed_pool (reads n bytes)
    uint32_t pk_root_off;   // byte offset into pk_root_pool (reads n bytes)
    uint32_t msg_off;       // byte offset into msg_pool
    uint32_t msg_len;       // bytes
    uint32_t digest_len;    // m bytes (≤ 47 for SLH-DSA-SHAKE)
    uint32_t n;
    uint32_t _pad;
} LuxMagnetarHmsgElem;

// FIPS 205 §11.2 SHAKE PRF_msg element.
//   SHAKE256(sk_prf || opt_rand || msg)[:out_len].
typedef struct {
    uint32_t sk_prf_off;
    uint32_t opt_rand_off;
    uint32_t msg_off;
    uint32_t msg_len;
    uint32_t out_len;       // bytes (n for SLH-DSA-SHAKE)
    uint32_t n;
    uint32_t _pad0;
    uint32_t _pad1;
} LuxMagnetarPrfmsgElem;

// =============================================================================
// Error Codes
// =============================================================================

typedef enum {
    LUX_CRYPTO_OK                  = 0,
    LUX_CRYPTO_ERROR_INVALID_ARG   = 1,
    LUX_CRYPTO_ERROR_OUT_OF_MEMORY = 2,
    LUX_CRYPTO_ERROR_NOT_SUPPORTED = 3,
    LUX_CRYPTO_ERROR_INVALID_CURVE = 4,
    LUX_CRYPTO_ERROR_INVALID_POINT = 5,
    LUX_CRYPTO_ERROR_DEVICE_ERROR  = 6,
} LuxCryptoError;

#ifdef __cplusplus
}
#endif

#endif // LUX_GPU_CRYPTO_H
