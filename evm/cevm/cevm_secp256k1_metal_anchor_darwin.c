// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Anchor for the secp256k1 Metal driver symbol. See cpp/ecrecover.cpp in
// luxcpp/crypto for the dispatch logic that resolves this symbol via dlsym.

#include <stddef.h>
#include <stdint.h>

extern int secp256k1_ecrecover_address_batch_metal(
    const uint8_t* inputs, size_t n,
    uint8_t* out_addr, uint8_t* out_st, const char* metallib_path);

void* const lux_secp256k1_metal_anchor =
    (void*)&secp256k1_ecrecover_address_batch_metal;
