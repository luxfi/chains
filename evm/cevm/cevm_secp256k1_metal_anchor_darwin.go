// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build cgo && darwin

package cevm

/*
#include <stddef.h>

extern void* const lux_secp256k1_metal_anchor;

static inline void* lux_secp256k1_metal_anchor_keep(void) {
    return lux_secp256k1_metal_anchor;
}
*/
import "C"

// metalAnchorAddr keeps the anchor + Metal driver symbol alive through
// linker DCE. See cpp/ecrecover.cpp for the dispatch logic.
var metalAnchorAddr = C.lux_secp256k1_metal_anchor_keep()

func init() {
	if metalAnchorAddr == nil {
		_ = metalAnchorAddr
	}
}
