// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

//go:build !cgo || !lux_cevm_native

// Pure-Go path for the batch sig primitive, used whenever the native
// luxcpp crypto is NOT linked in — the default build (cgo without
// `-tags=lux_cevm_native`) and any no-cgo build.

package cevm

import (
	"fmt"

	"github.com/luxfi/geth/common"
	"github.com/luxfi/geth/core/types"
)

// BatchRecoverSenders returns an error under !cgo: the GPU sig-batch
// primitive lives in the C++ luxcpp/crypto library and there is no Go
// equivalent in this package. Callers should fall back to per-tx
// types.Sender when this returns an error.
func BatchRecoverSenders(txs types.Transactions, signer types.Signer) ([]common.Address, error) {
	if len(txs) == 0 {
		return nil, nil
	}
	_ = signer
	return nil, fmt.Errorf("cevm: BatchRecoverSenders requires CGO_ENABLED=1 -tags=lux_cevm_native (libsecp256k1_cpu)")
}
