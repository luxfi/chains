// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"errors"
	"testing"

	"github.com/luxfi/chains/chain"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
)

func TestThresholdVM_FeePolicy_IsNoUserTxSentinel(t *testing.T) {
	v := &VM{log: log.NewNoOpLogger(), fee: chain.Closed()}
	if v.FeePolicy() == nil {
		t.Fatal("FeePolicy() = nil; want NoUserTxPolicy")
	}
	if _, ok := v.FeePolicy().(fee.NoUserTxPolicy); !ok {
		t.Fatalf("FeePolicy() = %T, want NoUserTxPolicy", v.FeePolicy())
	}
	if err := fee.Validate(v.FeePolicy()); err != nil {
		t.Errorf("fee.Validate(NoUserTxPolicy) = %v, want nil", err)
	}
}

func TestThresholdVM_FeePolicy_RejectsAllUserTx(t *testing.T) {
	v := &VM{log: log.NewNoOpLogger(), fee: chain.Closed()}
	if err := v.gateUserTx(); !errors.Is(err, fee.ErrChainAcceptsNoUserTxs) {
		t.Fatalf("gateUserTx() = %v, want ErrChainAcceptsNoUserTxs", err)
	}
}
