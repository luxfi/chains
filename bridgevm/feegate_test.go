// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
)

// newBridgeVMWithPolicy wires a VM with the canonical FlatPolicy
// directly, bypassing the full Initialize (which requires MPC
// keygen, 1M LUX bond validation, etc.).
func newBridgeVMWithPolicy(networkID uint32) *VM {
	v := &VM{log: log.NewNoOpLogger()}
	v.networkID = networkID
	v.feePolicy = newFeePolicy(networkID)
	return v
}

func TestBridgeVM_FeePolicy_AttachedAtInit(t *testing.T) {
	v := newBridgeVMWithPolicy(96369)
	if v.FeePolicy() == nil {
		t.Fatal("FeePolicy() = nil; want non-nil FlatPolicy")
	}
	if got := v.FeePolicy().MinTxFee(); got != fee.MinTxFeeFloor {
		t.Errorf("MinTxFee() = %d, want %d", got, fee.MinTxFeeFloor)
	}
	if err := fee.Validate(v.FeePolicy()); err != nil {
		t.Errorf("fee.Validate = %v, want nil", err)
	}
}

func TestBridgeVM_FeePolicy_RejectsZeroFee(t *testing.T) {
	v := newBridgeVMWithPolicy(96369)
	msg := &BridgeMessage{ID: ids.GenerateTestID(), Fee: 0}
	if err := v.gateUserBridgeMessage(msg); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("gateUserBridgeMessage(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}

func TestBridgeVM_FeePolicy_AcceptsMinFee(t *testing.T) {
	v := newBridgeVMWithPolicy(96369)
	msg := &BridgeMessage{ID: ids.GenerateTestID(), Fee: fee.MinTxFeeFloor}
	if err := v.gateUserBridgeMessage(msg); err != nil {
		t.Fatalf("gateUserBridgeMessage(min-fee) = %v, want nil", err)
	}
}

// InitiateBridgeTransfer must reject zero-fee messages at the gate
// before any MPC signing capacity (signerSet read, signer share
// creation) is exercised. We feed a zero-fee message and assert on
// ErrInsufficientFee without standing up the MPC pipeline.
func TestBridgeVM_InitiateBridgeTransfer_RejectsZeroFee(t *testing.T) {
	v := newBridgeVMWithPolicy(96369)
	msg := &BridgeMessage{ID: ids.GenerateTestID(), Fee: 0}
	err := v.InitiateBridgeTransfer(context.Background(), msg)
	if !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("InitiateBridgeTransfer(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}
