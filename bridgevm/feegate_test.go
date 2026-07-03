// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"errors"
	"testing"

	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
)

// newBridgeVMWithPolicy wires a VM with the canonical FlatPolicy
// directly, bypassing the full Initialize (which requires the M-Chain
// custody keygen handshake, 1M LUX bond validation, etc.).
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

// The fee gate (LP-0130 §8) refuses a zero-fee bridge transfer before any
// M-Chain signing capacity is consumed.
func TestBridgeVM_FeeGate_RejectsZeroFee(t *testing.T) {
	v := newBridgeVMWithPolicy(96369)
	if err := v.gateUserBridgeFee(0); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("gateUserBridgeFee(0) = %v, want ErrInsufficientFee", err)
	}
}

func TestBridgeVM_FeeGate_AcceptsMinFee(t *testing.T) {
	v := newBridgeVMWithPolicy(96369)
	if err := v.gateUserBridgeFee(fee.MinTxFeeFloor); err != nil {
		t.Fatalf("gateUserBridgeFee(min) = %v, want nil", err)
	}
}

// Custody group key is nil until M-Chain completes dealerless keygen —
// B-Chain never generates key material itself.
func TestBridgeVM_NoLocalCustodyKey(t *testing.T) {
	v := newBridgeVMWithPolicy(96369)
	if key := v.mpcGroupPublicKey(); key != nil {
		t.Fatalf("mpcGroupPublicKey() = %x, want nil (no B-Chain keygen)", key)
	}
}
