// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package identityvm

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

func newIdentityVMForFeeTest(t *testing.T) *VM {
	t.Helper()
	logger := log.NewNoOpLogger()
	rt := &runtime.Runtime{
		ChainID:   ids.GenerateTestID(),
		NetworkID: 96369,
		Log:       logger,
	}
	v := &VM{}
	if err := v.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  []byte(`{"timestamp":0,"issuers":[],"identities":[]}`),
	}); err != nil {
		t.Fatalf("init identityvm: %v", err)
	}
	return v
}

func TestIdentityVM_FeePolicy_AttachedAtInit(t *testing.T) {
	v := newIdentityVMForFeeTest(t)
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

func TestIdentityVM_FeePolicy_RejectsZeroFee(t *testing.T) {
	v := newIdentityVMForFeeTest(t)
	if err := v.gateUserFee(0); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("gateUserFee(0) = %v, want ErrInsufficientFee", err)
	}
}

func TestIdentityVM_FeePolicy_AcceptsMinFee(t *testing.T) {
	v := newIdentityVMForFeeTest(t)
	if err := v.gateUserFee(fee.MinTxFeeFloor); err != nil {
		t.Fatalf("gateUserFee(MinTxFeeFloor) = %v, want nil", err)
	}
}

// Service-level test: mutating RPCs refuse zero-fee calls before any
// state is allocated. We test CreateIdentity here as the canonical
// example; the other mutating RPCs (IssueCredential,
// RevokeCredential, CreateProof, RegisterIssuer) follow the same
// pattern.
func TestIdentityVM_Service_CreateIdentity_RejectsZeroFee(t *testing.T) {
	v := newIdentityVMForFeeTest(t)
	s := &Service{vm: v}
	req, _ := http.NewRequest(http.MethodPost, "/", nil)
	reply := &CreateIdentityReply{}
	err := s.CreateIdentity(req, &CreateIdentityArgs{PublicKey: "", Fee: 0}, reply)
	if !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("Service.CreateIdentity(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}
