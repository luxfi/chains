// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package quantumvm

import (
	"errors"
	"testing"
	"time"

	"github.com/luxfi/chains/quantumvm/quantum"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/node/vms/types/fee"
)

// feeTestTx implements the Q-Chain Transaction interface with a
// configurable fee and a pre-set valid signature so .Verify() passes.
type feeTestTx struct {
	id  ids.ID
	fee uint64
}

func (t *feeTestTx) ID() ids.ID                                   { return t.id }
func (t *feeTestTx) Bytes() []byte                                { return t.id[:] }
func (t *feeTestTx) Verify() error                                { return nil }
func (t *feeTestTx) Execute() error                               { return nil }
func (t *feeTestTx) GetQuantumSignature() *quantum.QuantumSignature { return &quantum.QuantumSignature{} }
func (t *feeTestTx) Timestamp() time.Time                         { return time.Unix(0, 0) }
func (t *feeTestTx) Fee() uint64                                  { return t.fee }

// newQuantumVMWithPolicy wires a VM with the canonical FlatPolicy
// directly, bypassing the full Initialize (which requires Quasar
// bridge setup, quantum signer pool, etc.).
func newQuantumVMWithPolicy(networkID uint32) *VM {
	v := &VM{log: log.NewNoOpLogger()}
	v.NetworkID = networkID
	v.feePolicy = newFeePolicy(networkID)
	v.txPool = NewTransactionPool(8, 8, v.log)
	return v
}

func TestQuantumVM_FeePolicy_AttachedAtInit(t *testing.T) {
	v := newQuantumVMWithPolicy(96369)
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

func TestQuantumVM_IssueTx_RejectsZeroFee(t *testing.T) {
	v := newQuantumVMWithPolicy(96369)
	tx := &feeTestTx{id: ids.GenerateTestID(), fee: 0}
	if err := v.IssueTx(tx); !errors.Is(err, fee.ErrInsufficientFee) {
		t.Fatalf("IssueTx(zero-fee) = %v, want ErrInsufficientFee", err)
	}
}

func TestQuantumVM_IssueTx_AcceptsMinFee(t *testing.T) {
	v := newQuantumVMWithPolicy(96369)
	tx := &feeTestTx{id: ids.GenerateTestID(), fee: fee.MinTxFeeFloor}
	if err := v.IssueTx(tx); err != nil {
		t.Fatalf("IssueTx(min-fee) = %v, want nil", err)
	}
}
