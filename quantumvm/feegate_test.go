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

func (t *feeTestTx) ID() ids.ID                                     { return t.id }
func (t *feeTestTx) Bytes() []byte                                  { return t.id[:] }
func (t *feeTestTx) Verify() error                                  { return nil }
func (t *feeTestTx) Execute() error                                 { return nil }
func (t *feeTestTx) GetQuantumSignature() *quantum.QuantumSignature { return &quantum.QuantumSignature{} }
func (t *feeTestTx) Timestamp() time.Time                           { return time.Unix(0, 0) }
func (t *feeTestTx) Fee() uint64                                    { return t.fee }

// newQuantumVMWithPolicy wires a VM with the canonical policy directly,
// bypassing the full Initialize (which requires Quasar bridge setup,
// quantum signer pool, etc.).
func newQuantumVMWithPolicy(networkID uint32) *VM {
	v := &VM{log: log.NewNoOpLogger()}
	v.NetworkID = networkID
	v.feePolicy = newFeePolicy(networkID)
	v.txPool = NewTransactionPool(8, 8, v.log)
	return v
}

// LP-0130 §6: Q-Chain has no user-payable blockspace. The policy is the
// committee-only sentinel and the boot-time Validate gate accepts it.
func TestQuantumVM_FeePolicy_IsNoUserTxSentinel(t *testing.T) {
	v := newQuantumVMWithPolicy(96369)
	if v.FeePolicy() == nil {
		t.Fatal("FeePolicy() = nil; want NoUserTxPolicy sentinel")
	}
	if _, ok := v.FeePolicy().(fee.NoUserTxPolicy); !ok {
		t.Fatalf("FeePolicy() = %T, want fee.NoUserTxPolicy (LP-0130 §6)", v.FeePolicy())
	}
	if err := fee.Validate(v.FeePolicy()); err != nil {
		t.Errorf("fee.Validate = %v, want nil", err)
	}
}

// Every user tx is refused regardless of fee paid — including a tx that
// pays the floor other chains would accept. Finality is a validator
// obligation, never purchasable blockspace.
func TestQuantumVM_IssueTx_RejectsAllUserTx(t *testing.T) {
	v := newQuantumVMWithPolicy(96369)
	for _, paid := range []uint64{0, fee.MinTxFeeFloor, fee.MinTxFeeFloor * 1000} {
		tx := &feeTestTx{id: ids.GenerateTestID(), fee: paid}
		if err := v.IssueTx(tx); !errors.Is(err, fee.ErrChainAcceptsNoUserTxs) {
			t.Fatalf("IssueTx(fee=%d) = %v, want ErrChainAcceptsNoUserTxs", paid, err)
		}
	}
}
