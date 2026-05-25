// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package multichain

import (
	"context"
	"testing"
)

// fakeKernel is a deterministic in-memory ChainKernel for tests. It
// echoes back one receipt per DirectOp, propagates CrossInbound as
// receipt cross-outs, and seals to a constant root.
type fakeKernel struct {
	id           ChainID
	seenDirect   int
	seenInbound  int
	produceCRTo  []ChainID // CrossOut targets to fan out to (per direct op)
	closed       bool
}

func (k *fakeKernel) ChainID() ChainID { return k.id }

func (k *fakeKernel) Execute(_ context.Context, in ChainInput) (ChainOutput, error) {
	k.seenDirect += len(in.DirectOps)
	k.seenInbound += len(in.CrossInbound)

	out := ChainOutput{}
	for i := range in.DirectOps {
		r := Receipt{Chain: k.id, Status: 0, GasUsed: 21000}
		// Fan out one cross-ref per declared target per direct op.
		for _, target := range k.produceCRTo {
			cr := CrossRef{
				From: k.id, FromHash: [32]byte{byte(i + 1)},
				Into: target, IntoHash: [32]byte{byte(i + 1)},
			}
			out.CrossOut = append(out.CrossOut, cr)
			r.CrossOut = append(r.CrossOut, cr)
		}
		out.Receipts = append(out.Receipts, r)
	}
	for i, cr := range in.CrossInbound {
		// Inbound cross-refs land as a "service" receipt on this chain.
		out.Receipts = append(out.Receipts, Receipt{
			Chain: k.id, Status: 0, GasUsed: 5000,
			TxHash: [32]byte{0xCC, byte(i)},
			CrossOut: []CrossRef{cr}, // record resolution
		})
	}
	return out, nil
}

func (k *fakeKernel) Seal(_ context.Context) ([]byte, [32]byte, error) {
	return []byte{byte(k.id)}, [32]byte{byte(k.id), 0xFF}, nil
}

func (k *fakeKernel) Close() error { k.closed = true; return nil }

func newTestCoordinator(crFromC []ChainID, crFromD []ChainID, crFromF []ChainID) (*Coordinator, error) {
	return NewCoordinator(
		&fakeKernel{id: ChainC, produceCRTo: crFromC},
		&fakeKernel{id: ChainD, produceCRTo: crFromD},
		&fakeKernel{id: ChainF, produceCRTo: crFromF},
	)
}

func TestCoordinator_StandaloneChains(t *testing.T) {
	// Each chain has its own DirectOps, no cross-refs. One dispatch round,
	// one receipt per op, three sealed sub-blocks.
	c, err := newTestCoordinator(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	batch := CrossChainBatch{
		CChainTxs: []EVMTx{{Raw: []byte("evm1")}, {Raw: []byte("evm2")}},
		DChainOps: []DEXOp{{Kind: DEXOpPlaceLimit, Payload: []byte("dex1")}},
		FChainOps: []FHEOp{{Kind: FHEOpAdd, Payload: []byte("fhe1")}},
	}
	block, err := c.ExecuteBlock(context.Background(), batch)
	if err != nil {
		t.Fatalf("ExecuteBlock: %v", err)
	}
	if len(block.Receipts) != 4 {
		t.Errorf("receipts=%d want 4", len(block.Receipts))
	}
	if block.CChainBlock == nil || block.DChainBlock == nil || block.FChainBlock == nil {
		t.Errorf("missing sub-block in MultiChainBlock")
	}
}

func TestCoordinator_CrossChainEVMtoDEX(t *testing.T) {
	// C-Chain emits one cross-ref per tx → D-Chain. D-Chain consumes them
	// in round 2 and produces resolution receipts. F-Chain has no work.
	c, err := newTestCoordinator(
		[]ChainID{ChainD}, // C-Chain → D-Chain
		nil,
		nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	batch := CrossChainBatch{
		CChainTxs: []EVMTx{{Raw: []byte("call_clob_1")}, {Raw: []byte("call_clob_2")}},
		CrossRefs: []CrossRef{
			{From: ChainC, FromHash: [32]byte{1}, Into: ChainD, IntoHash: [32]byte{1}},
			{From: ChainC, FromHash: [32]byte{2}, Into: ChainD, IntoHash: [32]byte{2}},
		},
	}
	block, err := c.ExecuteBlock(context.Background(), batch)
	if err != nil {
		t.Fatalf("ExecuteBlock: %v", err)
	}
	// 2 C-Chain receipts + 2 D-Chain service receipts (one per inbound CR).
	if len(block.Receipts) != 4 {
		t.Errorf("receipts=%d want 4 (got: %+v)", len(block.Receipts), block.Receipts)
	}
}

func TestCoordinator_CrossRefUnresolved(t *testing.T) {
	// Caller declares a CrossRef the kernel won't produce. Block must
	// reject with ErrCrossRefUnresolved — no partial commit allowed.
	c, err := newTestCoordinator(nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	batch := CrossChainBatch{
		CChainTxs: []EVMTx{{Raw: []byte("evm1")}},
		CrossRefs: []CrossRef{
			{From: ChainC, FromHash: [32]byte{99}, Into: ChainD, IntoHash: [32]byte{99}},
		},
	}
	_, err = c.ExecuteBlock(context.Background(), batch)
	if err == nil {
		t.Fatal("expected ErrCrossRefUnresolved, got nil")
	}
}

func TestCoordinator_MissingKernel(t *testing.T) {
	_, err := NewCoordinator(
		&fakeKernel{id: ChainC},
		&fakeKernel{id: ChainD},
		// no F kernel
	)
	if err == nil {
		t.Fatal("expected error for missing F-Chain kernel")
	}
}
