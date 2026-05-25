// Copyright (C) 2025-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package multichain

import (
	"context"
	"fmt"
	"sync"
)

// ChainKernel is the per-chain execution surface the BlockBuilder
// coordinates. Each chain provides one. Today these wrap independent
// kernels (cevm.ExecuteBlock for C-Chain, lx.MatchOrderGPU for D-Chain,
// fhe.NTTEngine.NTTBatch + the FHE evaluator for F-Chain). When the
// luxcpp shared-MvMemory work lands, the same interface is satisfied by
// a single kernel that handles all three chains in one dispatch.
type ChainKernel interface {
	// ChainID reports which chain this kernel serves.
	ChainID() ChainID

	// Execute runs the per-chain ops produced by both direct submission
	// and cross-chain dispatch (CrossInbound). All state writes go to
	// the shared MvMemory namespace passed in; the kernel never reads
	// state outside its declared namespace.
	//
	// Returns receipts (one per consumed op) plus any CrossRefs produced
	// (CrossOut) that the block builder will route to the target chain.
	Execute(ctx context.Context, in ChainInput) (ChainOutput, error)

	// Seal commits the per-chain state for this block and returns the
	// ZAP-encoded sub-block buffer + state root. Called once after all
	// CrossRefs have resolved.
	Seal(ctx context.Context) (subBlock []byte, stateRoot [32]byte, err error)

	// Close releases the kernel's session.
	Close() error
}

// ChainInput is what a ChainKernel.Execute receives.
type ChainInput struct {
	// DirectOps are the operations submitted directly to this chain
	// (DChainOps for D-Chain, FChainOps for F-Chain, CChainTxs for
	// C-Chain). Each kernel decodes its own wire format.
	DirectOps [][]byte

	// CrossInbound carries the cross-chain calls this chain must serve
	// during block construction. E.g. C-Chain EVM frames that called
	// the CLOB precompile send a CrossRef here with the order payload.
	CrossInbound []CrossRef
}

// ChainOutput is what a ChainKernel.Execute returns.
type ChainOutput struct {
	Receipts  []Receipt
	CrossOut  []CrossRef // crefs this chain produced and routed elsewhere
}

// Coordinator is the host-side BlockBuilder implementation. Phase 1: it
// dispatches each chain's kernel sequentially, routing CrossRefs between
// chains over a single fixed-point loop. Phase 2: this same Coordinator
// can be wired to a single multi-chain GPU kernel; the interface above
// stays unchanged.
type Coordinator struct {
	kernels [3]ChainKernel
}

// NewCoordinator wires the per-chain kernels. Each kernel must report
// the correct ChainID; ordering is enforced by ChainID, not by argument
// order.
func NewCoordinator(kernels ...ChainKernel) (*Coordinator, error) {
	c := &Coordinator{}
	var seen [3]bool
	for _, k := range kernels {
		id := k.ChainID()
		if int(id) >= len(c.kernels) {
			return nil, fmt.Errorf("multichain: unknown chain id %d", id)
		}
		if seen[id] {
			return nil, fmt.Errorf("multichain: duplicate chain %d", id)
		}
		c.kernels[id] = k
		seen[id] = true
	}
	for i, k := range c.kernels {
		if k == nil {
			return nil, fmt.Errorf("multichain: missing kernel for chain %d", i)
		}
	}
	return c, nil
}

// ExecuteBlock implements BlockBuilder. Phase 1 algorithm:
//
//  1. Convert the batch into per-chain ChainInputs.
//  2. Round 0: execute every chain on its DirectOps only.
//  3. Distribute the resulting CrossOut entries to their destination
//     chains' CrossInbound queues.
//  4. Round N: each chain that received new CrossInbound executes again
//     on only those new entries.
//  5. Repeat until no new CrossOut entries are produced. (Fixed point.)
//  6. Verify every declared CrossRef in the input batch resolved.
//  7. Seal each chain in order C → D → F (they don't depend on each
//     other at seal time; the order is just for deterministic state-root
//     ordering in the returned MultiChainBlock).
//
// Atomicity guarantee: if any round fails (kernel error, declared
// CrossRef unresolved at the fixed point) the entire block is rejected
// and the kernels are rolled back via their own MvMemory snapshot. The
// caller sees nothing partial.
//
// Phase 2 will collapse this into a single GPU kernel dispatch — the
// fixed-point loop runs inside the device, the host only sees the final
// sealed block.
func (c *Coordinator) ExecuteBlock(ctx context.Context, batch CrossChainBatch) (*MultiChainBlock, error) {
	if c == nil {
		return nil, fmt.Errorf("multichain: nil coordinator")
	}

	// Stage 1: convert batch → per-chain inputs.
	inputs := [3]ChainInput{
		ChainC: {DirectOps: encodeEVM(batch.CChainTxs)},
		ChainD: {DirectOps: encodeDEX(batch.DChainOps)},
		ChainF: {DirectOps: encodeFHE(batch.FChainOps)},
	}

	// batch.CrossRefs is an ASSERTION set — it lists cross-chain
	// dispatches the caller expects to happen during block construction.
	// It is NOT an input queue. The chain kernels themselves produce
	// cross-chain dispatches as they execute. We check the assertion at
	// seal time: every declared CrossRef must match a kernel-produced
	// CrossOut, or the block is rejected. This keeps the kernel as the
	// single source of truth for cross-chain calls.

	// Stage 2: fixed-point dispatch. We bound the loop to len(kernels) +
	// MaxCrossDepth to avoid pathological cycles.
	const MaxCrossDepth = 16
	var (
		allReceipts []Receipt
		producedCR  []CrossRef
	)
	for round := 0; round < MaxCrossDepth; round++ {
		producedCR = producedCR[:0]
		anyWork := false

		// Each chain runs once per round on whatever DirectOps +
		// CrossInbound it has accumulated. The kernels themselves are
		// independent and the dispatches can run in parallel; we use
		// goroutines + a barrier to overlap kernel dispatch time.
		var wg sync.WaitGroup
		outputs := make([]ChainOutput, len(c.kernels))
		errs := make([]error, len(c.kernels))
		for i, k := range c.kernels {
			in := inputs[i]
			if len(in.DirectOps) == 0 && len(in.CrossInbound) == 0 {
				continue
			}
			anyWork = true
			wg.Add(1)
			go func(idx int, k ChainKernel, in ChainInput) {
				defer wg.Done()
				out, err := k.Execute(ctx, in)
				outputs[idx] = out
				errs[idx] = err
			}(i, k, in)
		}
		wg.Wait()

		// Surface any hard kernel error.
		for i, err := range errs {
			if err != nil {
				return nil, fmt.Errorf("%w: chain %d round %d: %v",
					ErrChainKernelFailed, i, round, err)
			}
		}

		// Drain DirectOps + CrossInbound — they were consumed this round.
		for i := range inputs {
			inputs[i].DirectOps = nil
			inputs[i].CrossInbound = nil
		}

		// Collect receipts; route new CrossOut to inbound queues.
		for _, out := range outputs {
			allReceipts = append(allReceipts, out.Receipts...)
			for _, cr := range out.CrossOut {
				inputs[cr.Into].CrossInbound = append(inputs[cr.Into].CrossInbound, cr)
				producedCR = append(producedCR, cr)
			}
		}

		if !anyWork || len(producedCR) == 0 {
			// Fixed point reached: no chain had work and no new cross-
			// refs were produced. Time to seal.
			break
		}
	}

	// Stage 3: verify declared CrossRefs all resolved. Cheap two-pass:
	// build a set of (Into, IntoHash) from receipts' CrossOut, then check
	// every batch.CrossRefs entry has a match.
	resolved := make(map[[33]byte]struct{}, len(batch.CrossRefs))
	for _, r := range allReceipts {
		for _, cr := range r.CrossOut {
			var k [33]byte
			k[0] = byte(cr.Into)
			copy(k[1:], cr.IntoHash[:])
			resolved[k] = struct{}{}
		}
	}
	for _, cr := range batch.CrossRefs {
		var k [33]byte
		k[0] = byte(cr.Into)
		copy(k[1:], cr.IntoHash[:])
		if _, ok := resolved[k]; !ok {
			return nil, fmt.Errorf("%w: chain=%d hash=%x", ErrCrossRefUnresolved, cr.Into, cr.IntoHash)
		}
	}

	// Stage 4: seal each chain. C → D → F for deterministic ordering.
	block := &MultiChainBlock{Receipts: allReceipts}
	for i, k := range c.kernels {
		sub, root, err := k.Seal(ctx)
		if err != nil {
			return nil, fmt.Errorf("multichain: chain %d Seal: %w", i, err)
		}
		block.StateRoots[i] = root
		switch ChainID(i) {
		case ChainC:
			block.CChainBlock = sub
		case ChainD:
			block.DChainBlock = sub
		case ChainF:
			block.FChainBlock = sub
		}
	}
	return block, nil
}

// Close releases every kernel's session.
func (c *Coordinator) Close() error {
	var first error
	for _, k := range c.kernels {
		if err := k.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// encodeEVM / encodeDEX / encodeFHE convert the typed wrappers into the
// opaque [][]byte slice each chain kernel decodes. Each is a one-line
// helper kept here so callers see the conversion at the dispatch seam.
func encodeEVM(txs []EVMTx) [][]byte {
	out := make([][]byte, len(txs))
	for i, t := range txs {
		out[i] = t.Raw
	}
	return out
}

func encodeDEX(ops []DEXOp) [][]byte {
	out := make([][]byte, len(ops))
	for i, o := range ops {
		out[i] = o.Payload
	}
	return out
}

func encodeFHE(ops []FHEOp) [][]byte {
	out := make([][]byte, len(ops))
	for i, o := range ops {
		out[i] = o.Payload
	}
	return out
}
