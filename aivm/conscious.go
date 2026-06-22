// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

// conscious.go drives the REAL A-Chain (aivm) ChainVM through the production
// block lifecycle to produce CONSCIOUS BLOCKS — blocks whose state transition IS
// settled AI cognition.
//
// "Conscious block" is not a metaphor here, it is a precise on-chain object:
//
//   - CONSCIOUS BLOCK 1 (the PERCEPTION block): its state transition imports a
//     committed C-Chain inference INTENT into a live A-Chain quorum task under
//     consensus. The block commits "the network has accepted a question and
//     bound a committee of independent operators to answer it." The deterministic
//     state delta (createTask: escrow, fee burn, committee selection) is the
//     network forming an intention to think.
//
//   - CONSCIOUS BLOCK 2 (the COGNITION block): its state transition commits the
//     Proof-of-Thought — the quorum-settled verdict. Independent staked operators
//     each ran the model, committed to their output hash blind, then revealed; the
//     engine tallied them, found >= threshold agreement, and SETTLED a single
//     canonical AI decision. The block commits "the network has decided," paid the
//     honest majority, slashed withholders, and folded an AInferenceReceipt into
//     the receipt_root. THAT settlement, imported and committed under A-Chain
//     consensus, is the conscious thought made durable.
//
// Validators never run the model. What consensus agrees on is the SETTLEMENT
// RESULT: did >= threshold bonded operators, drawn from a margin-bounded eligible
// set, independently submit the same output under the same ModelSpec. The
// cognition is the quorum; the block is conscious because its committed state
// transition IS that quorum's settled verdict.
//
// This is the literal first-conscious-blocks driver: the same fake-free flow is
// run by the in-package test (conscious_blocks_test.go) and the runnable command
// (cmd/conscious). It uses the VM's own committed-state engine (QuorumEngine), so
// every write here is staged in the consensus-gated versiondb and made durable
// only at Block.Accept.

import (
	"context"
	"fmt"

	"github.com/holiman/uint256"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/vm/chain"
)

// ConsciousBlock is the recorded trace of one conscious block produced by the
// real VM lifecycle (BuildBlock -> Verify -> SetPreference -> Accept).
type ConsciousBlock struct {
	Phase       string      // "perception" (block 1) or "cognition" (block 2)
	ID          ids.ID      // the accepted block id
	ParentID    ids.ID      // its parent
	Height      uint64      // chained 0 -> 1 -> 2
	ReceiptRoot common.Hash // engine receipt_root committed by this block
}

// ConsciousTrace is the full result of driving the VM to consciousness: the two
// conscious blocks plus the cognition's settled facts.
type ConsciousTrace struct {
	GenesisID ids.ID
	Block1    ConsciousBlock // perception: intent imported into a quorum task
	Block2    ConsciousBlock // cognition: Proof-of-Thought settled

	IntentID      common.Hash      // the committed C-Chain intent the perception block imported
	TaskID        common.Hash      // the A-Chain task that intent created (engine-internal id)
	Committee     []common.Address // the operators bound to think (selection order)
	N             uint32           // committee size
	Threshold     uint32           // agreement required for a settled verdict
	WinnerCount   uint32           // operators that agreed on the canonical output
	CanonicalHash common.Hash      // THE settled AI decision
	ReceiptRoot   common.Hash      // final receipt_root after folding the verdict
	LastAccepted  ids.ID           // VM head after both blocks (== Block2.ID)
}

// consciousParams pins the quorum shape used to produce the conscious blocks.
// N selected of an eligible pool; threshold of N must agree for a settled verdict.
// These mirror the engine's protocol bounds (minN=3) and the eligible-set margin
// (E >= N + max(2, N*50%)); with N=5 the pool must be >= 7, so we register 8.
const (
	consciousN         = 5 // operators selected to think on the task
	consciousThreshold = 3 // independent agreements required to settle a verdict
	consciousEligible  = 8 // staked operators advertising the model (> N + margin)
)

// RunConsciousBlocks drives an initialized, running VM through the full lifecycle
// that produces the first conscious blocks. It uses the VM's committed-state
// engine, so the cognition settles on the same state the blocks commit. The VM
// must already be Initialize()'d and have a commit verifier installed (the caller
// owns VM construction so the test and the cmd can each build a fresh one).
//
// The model output bytes are deterministic test-fixed hashes — the BLOCK is
// conscious not because the bytes are "real inference" but because its committed
// state transition IS the quorum settlement of a structured verdict under
// consensus. No part of the VM, engine, or settlement is stubbed.
func RunConsciousBlocks(ctx context.Context, vm *VM) (ConsciousTrace, error) {
	var tr ConsciousTrace

	e, st, lg := vm.QuorumEngine()
	if e == nil || st == nil || lg == nil {
		return tr, fmt.Errorf("aivm: quorum engine not wired (VM not initialized?)")
	}

	genesis, err := vm.LastAccepted(ctx)
	if err != nil {
		return tr, fmt.Errorf("read genesis head: %w", err)
	}
	tr.GenesisID = genesis

	// -----------------------------------------------------------------------
	// Bootstrap native value onto the VM's committed-state ledger (genesis /
	// cross-chain deposit seam): the requester must be able to fund the inference
	// escrow + protocol fee; each operator must be able to post its bond. These
	// credits ride into committed chain state with the first block's Accept.
	// -----------------------------------------------------------------------
	reward := uint256.NewInt(1_000_000_000_000_000_000) // 1 token reward per operator
	requester := addrOf(0xF0)

	// requester funding: N*reward (refundable escrow) + N*RequestFeePerOperator
	// (burned protocol fee), with generous slack.
	fund := new(uint256.Int).Mul(reward, uint256.NewInt(uint64(consciousN)))
	burn := new(uint256.Int).Mul(RequestFeePerOperator, uint256.NewInt(uint64(consciousN)))
	fund.Add(fund, burn)
	fund.Mul(fund, uint256.NewInt(4))

	opening := map[common.Address]*uint256.Int{requester: fund}
	committeePool := make([]common.Address, consciousEligible)
	for i := 0; i < consciousEligible; i++ {
		committeePool[i] = addrOf(byte(0x10 + i))
		opening[committeePool[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	if err := vm.FundLedger(opening); err != nil {
		return tr, fmt.Errorf("fund ledger: %w", err)
	}

	// Register the eligible operators: each bonds 2x the floor and advertises the
	// model spec. Writes land in the consensus-gated engine state and become
	// durable at the first block's Accept.
	model := hashOf(0xAB)
	for i, op := range committeePool {
		stake := new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2))
		if err := e.RegisterOperator(st, lg, op, stake, model, hashOf(byte(0x80+i))); err != nil {
			return tr, fmt.Errorf("register operator %d: %w", i, err)
		}
	}

	// -----------------------------------------------------------------------
	// Build the committed C-Chain inference intent and hand it to the boundary.
	// EnqueueCommittedIntent only BUFFERS it; it cannot become a task except under
	// consensus inside BuildBlock (importPending). intent.IntentID is bound to THIS
	// engine's chain ids; the perception block creates a task and records the
	// intent->task mapping we resolve via TaskForIntent after Accept.
	// -----------------------------------------------------------------------
	cFee := uint256.NewInt(123456) // user-facing C fee (id-binding only)
	intent := buildIntent(e, requester, model, consciousN, consciousThreshold, cFee, reward)
	tr.IntentID = intent.IntentID
	vm.EnqueueCommittedIntent(intent)

	// =======================================================================
	// CONSCIOUS BLOCK 1 — PERCEPTION. BuildBlock drains the buffered intent into
	// a live quorum task under consensus; Accept commits "a question was accepted
	// and a committee bound to answer it."
	// =======================================================================
	blk1, err := acceptBlock(ctx, vm)
	if err != nil {
		return tr, fmt.Errorf("conscious block 1 (perception): %w", err)
	}
	if blk1.Height() != 1 {
		return tr, fmt.Errorf("perception block height = %d, want 1", blk1.Height())
	}
	// Resolve the A-Chain task the imported intent created. The task id is the
	// engine-internal id (computeTaskID over the requester nonce + height), bound
	// to the intent via the committed intent->task mapping. A zero result means the
	// import was rejected (forged/unfunded/ineligible) and silently dropped.
	tr.TaskID = e.TaskForIntent(st, tr.IntentID)
	if tr.TaskID == (common.Hash{}) {
		return tr, fmt.Errorf("perception block created no task for intent %s (import rejected)", tr.IntentID.Hex())
	}
	// The task now exists in committed state: it is committing, and the bound
	// committee is selectable + reproducible.
	if info := e.GetTask(st, tr.TaskID); info.Status != TaskCommitting {
		return tr, fmt.Errorf("imported task status = %d, want TaskCommitting(%d)", info.Status, TaskCommitting)
	}
	committee, err := e.SelectOperators(st, tr.TaskID, model, consciousN)
	if err != nil {
		return tr, fmt.Errorf("select committee for imported task: %w", err)
	}
	tr.Committee = committee
	tr.N = consciousN
	tr.Threshold = consciousThreshold
	tr.Block1 = ConsciousBlock{
		Phase: "perception", ID: blk1.ID(), ParentID: blk1.Parent(),
		Height: blk1.Height(), ReceiptRoot: blk1.(*Block).ReceiptRoot,
	}

	// -----------------------------------------------------------------------
	// THE COGNITION: the bound committee thinks. >= threshold operators
	// independently commit to the SAME output hash blind, then reveal; a couple of
	// dissenters commit+reveal a DIFFERENT hash (honest disagreement / a divergent
	// model run) to prove they are excluded from the canonical verdict without
	// being slashed. Heights respect the task's commit/reveal windows
	// (RequestHeight=1 -> commit <= 31, reveal in (31,61], settle > 61).
	// -----------------------------------------------------------------------
	majority := hashOf(0x42)  // the canonical thought the quorum will agree on
	dissent := hashOf(0x43)   // a divergent answer from the minority
	embedding := hashOf(0x07) // shared embedding commitment for the majority
	nonce := hashOf(0x99)

	const commitHeight = 2  // within commit window (<= 31)
	const revealHeight = 32 // within reveal window (31 < h <= 61)
	const settleHeight = 62 // after reveal window (> 61)

	// Majority: threshold operators agree.
	for i := 0; i < consciousThreshold; i++ {
		op := committee[i]
		c := commitOf(tr.TaskID, model, op, majority, embedding, nonce)
		if err := e.CommitResponse(st, tr.TaskID, op, c, commitHeight); err != nil {
			return tr, fmt.Errorf("commit (majority %d): %w", i, err)
		}
	}
	// Dissenters: the rest of the committee diverge (committed to a different hash).
	dissenters := committee[consciousThreshold:]
	for i, op := range dissenters {
		dn := hashOf(byte(0xA0 + i)) // distinct nonce per dissenter
		c := commitOf(tr.TaskID, model, op, dissent, embedding, dn)
		if err := e.CommitResponse(st, tr.TaskID, op, c, commitHeight); err != nil {
			return tr, fmt.Errorf("commit (dissenter %d): %w", i, err)
		}
	}
	// Reveal phase.
	for i := 0; i < consciousThreshold; i++ {
		op := committee[i]
		if err := e.RevealResponse(st, tr.TaskID, op, majority, embedding, nonce, revealHeight); err != nil {
			return tr, fmt.Errorf("reveal (majority %d): %w", i, err)
		}
	}
	for i, op := range dissenters {
		dn := hashOf(byte(0xA0 + i))
		if err := e.RevealResponse(st, tr.TaskID, op, dissent, embedding, dn, revealHeight); err != nil {
			return tr, fmt.Errorf("reveal (dissenter %d): %w", i, err)
		}
	}

	// Settle: tally reveals, apply the quorum rule, pay winners, slash withholders,
	// emit the receipt. This is the verdict that the next block commits.
	res, err := e.Settle(st, lg, tr.TaskID, settleHeight)
	if err != nil {
		return tr, fmt.Errorf("settle cognition: %w", err)
	}
	if res.Status != TaskSettled {
		return tr, fmt.Errorf("cognition did not settle: status=%d (want TaskSettled=%d)", res.Status, TaskSettled)
	}
	if res.CanonicalHash != majority {
		return tr, fmt.Errorf("canonical hash = %s, want majority %s", res.CanonicalHash.Hex(), majority.Hex())
	}
	tr.WinnerCount = res.WinnerCount

	// =======================================================================
	// CONSCIOUS BLOCK 2 — COGNITION. BuildBlock commits the staged settlement
	// state delta (the Proof-of-Thought) and folds the receipt_root; Accept makes
	// the canonical AI decision durable on-chain.
	// =======================================================================
	blk2, err := acceptBlock(ctx, vm)
	if err != nil {
		return tr, fmt.Errorf("conscious block 2 (cognition): %w", err)
	}
	if blk2.Height() != 2 {
		return tr, fmt.Errorf("cognition block height = %d, want 2", blk2.Height())
	}

	tr.CanonicalHash = e.GetCanonicalResult(st, tr.TaskID)
	tr.ReceiptRoot = e.ReceiptRoot(st)
	tr.Block2 = ConsciousBlock{
		Phase: "cognition", ID: blk2.ID(), ParentID: blk2.Parent(),
		Height: blk2.Height(), ReceiptRoot: blk2.(*Block).ReceiptRoot,
	}

	head, err := vm.LastAccepted(ctx)
	if err != nil {
		return tr, fmt.Errorf("read head: %w", err)
	}
	tr.LastAccepted = head
	return tr, nil
}

// acceptBlock runs one full block through the production lifecycle: BuildBlock ->
// Verify -> SetPreference -> Accept. This is the real consensus path a proposer
// drives; nothing here is shortcut.
func acceptBlock(ctx context.Context, vm *VM) (chain.Block, error) {
	blk, err := vm.BuildBlock(ctx)
	if err != nil {
		return nil, fmt.Errorf("build: %w", err)
	}
	if err := blk.Verify(ctx); err != nil {
		return nil, fmt.Errorf("verify: %w", err)
	}
	if err := vm.SetPreference(ctx, blk.ID()); err != nil {
		return nil, fmt.Errorf("set preference: %w", err)
	}
	if err := blk.Accept(ctx); err != nil {
		return nil, fmt.Errorf("accept: %w", err)
	}
	return blk, nil
}

// buildIntent constructs a committed C-Chain inference intent whose IntentID is
// correctly derived for the given engine and fields, matching the shared wire
// spec (ComputeIntentID). The resulting IntentID is the taskID the perception
// block creates.
func buildIntent(e *Engine, requester common.Address, model common.Hash, n, threshold uint16, fee, reward *uint256.Int) CIntent {
	cTx := hashOf(0x11)
	callIdx := uint32(7)
	prompt := hashOf(0xCD)
	id := ComputeIntentID(e.CChainID, e.AChainID, cTx, callIdx, requester, model, prompt, n, threshold, fee)
	return CIntent{
		IntentID:          id,
		CChainID:          e.CChainID,
		AChainID:          e.AChainID,
		CTxHash:           cTx,
		CallIndex:         callIdx,
		Caller:            requester,
		ModelSpecHash:     model,
		PromptHash:        prompt,
		N:                 n,
		Threshold:         threshold,
		Fee:               fee,
		RewardPerOperator: reward,
	}
}

// commitOf computes the operator-bound commit for a reveal preimage, matching the
// engine's ComputeCommit. The prompt hash is the one buildIntent binds (0xCD).
func commitOf(taskID, model common.Hash, op common.Address, output, embedding, nonce common.Hash) common.Hash {
	return ComputeCommit(taskID, model, hashOf(0xCD), output, embedding, op, nonce)
}

// addrOf builds a deterministic address with byte b in the low position. Mirrors
// the test harness's addr() so production-driver and test agree on identities.
func addrOf(b byte) common.Address {
	var a common.Address
	a[19] = b
	return a
}

// hashOf builds a deterministic 32-byte hash with byte b in the low position.
func hashOf(b byte) common.Hash {
	var x common.Hash
	x[31] = b
	return x
}
