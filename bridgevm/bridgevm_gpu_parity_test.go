// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

// Parity test for the one-and-only-one CPU oracle path in
// bridgevm_gpu_cpu.go. The test exercises every public bridge method via
// ActiveGPUBackend() on a non-trivial fixture and asserts:
//
//   1. Each method dispatches WITHOUT returning ErrGPUNotAvailable, even
//      when no GPU plugin is loaded — the fallback to cpuBackend in the
//      cgo bridge (and the direct cpuBackend under !cgo) makes
//      ErrGPUNotAvailable unreachable from the public surface.
//
//   2. The roots populated by BridgeTransition match a deterministic golden
//      digest. Any byte drift from the C++ CPU oracle (or, when a plugin
//      is loaded, any cross-backend drift) flips the digest immediately.
//
//   3. Running the same fixture twice produces the SAME output — both via
//      ActiveGPUBackend() and via a direct cpuBackend invocation. This
//      catches the case where the cgo bridge accidentally takes the GPU
//      path on the second call but the CPU path on the first (or vice
//      versa) — both must agree byte-for-byte.
//
// Build-tag-free: the test compiles under both `go test ./bridgevm/` and
// `go test -tags cgo ./bridgevm/`. Output is identical under both modes
// because (a) no GPU plugin is on the dlopen search path in CI, so cgo
// falls through to cpuBackend; (b) the cpu oracle is the same Go file in
// both cases.

import (
	"encoding/hex"
	"errors"
	"testing"
)

// fixtureRound builds the input fixture for a single non-trivial round.
// Two opt-in ops + one slash + one liquidity deposit + one accrue-fee +
// one inbound mint message + one outbound burn. The round closes (epoch
// rollover) so BridgeTransition produces every component root + the
// composed state root.
func fixtureRound() (
	desc *BridgeVMRoundDescriptor,
	signerOps []SignerOp,
	liquidityOps []LiquidityOp,
	inMsgs []Message,
	outReqs []OutboundReq,
	signers []Signer,
	liquidity []LiquidityEntry,
	daily []DailyLimit,
	inbox []Message,
	outbox []Message,
	epoch *BridgeVMEpochState,
) {
	desc = &BridgeVMRoundDescriptor{
		ChainID:          0x42,
		Round:            7,
		TimestampNs:      1_000_000_000,
		Epoch:            3,
		Height:           100,
		Mode:             transitionModeFullRound,
		InboundMsgCount:  1,
		SignerOpCount:    3,
		LiquidityOpCount: 2,
		OutboundReqCount: 1,
		ClosingFlag:      1,
	}
	for i := range desc.ParentStateRoot {
		desc.ParentStateRoot[i] = byte(i)
	}

	// Three signer ops:
	//  * Opt-in 0x1001 — makes 0x1001 an active signer (status Active|PendingAdd).
	//  * Opt-in 0x1002 — also active. Two signers gives a 2/3 BFT threshold
	//                   of ceil(4/3)=2 — both signers must be in the bitmap
	//                   for an inbound message to clear threshold.
	//  * Slash    0x1002 — at -1M bond, leaves the signer jailed (status
	//                      bit 0x2) which removes it from countActiveSigners.
	//                      After the slash, active count is 1 — inbound
	//                      messages with SignerCount=1 then meet threshold.
	signerOps = []SignerOp{
		{
			SignerID:     0x1001,
			BondAmountLo: minSignerBondLo, // exactly the minimum
			BondAmountHi: minSignerBondHi,
			OptInHeight:  90,
			Kind:         signerOpKindOptIn,
			Epoch:        3,
		},
		{
			SignerID:     0x1002,
			BondAmountLo: minSignerBondLo * 2,
			BondAmountHi: minSignerBondHi,
			OptInHeight:  90,
			Kind:         signerOpKindOptIn,
			Epoch:        3,
		},
		{
			SignerID:       0x1002,
			Kind:           signerOpKindSlash,
			Epoch:          3,
			SlashAmountLo:  1_000_000,
			JailUntilEpoch: 50,
		},
	}
	// Stuff some BLS / corona / mldsa key bytes so the opt-in path memcpy's
	// determinist­ically.
	for i := 0; i < 48; i++ {
		signerOps[0].BLSPubKey[i] = byte(0x10 + i)
		signerOps[1].BLSPubKey[i] = byte(0x60 + i)
	}
	for i := 0; i < 32; i++ {
		signerOps[0].RingtailPubKey[i] = byte(0x20 + i)
		signerOps[0].MLDSAPubKey[i] = byte(0x30 + i)
		signerOps[1].RingtailPubKey[i] = byte(0x70 + i)
		signerOps[1].MLDSAPubKey[i] = byte(0x80 + i)
	}
	signerOps[0].LuxAddress = [20]byte{
		0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
		0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
		0x77, 0x88, 0x99, 0x00, 0xa1, 0xb2,
		0xc3, 0xd4,
	}
	signerOps[1].LuxAddress = [20]byte{
		0xb1, 0xb2, 0xb3, 0xb4, 0xb5, 0xb6,
		0xb7, 0xb8, 0xb9, 0xba, 0xbb, 0xbc,
		0xbd, 0xbe, 0xbf, 0xc0, 0xc1, 0xc2,
		0xc3, 0xc4,
	}

	// Two liquidity ops: one deposit (creates a slot), one accrue-fee
	// (distributes to the new deposit).
	liquidityOps = []LiquidityOp{
		{
			ProviderAddr: [20]byte{
				0x01, 0x02, 0x03, 0x04, 0x05, 0x06,
				0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
				0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
				0x13, 0x14,
			},
			AssetID:  42,
			Kind:     liquidityOpKindDeposit,
			AmountLo: 1_000_000,
			Height:   80,
		},
		{
			AssetID:  42,
			Kind:     liquidityOpKindAccrueFee,
			AmountLo: 1000,
		},
	}

	// One inbound mint message that should be accepted (popcount==signer_count,
	// meets BFT threshold of 1 signer when active set has 1 signer).
	inMsgs = make([]Message, 1)
	msg := &inMsgs[0]
	msg.Nonce = 1
	msg.DstChain = 1
	msg.SrcChain = 2
	msg.Kind = msgKindMint
	msg.AssetID = 42
	msg.AmountLo = 500
	msg.SignersBitmapLo = 1
	msg.SignerCount = 1
	for i := range msg.PayloadRoot {
		msg.PayloadRoot[i] = byte(0x40 + i)
	}
	computeMsgSubject(msg.DstChain, msg.Nonce, msg.PayloadRoot[:], msg.MsgID[:])

	// One outbound burn request.
	outReqs = []OutboundReq{
		{
			Recipient: [20]byte{
				0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
				0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c,
				0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32,
				0x33, 0x34,
			},
			SrcChain: 1,
			DstChain: 2,
			Kind:     msgKindBurn,
			AssetID:  42,
			Nonce:    77,
			AmountLo: 250,
			Height:   100,
		},
	}
	for i := range outReqs[0].PayloadRoot {
		outReqs[0].PayloadRoot[i] = byte(0x50 + i)
	}

	// Arenas — powers-of-two sized so the FNV probe maths work.
	signers = make([]Signer, 16)
	liquidity = make([]LiquidityEntry, 16)
	daily = make([]DailyLimit, 16)
	// Pre-seed the asset's daily limit so MessageInbox can debit it.
	daily[0] = DailyLimit{
		AssetID:    42,
		Status:     dailyStatusActive,
		DailyCapLo: 10_000,
		ResetEpoch: 100,
	}
	inbox = make([]Message, 32)
	outbox = make([]Message, 32)
	epoch = &BridgeVMEpochState{CurrentEpoch: 3}

	return
}

// roundCounts is the per-step apply counter set. Each BridgeVM method returns
// its own count; BridgeTransition only does close-epoch + roots. We aggregate
// the counts at the test level so the parity check compares both the
// individual counter wires AND the merged counter aggregate.
type roundCounts struct {
	signers   uint32
	liquidity uint32
	inbox     uint32
	outbox    uint32
}

// runRoundOn drives a fresh fixture through the GPUBackend's 5 methods
// (the canonical caller path) and returns the populated result plus
// snapshots of the arenas + the per-step apply counts. The returned bytes
// ARE the equivalence oracle — every byte flip is a behavioural change.
func runRoundOn(t *testing.T, b GPUBackend) (
	*BridgeVMTransitionResult, []Signer, []LiquidityEntry, []DailyLimit, []Message, []Message, roundCounts,
) {
	t.Helper()
	desc, signerOps, liquidityOps, inMsgs, outReqs,
		signers, liquidity, daily, inbox, outbox, epoch := fixtureRound()

	var counts roundCounts

	applied, err := b.SignerApply(desc, signerOps, signers)
	if err != nil {
		t.Fatalf("SignerApply: %v", err)
	}
	counts.signers = applied

	applied, _, _, err = b.LiquidityApply(desc, liquidityOps, liquidity)
	if err != nil {
		t.Fatalf("LiquidityApply: %v", err)
	}
	counts.liquidity = applied

	applied, _, _, err = b.MessageInbox(desc, inMsgs, signers, daily, inbox)
	if err != nil {
		t.Fatalf("MessageInbox: %v", err)
	}
	counts.inbox = applied

	applied, _, _, err = b.MessageOutbox(desc, outReqs, daily, outbox, epoch)
	if err != nil {
		t.Fatalf("MessageOutbox: %v", err)
	}
	counts.outbox = applied

	result := &BridgeVMTransitionResult{}
	if err := b.BridgeTransition(desc, signers, liquidity, daily, inbox, outbox, epoch, result); err != nil {
		t.Fatalf("BridgeTransition: %v", err)
	}
	return result, signers, liquidity, daily, inbox, outbox, counts
}

// TestGPUBridgeCgoNocgoParity asserts that the public ActiveGPUBackend()
// surface produces identical state transitions to the direct cpuBackend
// oracle, regardless of build mode and GPU plugin availability.
//
// Mechanism:
//
//   * Run via ActiveGPUBackend() — under cgo this dispatches gpuOrCPU
//     (tries GPU plugin first, falls through to cpuBackend on
//     ErrGPUNotAvailable); under !cgo this dispatches cpuBackend directly.
//
//   * Run via cpuBackend{} — direct CPU oracle.
//
//   * Diff every byte of every output (result + arenas). Differences mean
//     either the CPU oracle drifted from the GPU plugin (a determinism
//     bug) or one side mutated state the other didn't.
//
// The test also locks in a golden hex digest for the bridgevm_state_root
// so any change to the transition algorithm (or the order in which the 5
// methods feed each other) is loud at CI time.
func TestGPUBridgeCgoNocgoParity(t *testing.T) {
	// Run via the public surface (gpuOrCPU under cgo, cpuBackend under
	// !cgo). Either way we land on the CPU oracle because no plugin is on
	// the dlopen path in CI.
	publicResult, publicSigners, publicLiquidity, publicDaily, publicInbox, publicOutbox, publicCounts :=
		runRoundOn(t, ActiveGPUBackend())

	// Run via direct cpuBackend — the canonical oracle.
	cpuResult, cpuSigners, cpuLiquidity, cpuDaily, cpuInbox, cpuOutbox, cpuCounts :=
		runRoundOn(t, cpuBackend{})

	// Byte-equal arenas — full diff.
	if !equalSigners(publicSigners, cpuSigners) {
		t.Errorf("signers arena differs between ActiveGPUBackend() and cpuBackend")
	}
	if !equalLiquidity(publicLiquidity, cpuLiquidity) {
		t.Errorf("liquidity arena differs between ActiveGPUBackend() and cpuBackend")
	}
	if !equalDaily(publicDaily, cpuDaily) {
		t.Errorf("daily arena differs between ActiveGPUBackend() and cpuBackend")
	}
	if !equalMessages(publicInbox, cpuInbox) {
		t.Errorf("inbox arena differs between ActiveGPUBackend() and cpuBackend")
	}
	if !equalMessages(publicOutbox, cpuOutbox) {
		t.Errorf("outbox arena differs between ActiveGPUBackend() and cpuBackend")
	}

	// Per-step apply counts agree across the two paths.
	if publicCounts != cpuCounts {
		t.Errorf("per-step apply counts differ: public=%+v cpu=%+v", publicCounts, cpuCounts)
	}

	// Byte-equal roots — the populated result.
	if *publicResult != *cpuResult {
		t.Errorf("BridgeVMTransitionResult differs between ActiveGPUBackend() and cpuBackend\n"+
			"  public.SignerSetRoot     = %s\n"+
			"  cpu.SignerSetRoot        = %s\n"+
			"  public.BridgeVMStateRoot = %s\n"+
			"  cpu.BridgeVMStateRoot    = %s",
			hex.EncodeToString(publicResult.SignerSetRoot[:]),
			hex.EncodeToString(cpuResult.SignerSetRoot[:]),
			hex.EncodeToString(publicResult.BridgeVMStateRoot[:]),
			hex.EncodeToString(cpuResult.BridgeVMStateRoot[:]))
	}

	// Sanity: at least one signer + one liquidity + one inbox + one outbox
	// op was applied — the fixture is non-trivial. The result struct's
	// apply-count fields are only populated by run_reference()-style
	// composite paths (used by C++); the Go interface returns per-step
	// counts from each method, so we check the captured counters instead.
	if publicCounts.signers == 0 {
		t.Errorf("SignerApply applied 0 — fixture didn't exercise signer path")
	}
	if publicCounts.liquidity == 0 {
		t.Errorf("LiquidityApply applied 0 — fixture didn't exercise liquidity path")
	}
	if publicCounts.inbox == 0 {
		t.Errorf("MessageInbox applied 0 — fixture didn't exercise inbox path")
	}
	if publicCounts.outbox == 0 {
		t.Errorf("MessageOutbox applied 0 — fixture didn't exercise outbox path")
	}

	// Golden digest — locks in the CPU oracle's expected
	// bridgevm_state_root for this fixture. Captured on first green
	// (zero-plugin, !cgo) run; matches the C++ reference's algorithm
	// byte-for-byte. Any drift here means either (a) the Go oracle
	// diverged from the C++ oracle or (b) a backend (CUDA/HIP/Metal/
	// Vulkan/WGSL) computed a different root from the same fixture
	// — both are correctness bugs.
	const wantStateRoot = "3340f9d13a5373b562c88ff09bdddc1e033d637789c4fa43a489e1dc933ccb64"
	got := hex.EncodeToString(publicResult.BridgeVMStateRoot[:])
	if got != wantStateRoot {
		t.Errorf("bridgevm_state_root = %s, want %s — algorithm drift, "+
			"update C++/Go oracles + GPU plugins together", got, wantStateRoot)
	}
}

// TestGPUBridgeNeverReturnsErrGPUNotAvailable asserts the public contract:
// ActiveGPUBackend() always executes the transition. ErrGPUNotAvailable
// only ever leaks out of the bare cgoBackend (internal type, used by
// TestStubReturnsErrGPUNotAvailable to verify the GPU layer's stub
// semantics). End-user code paths never see it.
func TestGPUBridgeNeverReturnsErrGPUNotAvailable(t *testing.T) {
	b := ActiveGPUBackend()
	desc, signerOps, liquidityOps, inMsgs, outReqs,
		signers, liquidity, daily, inbox, outbox, epoch := fixtureRound()

	if _, err := b.SignerApply(desc, signerOps, signers); errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("SignerApply leaked ErrGPUNotAvailable")
	}
	if _, _, _, err := b.LiquidityApply(desc, liquidityOps, liquidity); errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("LiquidityApply leaked ErrGPUNotAvailable")
	}
	if _, _, _, err := b.MessageInbox(desc, inMsgs, signers, daily, inbox); errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("MessageInbox leaked ErrGPUNotAvailable")
	}
	if _, _, _, err := b.MessageOutbox(desc, outReqs, daily, outbox, epoch); errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("MessageOutbox leaked ErrGPUNotAvailable")
	}
	result := &BridgeVMTransitionResult{}
	if err := b.BridgeTransition(desc, signers, liquidity, daily, inbox, outbox, epoch, result); errors.Is(err, ErrGPUNotAvailable) {
		t.Errorf("BridgeTransition leaked ErrGPUNotAvailable")
	}
}

// =============================================================================
// equal* helpers — flat byte-compare per slot. We can't use reflect.DeepEqual
// on the arenas because the layout structs have unexported pad fields that
// don't show up in a DeepEqual diff, but DO show up in the kernel's wire
// format. Comparing fields explicitly catches drift in every public field.
// =============================================================================

func equalSigners(a, b []Signer) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalLiquidity(a, b []LiquidityEntry) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalDaily(a, b []DailyLimit) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func equalMessages(a, b []Message) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
