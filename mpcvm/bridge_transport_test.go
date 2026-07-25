// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// bridge_transport_test.go — proves the B→M custody path end to end over the
// REAL cross-validator transport and the REAL chain state machine.
//
// Three in-process M-Chain validators are wired together by an in-memory p2p
// fabric that stands in for real sockets. The fabric drives the EXACT
// production path: warpAppNetwork.Broadcast → warp.Sender.SendGossip → the peer
// VMs' Gossip handler → envelope demux → the ceremony's gossipRouter.Deliver →
// the executor's receive loop.
//
// The whole custody lifecycle runs through it, with no shortcut at any step:
//
//	DKG over gossip  →  every validator stages the SAME registration
//	block            →  one proposer builds it, every validator VERIFIES and
//	                    accepts it, and the key enters the replicated registry
//	sign over gossip →  B asks for a release; every validator independently
//	                    returns the identical signature
//	block            →  the ceremony is recorded, and can be read back from
//	                    consensus state by its derived id
//
// What is SIMULATED: only the p2p fabric (in-memory channels, not sockets) and
// the request fan-out to the committee (the test hands the same request to
// every validator; production needs B to deliver it plus a policy layer).
// Nothing about the cryptography, the state transition or the block rules is
// stubbed.

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/math/set"
	"github.com/luxfi/runtime"
	validators "github.com/luxfi/validators"
	"github.com/luxfi/validators/validatorstest"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/vm/chain"
	"github.com/luxfi/warp"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// In-memory p2p fabric — wires N VMs' Gossip handlers together
// =============================================================================

// memFabric routes gossip between the in-process validators registered on it.
type memFabric struct {
	mu        sync.RWMutex
	vms       map[ids.NodeID]*VM
	delivered atomic.Int64 // count of envelopes actually handed to a peer Gossip
}

func newMemFabric() *memFabric { return &memFabric{vms: make(map[ids.NodeID]*VM)} }

func (f *memFabric) register(nid ids.NodeID, vm *VM) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.vms[nid] = vm
}

// senderFor returns a warp.Sender bound to a source validator.
func (f *memFabric) senderFor(self ids.NodeID) warp.Sender {
	return &memSender{fab: f, self: self}
}

// memSender is one validator's view of the fabric: SendGossip delivers to the
// targeted peers' Gossip handlers (async, like real gossip).
type memSender struct {
	fab  *memFabric
	self ids.NodeID
}

func (s *memSender) SendGossip(ctx context.Context, cfg warp.SendConfig, msg []byte) error {
	// Determine target node set. An explicit NodeIDs set (what warpAppNetwork
	// always uses for MPC) addresses exact peers; an empty set falls back to
	// "all other registered validators".
	s.fab.mu.RLock()
	var targets []*VM
	if cfg.NodeIDs.Len() > 0 {
		for _, nid := range cfg.NodeIDs.List() {
			if nid == s.self {
				continue
			}
			if vm := s.fab.vms[nid]; vm != nil {
				targets = append(targets, vm)
			}
		}
	} else {
		for nid, vm := range s.fab.vms {
			if nid != s.self {
				targets = append(targets, vm)
			}
		}
	}
	s.fab.mu.RUnlock()

	for _, vm := range targets {
		vm := vm
		cp := append([]byte(nil), msg...) // defensive copy across the "wire"
		s.fab.delivered.Add(1)
		go func() { _ = vm.Gossip(context.Background(), s.self, cp) }()
	}
	return nil
}

// The remaining Sender methods are unused by the MPC gossip transport (which
// rides SendGossip), but are required to satisfy warp.Sender.
func (s *memSender) SendRequest(context.Context, set.Set[ids.NodeID], uint32, []byte) error {
	return nil
}
func (s *memSender) SendResponse(context.Context, ids.NodeID, uint32, []byte) error { return nil }
func (s *memSender) SendError(context.Context, ids.NodeID, uint32, int32, string) error {
	return nil
}

var _ warp.Sender = (*memSender)(nil)

// =============================================================================
// Fabric VM construction
// =============================================================================

// committeeState is the validator set the ceremonies draw their committee from.
// In production this is the P-Chain's view at a height; here it is the fabric's
// membership — the same fact, which is the point: the MPC committee IS the
// validator set, with no separate operator roster to drift from it.
func committeeState(nodes []ids.NodeID) *validatorstest.TestState {
	return &validatorstest.TestState{
		GetValidatorSetF: func(context.Context, uint64, ids.ID) (map[ids.NodeID]*validators.GetValidatorOutput, error) {
			out := make(map[ids.NodeID]*validators.GetValidatorOutput, len(nodes))
			for _, n := range nodes {
				out[n] = &validators.GetValidatorOutput{NodeID: n, Weight: 1}
			}
			return out, nil
		},
	}
}

func newFabricVM(t *testing.T, fab *memFabric, nid ids.NodeID, vs *validatorstest.TestState) *VM {
	t.Helper()
	vm := &VM{}
	rt := &runtime.Runtime{NodeID: nid, NetworkID: 3, ValidatorState: vs}
	toEngine := make(chan vmcore.Message, 1)
	init := vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		Sender:   fab.senderFor(nid),
		Log:      log.NewTestLogger(log.ErrorLevel),
		ToEngine: toEngine,
	}
	require.NoError(t, vm.Initialize(context.Background(), init))
	fab.register(nid, vm)
	return vm
}

// ceremonyContext gives the ceremonies whatever wall clock the harness allows,
// less a margin so a budget overrun surfaces as a named failure rather than as
// the test binary being killed mid-round.
//
// The budget is taken rather than hardcoded because a CGGMP21 DKG is genuinely
// expensive (Paillier key generation) and roughly an order of magnitude slower
// again under -race: any fixed number is either too tight for the race detector
// or a lie about how long this takes. Each individual ceremony is still capped
// by the VM's own session timeout, which is the production bound.
func ceremonyContext(t *testing.T) (context.Context, context.CancelFunc) {
	t.Helper()
	if deadline, ok := t.Deadline(); ok {
		return context.WithDeadline(context.Background(), deadline.Add(-15*time.Second))
	}
	return context.WithCancel(context.Background())
}

// commitBlock has one validator propose a block and EVERY validator verify and
// accept it — including the proposer, which re-parses its own block from the
// wire so it applies exactly the bytes its peers applied.
//
// It returns the accepted block. A validator that rejects here has diverged,
// which is what the state root exists to surface.
func commitBlock(t *testing.T, ctx context.Context, proposer *VM, all []*VM) chain.Block {
	t.Helper()
	built, err := proposer.BuildBlock(ctx)
	require.NoError(t, err, "proposer could not build a block from its staged ceremonies")
	raw := built.Bytes()

	var accepted chain.Block
	for _, vm := range all {
		blk, err := vm.ParseBlock(ctx, raw)
		require.NoError(t, err)
		require.Equal(t, built.ID(), blk.ID(), "block id must be derived from the bytes, identically on every validator")
		require.NoError(t, blk.Verify(ctx), "validator rejected a block it should have verified")
		require.NoError(t, blk.Accept(ctx))
		accepted = blk
	}

	// Agreement is the whole point: after applying the same block to the same
	// prior state, every validator must hold the same root.
	want := all[0].StateRoot()
	for _, vm := range all {
		require.Equal(t, want, vm.StateRoot(), "validators disagree about custody state after accepting the same block")
	}
	return accepted
}

// =============================================================================
// The end-to-end B→M custody test
// =============================================================================

func TestBridgeCustody_KeygenSignAndRecordOverGossip(t *testing.T) {
	if testing.Short() {
		t.Skip("threshold DKG/sign is slow; skipped in -short")
	}

	const n = 3
	const keyID = "bridge-custody"

	nodes := make([]ids.NodeID, n)
	for i := range nodes {
		nodes[i] = ids.GenerateTestNodeID()
	}
	vs := committeeState(nodes)

	fab := newMemFabric()
	vms := make([]*VM, n)
	for i, nid := range nodes {
		vms[i] = newFabricVM(t, fab, nid, vs)
	}

	ctx, cancel := ceremonyContext(t)
	defer cancel()

	// --- DKG over the gossip fabric: every validator runs the ceremony ---
	//
	// The chain's default policy is 2-of-3, so the committee is all three
	// validators and any two of them can sign.
	policy := vms[0].Policy()
	require.Equal(t, "2-of-3", policy.String())

	keygens := runOnAll(t, ctx, vms, func(ctx context.Context, vm *VM) (*Operation, error) {
		return vm.StartKeygen(ctx, keyID, "B-Chain")
	})

	first := keygens[0]
	require.Equal(t, OpTypeKeygen, first.Type)
	require.NotNil(t, first.Key)
	require.Len(t, first.Key.GroupPublicKey, 33, "compressed secp256k1 custody key")
	require.Len(t, first.Key.Address, 20, "20-byte external-chain custody address")
	require.Equal(t, policy, first.Key.Policy)
	require.Equal(t, 1, first.Key.Degree(), "2-of-3 is a degree-1 key; a degree-2 key would need 3 signers")
	for _, op := range keygens {
		require.Equal(t, first.CeremonyID, op.CeremonyID, "every validator must derive the same ceremony id with no announce round")
		require.Equal(t, first.Key.GroupPublicKey, op.Key.GroupPublicKey, "all validators must agree on the group key")
		require.Equal(t, first.Artifact, op.Artifact, "all honest validators derive the identical proof of possession")
	}
	// The proof of possession is a real signature by the fresh group key over
	// its own registration — this is what stops a proposer registering a public
	// key it does not control.
	commit := KeyCommitDigest(first.Key)
	require.Equal(t, commit[:], first.Digest)
	require.NoError(t, verifyGroupSignature(first.Key.GroupPublicKey, commit[:], first.Artifact))

	// --- the registration becomes consensus state ---
	commitBlock(t, ctx, vms[0], vms)
	groupPub := first.Key.GroupPublicKey
	for _, vm := range vms {
		rec, err := vm.Key(keyID)
		require.NoError(t, err, "key must be readable from the registry after the block is accepted")
		require.Equal(t, groupPub, rec.GroupPublicKey)
		require.Equal(t, policy, rec.Policy)

		held, err := vm.state.HasShare(keyID)
		require.NoError(t, err)
		require.True(t, held, "every committee member must hold a share for a key it participated in")
	}

	// --- B asks every validator to release the SAME transfer ---
	var asset [32]byte
	copy(asset[:], []byte("LUX"))
	var recip [20]byte
	copy(recip[:], []byte("recipient-0xabc0123"))
	req := BridgeReleaseRequest{
		RequestingChain: "B-Chain",
		KeyID:           keyID,
		SrcChainID:      200201, // Zoo EVM
		DstChainID:      97368,  // Lux testnet M-Chain route
		Asset:           asset,
		Amount:          1_000_000,
		Recipient:       recip,
		Nonce:           7,
	}

	atts := runOnAll(t, ctx, vms, func(ctx context.Context, vm *VM) (*BridgeTransferAttestation, error) {
		return vm.RequestBridgeRelease(ctx, req)
	})

	bt := BridgeTransfer{
		SrcChainID: req.SrcChainID,
		DstChainID: req.DstChainID,
		Asset:      req.Asset,
		Amount:     req.Amount,
		Recipient:  req.Recipient,
		Nonce:      req.Nonce,
	}
	att := atts[0]
	require.Len(t, att.Signature, 65, "r‖s‖v")
	for _, a := range atts {
		require.Equal(t, att.Signature, a.Signature, "all honest validators derive the identical signature")
		require.Equal(t, att.CeremonyID, a.CeremonyID, "the ceremony id is derived from the task, not announced")
		require.Equal(t, groupPub, a.GroupPubKey, "attestation carries the custody group key")
		require.True(t, VerifyBridgeAttestation(groupPub, bt, a.Signature),
			"threshold signature must verify against the custody key over the domain-bound digest")
	}

	// The signature is bound to THIS transfer only: a verifier that flips any
	// digest-committed field must reject the same signature (replay/rebind).
	require.False(t, VerifyBridgeAttestation(groupPub, mutateNonce(bt), att.Signature),
		"signature must not verify under a different nonce")
	require.False(t, VerifyBridgeAttestation(groupPub, mutateDstChain(bt), att.Signature),
		"signature must not verify under a different destination chain")

	// --- the signature becomes an auditable record in replicated state ---
	commitBlock(t, ctx, vms[1], vms) // a DIFFERENT proposer: nothing depends on who builds
	digest := bt.Digest()
	for _, vm := range vms {
		rec, err := vm.Ceremony(att.CeremonyID)
		require.NoError(t, err, "a produced signature must be readable from the ceremony log")
		require.Equal(t, OpTypeSign, rec.Kind)
		require.Equal(t, keyID, rec.KeyID)
		require.Equal(t, digest[:], rec.Digest)
		require.Equal(t, att.Signature, rec.Artifact, "the recorded artifact is the signature B was handed")
		require.Equal(t, "B-Chain", rec.RequestingChain)
		require.Len(t, rec.Signers, n)
	}

	// Replay is refused: the ceremony id is derived from (key, digest, signers),
	// so asking again for the identical release is the identical ceremony — and
	// recording it twice would be a double release.
	_, err := vms[0].RequestBridgeRelease(ctx, req)
	require.ErrorIs(t, err, ErrCeremonyExists)

	// Proof the fabric actually carried ceremony messages between validators
	// (not a single-party shortcut).
	require.Greater(t, fab.delivered.Load(), int64(0),
		"no ceremony messages crossed the gossip fabric")

	t.Logf("custody lifecycle: %d validators ran DKG + threshold sign over gossip; %d envelopes carried; signature verifies and is recorded at state root %x",
		n, fab.delivered.Load(), vms[0].StateRoot())
}

// runOnAll invokes fn on every validator concurrently and returns the results
// in validator order. Every validator must succeed: a ceremony that completes
// on some nodes and not others is exactly the split-brain this VM exists to
// prevent, so a partial success is a failure.
func runOnAll[T any](t *testing.T, ctx context.Context, vms []*VM, fn func(context.Context, *VM) (T, error)) []T {
	t.Helper()
	var wg sync.WaitGroup
	out := make([]T, len(vms))
	errs := make([]error, len(vms))
	for i, vm := range vms {
		wg.Add(1)
		go func(i int, vm *VM) {
			defer wg.Done()
			out[i], errs[i] = fn(ctx, vm)
		}(i, vm)
	}
	wg.Wait()
	for i, err := range errs {
		require.NoErrorf(t, err, "validator %d failed", i)
	}
	return out
}

func mutateNonce(bt BridgeTransfer) BridgeTransfer    { bt.Nonce++; return bt }
func mutateDstChain(bt BridgeTransfer) BridgeTransfer { bt.DstChainID++; return bt }
