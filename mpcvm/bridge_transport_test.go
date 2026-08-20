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
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/math/set"
	"github.com/luxfi/runtime"
	"github.com/luxfi/threshold/pkg/quorum"
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
		return vm.StartKeygen(ctx, keyID, authenticated(vm, "B-Chain"))
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
		KeyID:           keyID,
		SrcChainID:      200201, // Zoo EVM
		DstChainID:      97368,  // Lux testnet M-Chain route
		Asset:           asset,
		Amount:          1_000_000,
		Recipient:       recip,
		Nonce:           7,
	}

	// Every validator is asked; only the policy's K-subset signs. With a 2-of-3
	// key that is two of the three, chosen deterministically from the task, so
	// the third declines without anyone coordinating that.
	atts, declined := runOnQuorum(t, ctx, vms, func(ctx context.Context, vm *VM) (*BridgeTransferAttestation, error) {
		return vm.RequestBridgeRelease(ctx, authenticated(vm, "B-Chain"), req)
	})
	require.Len(t, atts, policy.K, "exactly K validators sign")
	require.Equal(t, policy.N-policy.K, declined, "the rest decline rather than sign")

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
	commitBlock(t, ctx, signerVM(t, vms, atts[0]), vms)
	digest := bt.Digest()
	for _, vm := range vms {
		rec, err := vm.Ceremony(att.CeremonyID)
		require.NoError(t, err, "a produced signature must be readable from the ceremony log")
		require.Equal(t, OpTypeSign, rec.Kind)
		require.Equal(t, keyID, rec.KeyID)
		require.Equal(t, digest[:], rec.Digest)
		require.Equal(t, att.Signature, rec.Artifact, "the recorded artifact is the signature B was handed")
		require.Equal(t, "B-Chain", rec.RequestingChain)
		require.Len(t, rec.Signers, policy.K, "the recorded quorum is K, not the whole committee")
	}

	// Replay is refused: the ceremony id is derived from (key, digest, signers),
	// so asking again for the identical release is the identical ceremony — and
	// recording it twice would be a double release.
	_, err := signerVM(t, vms, atts[0]).RequestBridgeRelease(ctx, authenticated(signerVM(t, vms, atts[0]), "B-Chain"), req)
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

// runOnQuorum invokes fn on every validator and separates the ones that signed
// from the ones that correctly declined because they are outside this task's
// K-subset. Any OTHER error is a failure: a ceremony that breaks on some nodes
// and not others is the split-brain this VM exists to prevent.
func runOnQuorum[T any](t *testing.T, ctx context.Context, vms []*VM, fn func(context.Context, *VM) (T, error)) (signed []T, declined int) {
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
		switch {
		case err == nil:
			signed = append(signed, out[i])
		case errors.Is(err, ErrNotInQuorum):
			declined++
		default:
			require.NoErrorf(t, err, "validator %d failed for a reason other than being outside the quorum", i)
		}
	}
	return signed, declined
}

// signerVM returns a validator that participated in att's ceremony — i.e. one
// whose party id is in the signing quorum. Such a node has the signature staged
// (so it can propose a block carrying it) and is the node that would re-run the
// ceremony on a replay rather than declining as an outsider.
//
// Membership is read from the attestation's signer set rather than from the
// staging map, because Accept clears a ceremony from staging once its block
// lands — a post-commit lookup by staging would find nobody.
func signerVM(t *testing.T, vms []*VM, att *BridgeTransferAttestation) *VM {
	t.Helper()
	for _, vm := range vms {
		for _, s := range att.Signers {
			if s == vm.partyID {
				return vm
			}
		}
	}
	t.Fatalf("no validator is in the signing quorum of ceremony %s", att.CeremonyID)
	return nil
}

func mutateNonce(bt BridgeTransfer) BridgeTransfer    { bt.Nonce++; return bt }
func mutateDstChain(bt BridgeTransfer) BridgeTransfer { bt.DstChainID++; return bt }

// =============================================================================
// THE GATE: a genuine 3-of-5 custody key, signing through the chain
// =============================================================================

// TestBridgeCustody_ThreeOfFive is the proof that M-Chain replaces an off-chain
// signer cluster with something strictly better than what it replaces.
//
// Five validators generate one custody key under a 3-of-5 policy. The policy is
// consensus state, so the degree is not a per-binary flag that can silently
// disagree with it — which is exactly how three live k8s quorums ended up
// 1-of-n while their configs said 3-of-5.
//
// It then proves the quorum is real in both directions:
//
//   - EXACTLY THREE of the five validators run the signing ceremony and produce
//     a valid signature. Not five. If the key were degree-3 (the off-by-one this
//     whole change exists to prevent) three parties could not have signed at all.
//   - The other two never touch the ceremony, yet still verify and accept the
//     block — non-participants validate custody without trusting the signers.
func TestBridgeCustody_ThreeOfFive(t *testing.T) {
	if testing.Short() {
		t.Skip("threshold DKG/sign is slow; skipped in -short")
	}

	const n = 5
	const keyID = "bridge-custody-3of5"
	policy := quorum.MustNew(3, 5)

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

	// --- DKG at degree 2 across all five ---
	keygens := runOnAll(t, ctx, vms, func(ctx context.Context, vm *VM) (*Operation, error) {
		return vm.StartKeygenWithPolicy(ctx, keyID, policy, authenticated(vm, "B-Chain"))
	})
	rec := keygens[0].Key
	require.Equal(t, policy, rec.Policy)
	require.Equal(t, 2, rec.Degree(),
		"3-of-5 must be a degree-2 key; degree 3 would need four signers and is the classic off-by-one")
	require.Len(t, rec.Participants, 5)
	for _, op := range keygens {
		require.Equal(t, rec.GroupPublicKey, op.Key.GroupPublicKey, "all five must agree on the group key")
	}

	commitBlock(t, ctx, vms[0], vms)
	groupPub := rec.GroupPublicKey

	// --- exactly three sign ---
	var asset [32]byte
	copy(asset[:], []byte("LUX"))
	var recip [20]byte
	copy(recip[:], []byte("recipient-3of5"))
	req := BridgeReleaseRequest{
		KeyID:           keyID,
		SrcChainID:      200201,
		DstChainID:      97368,
		Asset:           asset,
		Amount:          4_200_000,
		Recipient:       recip,
		Nonce:           11,
	}

	// Every validator is asked; the ones outside this task's quorum decline with
	// ErrNotInQuorum. Nobody coordinates that — each node computes the same
	// quorum from the task alone.
	signed, declined := runOnQuorum(t, ctx, vms, func(ctx context.Context, vm *VM) (*BridgeTransferAttestation, error) {
		return vm.RequestBridgeRelease(ctx, authenticated(vm, "B-Chain"), req)
	})
	require.Len(t, signed, 3, "exactly K=3 validators must sign a 3-of-5 key")
	require.Equal(t, 2, declined, "the remaining N-K=2 validators must decline, not sign")

	att := signed[0]
	bt := BridgeTransfer{
		SrcChainID: req.SrcChainID,
		DstChainID: req.DstChainID,
		Asset:      req.Asset,
		Amount:     req.Amount,
		Recipient:  req.Recipient,
		Nonce:      req.Nonce,
	}
	for _, a := range signed {
		require.Equal(t, att.Signature, a.Signature, "the three signers derive one identical signature")
		require.True(t, VerifyBridgeAttestation(groupPub, bt, a.Signature),
			"three shares of a 3-of-5 key must produce a signature that verifies under the group key")
	}
	require.Len(t, att.Signers, 3)

	// --- the two non-signers verify and accept a block they had no part in ---
	//
	// The signature reaches a block via one of the three signers (a non-signer
	// has nothing staged to propose). Every validator then verifies it against
	// its own registry. That is the property that matters: verification does not
	// require participation, so a validator that sat out the ceremony still
	// polices custody rather than trusting whoever signed.
	commitBlock(t, ctx, signerVM(t, vms, att), vms)

	digest := bt.Digest()
	for i, vm := range vms {
		crec, err := vm.Ceremony(att.CeremonyID)
		require.NoErrorf(t, err, "validator %d cannot read the ceremony it accepted", i)
		require.Equal(t, digest[:], crec.Digest)
		require.Equal(t, att.Signature, crec.Artifact)
		require.Len(t, crec.Signers, 3, "the recorded quorum is three, not five")

		krec, err := vm.Key(keyID)
		require.NoError(t, err)
		require.Equal(t, "3-of-5", krec.Policy.String())
		require.Equal(t, 2, krec.Degree())
	}

	t.Logf("3-of-5 custody: key %s addr 0x%x | %d of %d validators signed, %d declined | signature verifies | state root %x",
		keyID, rec.Address, len(signed), n, declined, vms[0].StateRoot())
}
