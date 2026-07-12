// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// bridge_transport_test.go — proves the B→M threshold-signing seam end to end
// over the REAL cross-validator transport.
//
// Three in-process M-Chain validators are wired together by an in-memory p2p
// fabric that stands in for real sockets. The fabric drives the EXACT
// production path: warpAppNetwork.Broadcast → warp.Sender.SendGossip → the peer
// VMs' Gossip handler → envelope demux → the ceremony's gossipRouter.Deliver →
// the executor's receive loop. A DKG establishes one group key; then B asks
// every validator to release the same transfer, the validators run a CGGMP21
// threshold sign across the fabric, and each independently returns an
// attestation that VerifyBridgeAttestation accepts against the group key.
//
// What is DEMONSTRATED here: the message router transports ceremony messages
// between separate VM instances, a signing session completes, and the produced
// signature verifies against the expected custody pubkey over a domain-bound,
// replay-safe digest. What is SIMULATED: the p2p fabric (in-memory, not
// sockets) and the request fan-out to the committee (the test hands the same
// request to every validator; production needs B to deliver it + a policy layer
// agreeing to sign).

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
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	vmcore "github.com/luxfi/vm"
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

func newFabricVM(t *testing.T, fab *memFabric, nid ids.NodeID) *VM {
	t.Helper()
	vm := &VM{}
	rt := &runtime.Runtime{NodeID: nid, NetworkID: 3}
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

// =============================================================================
// The end-to-end B→M threshold-signing test
// =============================================================================

func TestBridgeRelease_ThresholdSignOverGossip(t *testing.T) {
	if testing.Short() {
		t.Skip("threshold DKG/sign is slow; skipped in -short")
	}

	const n = 3
	const threshold = 1 // t+1 = 2 minimum signers; we sign with all n

	fab := newMemFabric()
	vms := make([]*VM, n)
	parties := make([]party.ID, n)
	for i := 0; i < n; i++ {
		nid := ids.GenerateTestNodeID()
		vms[i] = newFabricVM(t, fab, nid)
		parties[i] = vms[i].partyID
	}

	// --- DKG (in-process mesh) to establish one group key + per-party shares ---
	execs := make(map[party.ID]*ProtocolExecutor, n)
	for _, p := range parties {
		pl := pool.NewPool(4)
		defer pl.TearDown()
		execs[p] = NewProtocolExecutor(pl, log.NewTestLogger(log.ErrorLevel))
	}
	dkgCtx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	configs := runKeygenViaTransport(t, dkgCtx, execs, parties, threshold)

	var groupPub []byte
	for _, p := range parties {
		pub, err := configs[p].PublicPoint().MarshalBinary()
		require.NoError(t, err)
		if groupPub == nil {
			groupPub = pub
		} else {
			require.Equal(t, groupPub, pub, "all validators must agree on the group key")
		}
	}
	require.Len(t, groupPub, 33, "compressed secp256k1 custody key")

	// --- install the CGGMP21 custody key into every validator ---
	const keyID = "bridge-custody"
	for i, vm := range vms {
		p := parties[i]
		vm.mu.Lock()
		vm.keys[keyID] = &ManagedKey{
			KeyID:        keyID,
			KeyType:      string(ProtocolCGGMP21),
			PublicKey:    groupPub,
			Threshold:    threshold,
			TotalParties: n,
			Status:       "active",
			PartyIDs:     parties,
			CMPConfig:    configs[p],
		}
		vm.activeKeyID = keyID
		vm.mu.Unlock()
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

	type result struct {
		att *BridgeTransferAttestation
		err error
	}
	results := make(chan result, n)
	for _, vm := range vms {
		vm := vm
		go func() {
			att, err := vm.RequestBridgeRelease(req)
			results <- result{att, err}
		}()
	}

	atts := make([]*BridgeTransferAttestation, 0, n)
	for i := 0; i < n; i++ {
		select {
		case r := <-results:
			require.NoError(t, r.err, "validator failed to produce a bridge attestation")
			require.NotNil(t, r.att)
			atts = append(atts, r.att)
		case <-time.After(150 * time.Second):
			t.Fatal("bridge release timed out — ceremony did not complete over the gossip transport")
		}
	}

	// (a) the router transported messages and the signing session completed on
	//     every validator (all n returned an attestation above), and
	// (b) the produced signature verifies against the expected custody pubkey.
	bt := BridgeTransfer{
		SrcChainID: req.SrcChainID,
		DstChainID: req.DstChainID,
		Asset:      req.Asset,
		Amount:     req.Amount,
		Recipient:  req.Recipient,
		Nonce:      req.Nonce,
	}
	first := atts[0]
	require.NotEmpty(t, first.Signature)
	for _, a := range atts {
		require.Equal(t, first.Signature, a.Signature, "all honest validators derive the identical signature")
		require.Equal(t, groupPub, a.GroupPubKey, "attestation carries the custody group key")
		require.True(t, VerifyBridgeAttestation(groupPub, bt, a.Signature),
			"threshold signature must verify against the custody key over the domain-bound digest")
	}

	// The signature is bound to THIS transfer only: a verifier that flips any
	// digest-committed field must reject the same signature (replay/rebind).
	require.False(t, VerifyBridgeAttestation(groupPub, mutateNonce(bt), first.Signature),
		"signature must not verify under a different nonce")
	require.False(t, VerifyBridgeAttestation(groupPub, mutateDstChain(bt), first.Signature),
		"signature must not verify under a different destination chain")

	// Proof the fabric actually carried ceremony messages between validators
	// (not a single-party shortcut).
	require.Greater(t, fab.delivered.Load(), int64(0),
		"no ceremony messages crossed the gossip fabric")

	t.Logf("bridge release: %d validators threshold-signed over gossip; %d envelopes carried; signature verifies against custody key",
		n, fab.delivered.Load())
}

func mutateNonce(bt BridgeTransfer) BridgeTransfer    { bt.Nonce++; return bt }
func mutateDstChain(bt BridgeTransfer) BridgeTransfer { bt.DstChainID++; return bt }
