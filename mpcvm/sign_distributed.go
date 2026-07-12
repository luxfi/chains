// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// sign_distributed.go — the cross-validator threshold-signing core.
//
// A signing session runs a threshold-ECDSA (CGGMP21/CMP) ceremony across the
// M-Chain committee over the native app-gossip transport: each validator runs
// its own executor + a per-session gossipRouter, the routers carry the round
// messages between validators, and every honest signer derives the SAME
// standard secp256k1 signature. B (or any chain holding the group key) verifies
// that signature with zero interaction.
//
// The ceremony id is DERIVED, not announced: every validator that computes the
// same (keyID, digest, signer-set) lands on the same session id, so the round
// messages demultiplex correctly without a separate coordination round. A fresh
// nonce inside a bridge digest gives a fresh ceremony id, so distinct transfers
// never share a session.
//
// SEPARATION OF CONCERNS: this file owns "run the ceremony over a router". The
// router owns "move opaque bytes" (transport.go). The executor owns "drive the
// threshold protocol" (executor.go). None interprets another's layer.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// maxPendingPerSession bounds the pre-registration buffer for one ceremony so a
// peer that opens a round a hair before us never loses its first broadcast,
// while a flood of junk-session gossip can never exhaust memory.
const maxPendingPerSession = 512

// ceremonyDomainTag domain-separates the ceremony-id hash from every other
// digest M computes, so a ceremony id can never alias a signing preimage.
const ceremonyDomainTag = "LUX_MPC_CEREMONY_v1"

// ceremonyID is the deterministic session id all honest validators converge on
// for a given signing task. It binds the key, the exact 32-byte digest, and the
// (order-independent) signer set: distinct keys, messages or quorums get
// distinct ceremony ids, and the same task always maps to the same id.
func ceremonyID(keyID string, digest []byte, signers []party.ID) string {
	sorted := append([]party.ID(nil), signers...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i] < sorted[j] })

	h := sha256.New()
	h.Write([]byte(ceremonyDomainTag))
	h.Write([]byte(keyID))
	h.Write(digest)
	for _, s := range sorted {
		h.Write([]byte{0x00}) // length-free separator; party ids are ascii node ids
		h.Write([]byte(s))
	}
	return "mpc/" + hex.EncodeToString(h.Sum(nil))
}

// resolveCommittee maps each signer party to the validator NodeID that runs it.
// The M-Chain sets party.ID == NodeID.String() at Initialize, so the mapping is
// the exact inverse — no side table, no place-vs-value drift.
func resolveCommittee(signers []party.ID) ([]ids.NodeID, map[party.ID]ids.NodeID, error) {
	nodes := make([]ids.NodeID, 0, len(signers))
	peers := make(map[party.ID]ids.NodeID, len(signers))
	for _, p := range signers {
		nid, err := ids.NodeIDFromString(string(p))
		if err != nil {
			return nil, nil, fmt.Errorf("mpcvm: signer %q is not a node id: %w", p, err)
		}
		nodes = append(nodes, nid)
		peers[p] = nid
	}
	return nodes, peers, nil
}

// registerSessionRouter installs a ceremony's router and drains any envelopes
// that arrived before we were ready, so no round-one broadcast is dropped.
func (vm *VM) registerSessionRouter(sessionID string, router *gossipRouter) {
	vm.routerMu.Lock()
	pending := vm.pendingBySession[sessionID]
	delete(vm.pendingBySession, sessionID)
	vm.sessionRouters[sessionID] = router
	vm.routerMu.Unlock()

	for _, m := range pending {
		router.Deliver(m)
	}
}

// unregisterSessionRouter tears a ceremony's router down and closes it so the
// executor's receive loop unwinds. Idempotent.
func (vm *VM) unregisterSessionRouter(sessionID string) {
	vm.routerMu.Lock()
	router := vm.sessionRouters[sessionID]
	delete(vm.sessionRouters, sessionID)
	delete(vm.pendingBySession, sessionID)
	vm.routerMu.Unlock()

	if router != nil {
		router.Close()
	}
}

// deliverCeremonyMessage routes one decoded envelope to its ceremony's router,
// buffering (bounded) if our own router for that ceremony has not registered
// yet. Called by the Gossip handler.
func (vm *VM) deliverCeremonyMessage(sessionID string, msg *protocol.Message) {
	vm.routerMu.Lock()
	router, ok := vm.sessionRouters[sessionID]
	if !ok {
		q := vm.pendingBySession[sessionID]
		if len(q) < maxPendingPerSession {
			vm.pendingBySession[sessionID] = append(q, msg)
		}
		vm.routerMu.Unlock()
		return
	}
	vm.routerMu.Unlock()
	router.Deliver(msg)
}

// thresholdSignCMP runs the CGGMP21 threshold-ECDSA sign for a custody key
// across the committee over the gossip transport, returning this validator's
// copy of the (canonical, low-S) secp256k1 signature. Every honest signer
// returns the same R‖S.
func (vm *VM) thresholdSignCMP(
	ctx context.Context,
	key *ManagedKey,
	session *SigningSession,
) (*ecdsaSignature, []party.ID, error) {
	if key.CMPConfig == nil {
		return nil, nil, errors.New("mpcvm: CGGMP21 custody key has no config")
	}
	if vm.sender == nil {
		return nil, nil, errors.New("mpcvm: no warp sender; cross-validator signing unavailable")
	}

	// The signer set is the key's full party set. Every committee member
	// participates. (Dynamic T+1 quorum selection under partial availability —
	// pick the minimal online subset — is a documented follow-up; it does not
	// affect signature validity, only liveness under faults.)
	signers := key.PartyIDs
	if len(signers) == 0 {
		for id := range key.CMPConfig.Public {
			signers = append(signers, id)
		}
	}

	nodes, peers, err := resolveCommittee(signers)
	if err != nil {
		return nil, nil, err
	}

	cid := ceremonyID(key.KeyID, session.MessageHash, signers)
	appNet := newWarpAppNetwork(vm.sender, vm.rt.NodeID, nodes)
	router := newGossipRouter(ctx, cid, vm.partyID, appNet, peers)

	vm.registerSessionRouter(cid, router)
	defer vm.unregisterSessionRouter(cid)

	sig, err := vm.protocolExecutor.RunCMPSign(ctx, cid, key.CMPConfig, signers, session.MessageHash, router)
	if err != nil {
		return nil, nil, err
	}
	return &ecdsaSignature{R: sig.R, S: sig.S, V: sig.V}, signers, nil
}

// signViaHandler is the legacy registry-handler signing path (LSS and any other
// protocol whose share is carried in ManagedKey.Config). Kept intact and in its
// own lane; the CGGMP21 bridge-custody path does not touch it.
func (vm *VM) signViaHandler(
	ctx context.Context,
	key *ManagedKey,
	session *SigningSession,
) (*ecdsaSignature, []party.ID, error) {
	handler, err := vm.protocolRegistry.Get(Protocol(key.KeyType))
	if err != nil {
		handler, err = vm.protocolRegistry.Get(ProtocolLSS)
		if err != nil {
			return nil, nil, err
		}
	}
	if key.Config == nil {
		return nil, nil, errors.New("mpcvm: no key share available for signing")
	}
	share := &lssKeyShare{
		config:  key.Config,
		pubKey:  key.PublicKey,
		partyID: vm.partyID,
		thresh:  key.Threshold,
		total:   key.TotalParties,
		gen:     key.Generation,
	}
	sig, err := handler.Sign(ctx, share, session.MessageHash, key.PartyIDs)
	if err != nil {
		return nil, nil, err
	}
	return &ecdsaSignature{R: sig.R().Bytes(), S: sig.S().Bytes(), V: sig.V()}, key.PartyIDs, nil
}
