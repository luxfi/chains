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
	"crypto/sha256"
	"encoding/hex"
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

// There is exactly one signing path: custody.go's thresholdSign, driven by
// RunSign. The VM previously carried two more — a CGGMP21 path keyed off an
// in-memory ManagedKey and a registry-handler fallback — and a key could be
// signed under whichever one the caller happened to reach, with different
// quorum rules on each. Fan-in at the router, not at the caller.
