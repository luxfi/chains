// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// custody.go — the ceremony lifecycle: how a threshold key comes into being and
// how it signs, and how each of those becomes a verifiable state transition.
//
// # Leaderless by derivation
//
// There is no coordinator and no privileged proposer. Every validator that
// observes the same request independently computes the same ceremony id from
// the task itself — H(tag ‖ keyID ‖ digest ‖ sorted signers) — so the round
// messages demultiplex correctly without a coordination round electing anyone.
// Every honest participant finishes holding the SAME signature, stages the SAME
// operation, and whichever validator happens to propose the next block carries
// it; the rest verify it against their own state and agree. Nothing about the
// outcome depends on who proposed.
//
// # Permissionless by construction
//
// The committee is the chain's own validator set (Committee below). Joining the
// signing ring is joining the validator set — there is no allowlist, no
// operator registry, and no key ceremony gated on an admin. A new validator
// participates in every key generated after it joins, and is reshared into
// existing keys by the resharing path.
//
// # Why this is the fix for off-chain signer clusters
//
// An off-chain cluster's quorum is whatever each binary happened to be
// configured with; a config that says 3-of-5 while the binary generated a
// degree-0 key produces a 1-of-n key and nothing notices until an audit. Here
// the policy is in consensus state, the degree is derived from it at exactly
// one place (quorum.Policy.Degree), and a block registering a key whose degree
// disagrees with a participant's own share is rejected by that participant.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/quorum"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
)

// keygenDomainTag domain-separates a keygen ceremony id from a signing ceremony
// id, so the two can never collide even for identical (key, participant) inputs.
const keygenDomainTag = "LUX_MPC_KEYGEN_v1"

// KindCGGMP21 names the threshold-ECDSA protocol used for bridge custody of
// external wallets. It is the value stored in KeyRecord.Kind.
const KindCGGMP21 = "cggmp21"

var (
	ErrNoCommittee    = errors.New("mpcvm: no validator committee available")
	ErrNotParticipant = errors.New("mpcvm: this node is not in the ceremony committee")
	ErrPolicyTooLarge = errors.New("mpcvm: policy requires more parties than the committee has")
)

// heldShare is this node's secret material for one custody key, plus the public
// facts derivable from it. It is the value the participant cross-check reads.
type heldShare struct {
	kind string
	cmp  *cmpconfig.Config
}

// groupKeyAndDegree returns the compressed group public key and the polynomial
// degree this share was generated with. These are the two facts a participant
// uses to contradict a mis-declared key registration.
func (h *heldShare) groupKeyAndDegree() ([]byte, int, error) {
	if h == nil || h.cmp == nil {
		return nil, 0, errors.New("mpcvm: empty share")
	}
	pub, err := h.cmp.PublicPoint().MarshalBinary()
	if err != nil {
		return nil, 0, err
	}
	return pub, h.cmp.Threshold, nil
}

// marshal serialises the share for node-private storage.
func (h *heldShare) marshal() ([]byte, error) {
	if h.cmp == nil {
		return nil, errors.New("mpcvm: no share to store")
	}
	return h.cmp.MarshalBinary()
}

// parseHeldShare reads a node-private share back.
func parseHeldShare(kind string, raw []byte) (*heldShare, error) {
	cfg := cmpconfig.EmptyConfig(nil)
	if err := cfg.UnmarshalBinary(raw); err != nil {
		return nil, fmt.Errorf("mpcvm: share for kind %s: %w", kind, err)
	}
	return &heldShare{kind: kind, cmp: cfg}, nil
}

// keygenCeremonyID derives the session id for a key generation. A keygen has no
// message to bind, so it binds the key id, the policy and the committee: two
// nodes that disagree about any of those run different ceremonies rather than
// silently producing incompatible shares of the same session.
func keygenCeremonyID(keyID string, policy quorum.Policy, participants []party.ID) string {
	h := sha256.New()
	writeTagged(h, keygenDomainTag)
	writeField(h, []byte(keyID))
	writeUint64(h, uint64(policy.K))
	writeUint64(h, uint64(policy.N))
	writeParties(h, participants)
	return "mpc/keygen/" + hex.EncodeToString(h.Sum(nil))
}

// Committee returns the ceremony party set: every validator of this chain at
// the given P-Chain height, in canonical order.
//
// party.ID is the NodeID string, so the mapping from a signer back to the peer
// that runs it is the exact inverse with no side table to drift out of sync.
// Canonical ordering makes the set order-independent, which is what lets every
// validator derive the same ceremony id without exchanging one.
func (vm *VM) Committee(ctx context.Context, height uint64) ([]party.ID, error) {
	if vm.rt == nil || vm.rt.ValidatorState == nil {
		return nil, ErrNoCommittee
	}
	set, err := vm.rt.ValidatorState.GetValidatorSet(ctx, height, vm.netID)
	if err != nil {
		return nil, fmt.Errorf("mpcvm: validator set at height %d: %w", height, err)
	}
	if len(set) == 0 {
		return nil, ErrNoCommittee
	}
	out := make([]party.ID, 0, len(set))
	for nodeID := range set {
		out = append(out, party.ID(nodeID.String()))
	}
	return canonicalParties(out), nil
}

// RunKeygen generates a custody key across the committee and stages its
// registration for the next block.
//
// The ceremony is: distributed key generation (no dealer — no party ever holds
// the whole secret), then a threshold signature by the fresh group key over its
// own registration digest. That second step is the proof of possession: it
// demonstrates the committee really can sign with the key it is registering, so
// a key that would be dead on arrival never reaches the registry, and a
// proposer cannot register a public key it does not control.
//
// Every participant runs this and stages an identical operation. Non-blocking
// on the caller's behalf is the caller's business; this returns when the
// ceremony is done.
func (vm *VM) RunKeygen(ctx context.Context, keyID string, policy quorum.Policy, requestingChain string) (*Operation, error) {
	if !policy.Valid() {
		return nil, fmt.Errorf("mpcvm: keygen for %s: undeployable policy %s", keyID, policy)
	}
	vm.mu.RLock()
	pchainHeight := vm.rt.PChainHeight
	selfID := vm.partyID
	vm.mu.RUnlock()

	participants, err := vm.Committee(ctx, pchainHeight)
	if err != nil {
		return nil, err
	}
	if len(participants) < policy.N {
		return nil, fmt.Errorf("%w: policy %s needs %d parties, committee has %d",
			ErrPolicyTooLarge, policy, policy.N, len(participants))
	}
	// The committee is the first N validators in canonical order. Deterministic
	// selection, so every node picks the same N without negotiating.
	participants = participants[:policy.N]
	if !containsParty(participants, selfID) {
		return nil, ErrNotParticipant
	}

	if has, err := vm.state.HasKey(keyID); err != nil {
		return nil, err
	} else if has {
		return nil, fmt.Errorf("%w: %s", ErrKeyExists, keyID)
	}

	cid := keygenCeremonyID(keyID, policy, participants)

	// THE conversion: operator policy -> protocol degree, at one boundary.
	// cmp.Keygen reads its threshold argument as t, the polynomial degree, and
	// a t-degree key needs t+1 signers. Handing it K directly is what produces
	// a (K+1)-of-N key from a config that says K-of-N.
	degree := policy.Degree()

	cfg, err := vm.runCMPKeygen(ctx, cid, selfID, participants, degree)
	if err != nil {
		return nil, fmt.Errorf("mpcvm: keygen %s: %w", keyID, err)
	}
	if cfg.Threshold != degree {
		// The library disagreeing with us about degree is not survivable: the
		// key would silently require a different quorum than the registry says.
		return nil, fmt.Errorf("mpcvm: keygen %s produced degree %d, policy %s requires %d",
			keyID, cfg.Threshold, policy, degree)
	}

	groupPub, err := cfg.PublicPoint().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("mpcvm: keygen %s: encode group key: %w", keyID, err)
	}
	address := publicKeyToAddress(groupPub)
	if address == nil {
		return nil, fmt.Errorf("mpcvm: keygen %s produced an underivable address", keyID)
	}

	rec := &KeyRecord{
		KeyID:          keyID,
		Kind:           KindCGGMP21,
		Policy:         policy,
		Participants:   participants,
		GroupPublicKey: groupPub,
		Address:        address,
		Generation:     0,
	}
	if err := rec.Validate(); err != nil {
		return nil, err
	}

	share := &heldShare{kind: KindCGGMP21, cmp: cfg}

	// Proof of possession: the new key signs its own registration.
	commit := KeyCommitDigest(rec)
	pop, err := vm.thresholdSign(ctx, rec, share, commit[:], participants)
	if err != nil {
		return nil, fmt.Errorf("mpcvm: keygen %s: proof of possession: %w", keyID, err)
	}

	// Store the share only once the key has demonstrably worked. A share for a
	// key that cannot sign is worse than no share: it makes the node claim
	// participation it cannot honour.
	raw, err := share.marshal()
	if err != nil {
		return nil, err
	}
	vm.mu.Lock()
	if err := vm.state.PutShare(keyID, raw); err != nil {
		vm.mu.Unlock()
		return nil, err
	}
	vm.shares[keyID] = share
	vm.mu.Unlock()

	op := &Operation{
		Type:            OpTypeKeygen,
		CeremonyID:      cid,
		KeyID:           keyID,
		RequestingChain: requestingChain,
		Digest:          commit[:],
		Artifact:        pop,
		Signers:         participants,
		Key:             rec,
		Timestamp:       time.Now().Unix(),
	}
	vm.stage(op)

	vm.log.Info("custody key generated",
		log.String("keyID", keyID),
		log.String("policy", policy.String()),
		log.Int("degree", degree),
		log.String("address", "0x"+hex.EncodeToString(address)),
		log.String("ceremony", cid),
	)
	return op, nil
}

// RunSign produces a threshold signature over digest with a registered custody
// key and stages it for the next block.
//
// digest must be the exact 32 bytes to sign. M-Chain does not hash on the
// caller's behalf: the caller knows its own signing domain (an Ethereum tx
// hash, a bridge release digest), and a chain that re-hashes would produce
// signatures over a preimage the caller never authorised.
func (vm *VM) RunSign(ctx context.Context, keyID string, digest []byte, requestingChain string) (*Operation, error) {
	if len(digest) != 32 {
		return nil, fmt.Errorf("mpcvm: sign %s: digest is %d bytes, want 32", keyID, len(digest))
	}
	rec, err := vm.state.GetKey(keyID)
	if err != nil {
		return nil, err
	}

	vm.mu.RLock()
	share, held := vm.shares[keyID]
	selfID := vm.partyID
	vm.mu.RUnlock()
	if !held {
		return nil, fmt.Errorf("%w: %s", ErrShareNotHeld, keyID)
	}
	if !containsParty(rec.Participants, selfID) {
		return nil, ErrNotParticipant
	}

	// The signer set is the key's full participant set. Every member signs.
	// Selecting a minimal K-subset under partial availability is a liveness
	// optimisation, not a correctness one, and it is deliberately not done
	// here: a subset chosen independently by each node would give different
	// nodes different ceremony ids and no ceremony would ever converge.
	signers := rec.Participants
	cid := ceremonyID(keyID, digest, signers)

	if _, err := vm.state.GetCeremony(cid); err == nil {
		return nil, fmt.Errorf("%w: %s", ErrCeremonyExists, cid)
	}

	sig, err := vm.thresholdSign(ctx, rec, share, digest, signers)
	if err != nil {
		return nil, fmt.Errorf("mpcvm: sign %s: %w", keyID, err)
	}
	// Check our own work before asking the network to accept it. A signature
	// that does not verify locally will be rejected by every peer anyway, and
	// finding out here names the ceremony instead of the block.
	if err := verifyGroupSignature(rec.GroupPublicKey, digest, sig); err != nil {
		return nil, fmt.Errorf("mpcvm: sign %s produced a signature that does not verify: %w", keyID, err)
	}

	op := &Operation{
		Type:            OpTypeSign,
		CeremonyID:      cid,
		KeyID:           keyID,
		RequestingChain: requestingChain,
		Digest:          append([]byte(nil), digest...),
		Artifact:        sig,
		Signers:         signers,
		Timestamp:       time.Now().Unix(),
	}
	vm.stage(op)

	vm.log.Info("custody signature produced",
		log.String("keyID", keyID),
		log.String("policy", rec.Policy.String()),
		log.Int("signers", len(signers)),
		log.String("ceremony", cid),
	)
	return op, nil
}

// thresholdSign runs one CGGMP21 signing ceremony over the gossip transport and
// returns the canonical 65-byte r‖s‖v signature. Every honest signer returns
// the same bytes.
func (vm *VM) thresholdSign(
	ctx context.Context,
	rec *KeyRecord,
	share *heldShare,
	digest []byte,
	signers []party.ID,
) ([]byte, error) {
	if share == nil || share.cmp == nil {
		return nil, fmt.Errorf("%w: %s", ErrShareNotHeld, rec.KeyID)
	}
	cid := ceremonyID(rec.KeyID, digest, signers)
	router, release, err := vm.ceremonyRouter(ctx, cid, signers)
	if err != nil {
		return nil, err
	}
	defer release()

	sig, err := vm.protocolExecutor.RunCMPSign(ctx, cid, share.cmp, signers, digest, router)
	if err != nil {
		return nil, err
	}
	if len(sig.R) != 32 || len(sig.S) != 32 {
		return nil, fmt.Errorf("mpcvm: malformed signature parts r=%d s=%d", len(sig.R), len(sig.S))
	}
	out := make([]byte, 0, 65)
	out = append(out, sig.R...)
	out = append(out, sig.S...)
	return append(out, sig.V), nil
}

// runCMPKeygen runs one distributed key generation over the gossip transport.
//
// It goes through the same per-ceremony router as signing rather than the
// protocol registry's handler, because a handler holds ONE router for the whole
// VM: two concurrent ceremonies would interleave on it, and a VM that never had
// one set could not run a keygen at all.
func (vm *VM) runCMPKeygen(
	ctx context.Context,
	cid string,
	selfID party.ID,
	participants []party.ID,
	degree int,
) (*cmpconfig.Config, error) {
	router, release, err := vm.ceremonyRouter(ctx, cid, participants)
	if err != nil {
		return nil, err
	}
	defer release()
	return vm.protocolExecutor.RunCMPKeygen(ctx, cid, selfID, participants, degree, router)
}

// ceremonyRouter builds the transport for one ceremony and registers it so
// inbound gossip for that ceremony finds it. release tears it down.
func (vm *VM) ceremonyRouter(ctx context.Context, cid string, parties []party.ID) (MessageRouter, func(), error) {
	if vm.sender == nil {
		// Single-process operation with no p2p. The in-process mesh is the same
		// MessageRouter boundary, so the executor path under test is the path
		// that runs in production; only the wire underneath differs.
		if vm.localMesh == nil {
			return nil, nil, errors.New("mpcvm: no warp sender and no local mesh; cross-validator ceremonies unavailable")
		}
		mesh := vm.localMesh
		return mesh.routerFor(cid, vm.partyID), func() { mesh.release(cid) }, nil
	}
	nodes, peers, err := resolveCommittee(parties)
	if err != nil {
		return nil, nil, err
	}
	appNet := newWarpAppNetwork(vm.sender, vm.rt.NodeID, nodes)
	router := newGossipRouter(ctx, cid, vm.partyID, appNet, peers)
	vm.registerSessionRouter(cid, router)
	return router, func() { vm.unregisterSessionRouter(cid) }, nil
}

// stage queues a completed operation for inclusion in the next block and wakes
// the block builder. Staging is idempotent on ceremony id: a ceremony that
// completes twice (a re-proposal after a rejected block) stages once.
func (vm *VM) stage(op *Operation) {
	vm.mu.Lock()
	if _, dup := vm.inflight[op.CeremonyID]; dup {
		vm.mu.Unlock()
		return
	}
	vm.inflight[op.CeremonyID] = op
	vm.order = append(vm.order, op.CeremonyID)
	vm.mu.Unlock()

	// Tell the engine there is work. Non-blocking: a full channel means the
	// engine already has a pending build notification, which is all this is.
	select {
	case vm.buildRequests <- struct{}{}:
	default:
	}
}

// drain returns the staged operations in staging order, ready for a block.
// Caller holds vm.mu.
func (vm *VM) drain(limit int) []*Operation {
	out := make([]*Operation, 0, min(limit, len(vm.order)))
	for _, cid := range vm.order {
		if len(out) == limit {
			break
		}
		if op, ok := vm.inflight[cid]; ok {
			out = append(out, op)
		}
	}
	return out
}

func containsParty(ps []party.ID, want party.ID) bool {
	for _, p := range ps {
		if p == want {
			return true
		}
	}
	return false
}

// netID is the network (subnet) this chain validates. M-Chain runs on the
// primary network, so its committee is the primary validator set.
var _ = ids.Empty
