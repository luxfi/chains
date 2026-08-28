// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// gossip_test.go — the cross-validator transport, in isolation.
//
// The transport moves opaque bytes and interprets no cryptography, so what
// there is to hold here is: an envelope round-trips, a broadcast reaches every
// committee member and nobody else, a directed message reaches one peer, and a
// session that is closing cannot be made to send on a closed channel.

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
	"github.com/luxfi/math/set"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
	"github.com/luxfi/warp"
)

// recordingSender records what the node was asked to gossip and to whom.
type recordingSender struct {
	mu   sync.Mutex
	sent []sentGossip
	err  error
}

type sentGossip struct {
	to  set.Set[ids.NodeID]
	msg []byte
}

func (s *recordingSender) SendGossip(_ context.Context, cfg warp.SendConfig, msg []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return s.err
	}
	s.sent = append(s.sent, sentGossip{to: cfg.NodeIDs, msg: msg})
	return nil
}

func (s *recordingSender) SendRequest(context.Context, set.Set[ids.NodeID], uint32, []byte) error {
	return nil
}
func (s *recordingSender) SendResponse(context.Context, ids.NodeID, uint32, []byte) error { return nil }
func (s *recordingSender) SendError(context.Context, ids.NodeID, uint32, int32, string) error {
	return nil
}

func (s *recordingSender) last() sentGossip {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.sent[len(s.sent)-1]
}

func (s *recordingSender) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.sent)
}

var _ warp.Sender = (*recordingSender)(nil)

// -----------------------------------------------------------------------------
// Envelopes
// -----------------------------------------------------------------------------

// A ceremony message survives the wire unchanged, tagged with the session it
// belongs to, so a validator running several ceremonies at once demultiplexes
// them to the right handler.
func TestACeremonyMessageSurvivesTheWireWithItsSession(t *testing.T) {
	msg := &protocol.Message{
		From:        "pa",
		To:          "pb",
		Protocol:    "cmp/sign",
		RoundNumber: 3,
		Data:        []byte("round data"),
		Broadcast:   true,
	}
	env, err := marshalEnvelope("mpc/session", msg)
	require.NoError(t, err)

	session, got, err := unmarshalEnvelope(env)
	require.NoError(t, err)
	require.Equal(t, "mpc/session", session)
	require.Equal(t, msg.From, got.From)
	require.Equal(t, msg.To, got.To)
	require.Equal(t, msg.Protocol, got.Protocol)
	require.Equal(t, msg.RoundNumber, got.RoundNumber)
	require.Equal(t, msg.Data, got.Data)
	require.Equal(t, msg.Broadcast, got.Broadcast)
}

func TestBytesThatAreNotAnEnvelopeAreRefused(t *testing.T) {
	_, _, err := unmarshalEnvelope([]byte("not json"))
	require.ErrorContains(t, err, "unmarshal envelope")

	// A well-formed envelope whose payload is not a ceremony message.
	env, err := marshalEnvelope("s", &protocol.Message{From: "pa"})
	require.NoError(t, err)
	broken := append([]byte(nil), env...)
	broken[len(broken)-4] ^= 0xff
	_, _, err = unmarshalEnvelope(broken)
	require.Error(t, err)
}

// -----------------------------------------------------------------------------
// Sending
// -----------------------------------------------------------------------------

// A broadcast is an explicit multicast to the ceremony's committee, never a
// validator sample: an MPC round is sound only if EVERY listed signer receives
// every broadcast, and sampling a subset silently starves a signer and stalls
// the round.
func TestABroadcastReachesEveryCommitteeMemberAndNobodyElse(t *testing.T) {
	self := ids.GenerateTestNodeID()
	peers := []ids.NodeID{ids.GenerateTestNodeID(), ids.GenerateTestNodeID()}
	sender := &recordingSender{}
	net := newWarpAppNetwork(sender, self, append([]ids.NodeID{self}, peers...))

	require.NoError(t, net.Broadcast(ctx(), []byte("round one")))
	got := sender.last()
	require.Equal(t, 2, got.to.Len(), "self is excluded; every other committee member is addressed")
	for _, p := range peers {
		require.True(t, got.to.Contains(p))
	}
	require.False(t, got.to.Contains(self))
	require.Equal(t, []byte("round one"), got.msg)
}

// A committee of one has nobody to broadcast to, and says so by sending
// nothing rather than by sending to everyone.
func TestABroadcastToACommitteeOfOneSendsNothing(t *testing.T) {
	self := ids.GenerateTestNodeID()
	sender := &recordingSender{}
	net := newWarpAppNetwork(sender, self, []ids.NodeID{self})

	require.NoError(t, net.Broadcast(ctx(), []byte("alone")))
	require.Zero(t, sender.count())
}

func TestADirectedMessageReachesOnePeerAndNeverThisNode(t *testing.T) {
	self, peer := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	sender := &recordingSender{}
	net := newWarpAppNetwork(sender, self, []ids.NodeID{self, peer})

	require.NoError(t, net.SendTo(ctx(), peer, []byte("for you")))
	got := sender.last()
	require.Equal(t, 1, got.to.Len())
	require.True(t, got.to.Contains(peer))

	require.NoError(t, net.SendTo(ctx(), self, []byte("for me")))
	require.Equal(t, 1, sender.count(), "a node does not gossip to itself")
}

// A node with no p2p cannot carry a ceremony, and says so rather than dropping
// rounds silently.
func TestANodeWithNoSenderCarriesNoCeremony(t *testing.T) {
	net := newWarpAppNetwork(nil, ids.GenerateTestNodeID(), []ids.NodeID{ids.GenerateTestNodeID()})
	require.ErrorContains(t, net.Broadcast(ctx(), nil), "no warp sender")
	require.ErrorContains(t, net.SendTo(ctx(), ids.GenerateTestNodeID(), nil), "no warp sender")

	vm := newVM(t)
	_, _, err := vm.ceremonyRouter(ctx(), "mpc/x", parties(3))
	require.ErrorContains(t, err, "no warp sender")
}

// -----------------------------------------------------------------------------
// The router
// -----------------------------------------------------------------------------

func TestTheRouterBroadcastsOrAddressesByWhatTheMessageSays(t *testing.T) {
	self, peer := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	sender := &recordingSender{}
	net := newWarpAppNetwork(sender, self, []ids.NodeID{self, peer})
	router := newGossipRouter(ctx(), "mpc/s", party.ID(self.String()), net,
		map[party.ID]ids.NodeID{party.ID(peer.String()): peer})

	require.NoError(t, router.Send(&protocol.Message{From: party.ID(self.String())}))
	require.Equal(t, 1, sender.count())

	require.NoError(t, router.Send(&protocol.Message{From: party.ID(self.String()), To: party.ID(peer.String())}))
	require.Equal(t, 2, sender.count())
	require.True(t, sender.last().to.Contains(peer))

	require.NoError(t, router.Send(nil), "nothing to send is not an error")
	require.Equal(t, 2, sender.count())
}

// A message addressed to a party this ceremony has no validator for is an
// error, not a silent drop: the round will stall either way, and only one of
// those says why.
func TestAMessageForAPartyWithNoValidatorIsNamed(t *testing.T) {
	sender := &recordingSender{}
	self := ids.GenerateTestNodeID()
	net := newWarpAppNetwork(sender, self, []ids.NodeID{self})
	router := newGossipRouter(ctx(), "mpc/s", party.ID(self.String()), net, nil)

	err := router.Send(&protocol.Message{From: party.ID(self.String()), To: "nobody"})
	require.ErrorContains(t, err, "no validator for party nobody")
}

func TestATransportFailureIsReportedNotSwallowed(t *testing.T) {
	sender := &recordingSender{err: errors.New("network down")}
	self, peer := ids.GenerateTestNodeID(), ids.GenerateTestNodeID()
	net := newWarpAppNetwork(sender, self, []ids.NodeID{self, peer})
	router := newGossipRouter(ctx(), "mpc/s", party.ID(self.String()), net,
		map[party.ID]ids.NodeID{party.ID(peer.String()): peer})

	require.ErrorContains(t, router.Send(&protocol.Message{From: party.ID(self.String())}), "network down")
	require.ErrorContains(t, router.Send(&protocol.Message{
		From: party.ID(self.String()), To: party.ID(peer.String()),
	}), "network down")
}

// A router drops a message rather than blocking consensus on a full inbox, and
// never sends on a closed channel however late a peer's gossip arrives.
func TestALateMessageNeverSendsOnAClosedSession(t *testing.T) {
	router := newGossipRouter(ctx(), "mpc/s", "self", nil, nil)

	router.Deliver(nil)
	router.Deliver(&protocol.Message{From: "self"})
	require.Empty(t, router.Receive(), "a router does not deliver this node's own message back to it")

	router.Deliver(&protocol.Message{From: "pa"})
	require.Len(t, router.Receive(), 1)
	<-router.Receive()

	router.Close()
	router.Close() // idempotent
	require.NotPanics(t, func() { router.Deliver(&protocol.Message{From: "pa"}) },
		"a peer still gossiping as the session tears down must not crash this node")
}

func TestAFullInboxDropsRatherThanBlocks(t *testing.T) {
	router := newGossipRouter(ctx(), "mpc/s", "self", nil, nil)
	for i := 0; i < cap(router.inbox)+50; i++ {
		router.Deliver(&protocol.Message{From: "pa", RoundNumber: 1})
	}
	require.Equal(t, cap(router.inbox), len(router.Receive()),
		"blocking here would block the consensus goroutine that called Gossip")
}

// -----------------------------------------------------------------------------
// party.ID is the NodeID string
// -----------------------------------------------------------------------------

// The committee and the peer set are the same value in two spellings, so the
// mapping from a signer back to the validator that runs it is the exact
// inverse, with no side table to drift.
func TestASignerResolvesToTheValidatorThatRunsIt(t *testing.T) {
	nodes := []ids.NodeID{ids.GenerateTestNodeID(), ids.GenerateTestNodeID()}
	signers := []party.ID{party.ID(nodes[0].String()), party.ID(nodes[1].String())}

	resolved, peers, err := resolveCommittee(signers)
	require.NoError(t, err)
	require.Equal(t, nodes, resolved)
	for i, s := range signers {
		require.Equal(t, nodes[i], peers[s])
	}
}

func TestASignerThatIsNotANodeIdIsNamed(t *testing.T) {
	_, _, err := resolveCommittee([]party.ID{"not-a-node-id"})
	require.ErrorContains(t, err, "is not a node id")
}
