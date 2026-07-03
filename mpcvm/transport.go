// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// transport.go — the MessageRouter concrete implementations that let an MPC
// ceremony (DKG / sign / reshare) run NATIVELY across the M-Chain's validators
// instead of the old off-chain REST cluster (luxfi/mpc). The executor drives a
// per-party threshold protocol.Handler; the router carries that handler's
// messages to the other parties and delivers theirs back. Two impls:
//
//   - inProcRouter: a shared in-memory mesh. Used by unit tests and by a
//     single-process/local dev node. This is the SAME fan-out the threshold
//     library's own test harness uses (broadcast-to-all-except-sender, or a
//     directed send by To), lifted to the MessageRouter boundary so the exact
//     executor code path that runs in production is exercised under test.
//
//   - gossipRouter: the cross-validator transport. Each validator runs its own
//     mpcvm with its own party.ID; the router serialises a ceremony message into
//     a session-tagged envelope and broadcasts it over the chain's app-gossip
//     (or sends it to one peer), and the VM's app-message handler calls Deliver
//     to feed incoming envelopes back to the right session. Decoupled from node
//     types via the small AppNetwork interface so this file stays node-free and
//     unit-testable; the VM supplies an AppNetwork backed by its AppSender.
//
// threshold stays the shared library — the router only moves its opaque
// protocol.Message bytes; it never interprets the cryptography.

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"

	"github.com/luxfi/ids"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// =============================================================================
// In-process mesh (tests + single-node local)
// =============================================================================

// inProcNetwork is a shared in-memory bus for one ceremony running inside a
// single process. Per-party buffered inboxes; Send fans a message out to its
// targets. Close drains in-flight sends before shutting the inboxes so a
// "go router loop" + deferred Close is race-free (mirrors the close discipline
// of threshold/internal/test.Network).
type inProcNetwork struct {
	mu       sync.RWMutex
	inboxes  map[party.ID]chan *protocol.Message
	inFlight sync.RWMutex
	closed   bool
}

// newInProcNetwork builds an in-memory mesh over the given parties.
func newInProcNetwork(parties []party.ID) *inProcNetwork {
	n := &inProcNetwork{inboxes: make(map[party.ID]chan *protocol.Message, len(parties))}
	for _, id := range parties {
		n.inboxes[id] = make(chan *protocol.Message, 1024)
	}
	return n
}

// send delivers msg to its targets: every party but the sender when To=="",
// otherwise the single addressed party.
func (n *inProcNetwork) send(msg *protocol.Message) {
	if msg == nil {
		return
	}
	n.inFlight.RLock()
	defer n.inFlight.RUnlock()
	if n.closed {
		return
	}
	n.mu.RLock()
	var targets []chan *protocol.Message
	if msg.To == "" {
		for id, ch := range n.inboxes {
			if id != msg.From {
				targets = append(targets, ch)
			}
		}
	} else if ch, ok := n.inboxes[msg.To]; ok {
		targets = append(targets, ch)
	}
	n.mu.RUnlock()
	for _, ch := range targets {
		ch <- msg
	}
}

// inbox returns a party's receive channel.
func (n *inProcNetwork) inbox(id party.ID) chan *protocol.Message {
	n.mu.RLock()
	defer n.mu.RUnlock()
	return n.inboxes[id]
}

// close shuts every inbox after in-flight sends drain, unblocking the router
// receive loops (which range over the inbox channel).
func (n *inProcNetwork) close() {
	n.inFlight.Lock()
	defer n.inFlight.Unlock()
	if n.closed {
		return
	}
	n.closed = true
	n.mu.Lock()
	defer n.mu.Unlock()
	for _, ch := range n.inboxes {
		close(ch)
	}
}

// inProcRouter is one party's MessageRouter view onto a shared inProcNetwork.
type inProcRouter struct {
	self party.ID
	net  *inProcNetwork
}

// newInProcRouters builds a mesh plus one router per party, ready to hand to
// each party's executor. Call net.close() once every party's ceremony returns.
func newInProcRouters(parties []party.ID) (*inProcNetwork, map[party.ID]*inProcRouter) {
	net := newInProcNetwork(parties)
	routers := make(map[party.ID]*inProcRouter, len(parties))
	for _, id := range parties {
		routers[id] = &inProcRouter{self: id, net: net}
	}
	return net, routers
}

// Send implements MessageRouter.
func (r *inProcRouter) Send(msg *protocol.Message) error {
	r.net.send(msg)
	return nil
}

// Receive implements MessageRouter.
func (r *inProcRouter) Receive() <-chan *protocol.Message { return r.net.inbox(r.self) }

// =============================================================================
// Cross-validator gossip transport (production)
// =============================================================================

// AppNetwork is the minimal consensus-gossip send capability the gossipRouter
// needs. The VM implements it over the node AppSender it receives at
// Initialize. Kept as an interface so this file imports no node packages and
// stays unit-testable.
type AppNetwork interface {
	// Broadcast reliably gossips an app message to the chain's validators.
	Broadcast(ctx context.Context, msg []byte) error
	// SendTo sends an app message to a single validator.
	SendTo(ctx context.Context, nodeID ids.NodeID, msg []byte) error
}

// sessionEnvelope wraps one ceremony message with its session id so a receiving
// validator can demultiplex concurrent ceremonies to the right handler.
type sessionEnvelope struct {
	SessionID string `json:"sessionId"`
	Message   []byte `json:"message"` // protocol.Message, wire-encoded
}

// marshalEnvelope encodes a ceremony message for gossip.
func marshalEnvelope(sessionID string, msg *protocol.Message) ([]byte, error) {
	wire, err := msg.MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("mpcvm: marshal ceremony message: %w", err)
	}
	return json.Marshal(sessionEnvelope{SessionID: sessionID, Message: wire})
}

// unmarshalEnvelope decodes a gossiped ceremony message.
func unmarshalEnvelope(b []byte) (string, *protocol.Message, error) {
	var env sessionEnvelope
	if err := json.Unmarshal(b, &env); err != nil {
		return "", nil, fmt.Errorf("mpcvm: unmarshal envelope: %w", err)
	}
	msg := &protocol.Message{}
	if err := msg.UnmarshalBinary(env.Message); err != nil {
		return "", nil, fmt.Errorf("mpcvm: unmarshal ceremony message: %w", err)
	}
	return env.SessionID, msg, nil
}

// gossipRouter carries one party's ceremony messages over consensus gossip and
// feeds incoming ones (delivered by the VM's app-message handler) to the local
// handler. One gossipRouter per (session, self-party).
type gossipRouter struct {
	ctx       context.Context
	sessionID string
	self      party.ID
	net       AppNetwork
	// peers maps a threshold party.ID to the validator NodeID that runs it, so
	// a directed (To != "") ceremony message becomes an app-request to one peer.
	peers map[party.ID]ids.NodeID
	inbox chan *protocol.Message
}

// newGossipRouter builds the cross-validator router for one session.
func newGossipRouter(
	ctx context.Context,
	sessionID string,
	self party.ID,
	net AppNetwork,
	peers map[party.ID]ids.NodeID,
) *gossipRouter {
	return &gossipRouter{
		ctx:       ctx,
		sessionID: sessionID,
		self:      self,
		net:       net,
		peers:     peers,
		inbox:     make(chan *protocol.Message, 1024),
	}
}

// Send implements MessageRouter: broadcast when To=="", else a directed send to
// the validator that runs the addressed party.
func (r *gossipRouter) Send(msg *protocol.Message) error {
	if msg == nil {
		return nil
	}
	env, err := marshalEnvelope(r.sessionID, msg)
	if err != nil {
		return err
	}
	if msg.To == "" {
		return r.net.Broadcast(r.ctx, env)
	}
	nodeID, ok := r.peers[msg.To]
	if !ok {
		return fmt.Errorf("mpcvm: no validator for party %s", msg.To)
	}
	return r.net.SendTo(r.ctx, nodeID, env)
}

// Receive implements MessageRouter.
func (r *gossipRouter) Receive() <-chan *protocol.Message { return r.inbox }

// Deliver hands an incoming ceremony message (already demultiplexed to this
// session) to the local handler. Called by the VM's app-message handler; drops
// on a full inbox rather than blocking consensus.
func (r *gossipRouter) Deliver(msg *protocol.Message) {
	if msg == nil || msg.From == r.self {
		return
	}
	select {
	case r.inbox <- msg:
	default:
	}
}

// Close releases the receive channel when the session ends.
func (r *gossipRouter) Close() { close(r.inbox) }

// Compile-time checks that both routers satisfy MessageRouter.
var (
	_ MessageRouter = (*inProcRouter)(nil)
	_ MessageRouter = (*gossipRouter)(nil)
)
