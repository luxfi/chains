// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// mesh_test.go — an in-memory MessageRouter for the executor tests.
//
// It lives here rather than beside the gossip router because it is scaffolding:
// nothing in production has a second transport, and one that shipped in the
// binary would be a second way for a ceremony to run. The fan-out matches the
// real one (broadcast to everyone but the sender, or a directed send by To) so
// the executor path under test is the executor path that runs.

import (
	"sync"

	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/protocol"
)

// mesh is a shared in-memory bus for one ceremony inside one process.
type mesh struct {
	mu       sync.RWMutex
	inboxes  map[party.ID]chan *protocol.Message
	inFlight sync.RWMutex
	closed   bool
}

func newMesh(parties []party.ID) *mesh {
	m := &mesh{inboxes: make(map[party.ID]chan *protocol.Message, len(parties))}
	for _, id := range parties {
		m.inboxes[id] = make(chan *protocol.Message, 1024)
	}
	return m
}

func (m *mesh) send(msg *protocol.Message) {
	if msg == nil {
		return
	}
	m.inFlight.RLock()
	defer m.inFlight.RUnlock()
	if m.closed {
		return
	}
	m.mu.RLock()
	var targets []chan *protocol.Message
	if msg.To == "" {
		for id, ch := range m.inboxes {
			if id != msg.From {
				targets = append(targets, ch)
			}
		}
	} else if ch, ok := m.inboxes[msg.To]; ok {
		targets = append(targets, ch)
	}
	m.mu.RUnlock()
	for _, ch := range targets {
		ch <- msg
	}
}

// close shuts every inbox once in-flight sends have drained, so a router loop
// ranging over its inbox unwinds without racing a send.
func (m *mesh) close() {
	m.inFlight.Lock()
	defer m.inFlight.Unlock()
	if m.closed {
		return
	}
	m.closed = true
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, ch := range m.inboxes {
		close(ch)
	}
}

// meshRouter is one party's view of the mesh.
type meshRouter struct {
	self party.ID
	net  *mesh
}

func (r *meshRouter) Send(msg *protocol.Message) error { r.net.send(msg); return nil }

func (r *meshRouter) Receive() <-chan *protocol.Message {
	r.net.mu.RLock()
	defer r.net.mu.RUnlock()
	return r.net.inboxes[r.self]
}

// newMeshRouters builds a mesh plus one router per party. Call net.close() once
// every party's ceremony has returned.
func newMeshRouters(parties []party.ID) (*mesh, map[party.ID]*meshRouter) {
	net := newMesh(parties)
	routers := make(map[party.ID]*meshRouter, len(parties))
	for _, id := range parties {
		routers[id] = &meshRouter{self: id, net: net}
	}
	return net, routers
}

var _ MessageRouter = (*meshRouter)(nil)
