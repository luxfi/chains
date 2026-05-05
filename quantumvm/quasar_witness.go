// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.
//
// Q-Chain Ringtail witness producer for Quasar parallel-witness finality
// (LP-020 §2 Consensus Modes, witness set bit WitnessQ).
//
// The Q-Chain VM is the parallel finality witness for the Q lane. Each
// consensus round, the Quasar driver pushes a 32-byte round digest to this
// adapter; the adapter drives the underlying Ringtail 2-round threshold
// ceremony (Module-LWE, eprint 2024/1113) and returns the resulting
// threshold signature as the round's Q-witness.
//
// The method signature matches consensus/protocol/quasar.QWitnessProducer
// (Witness(ctx, [32]byte) ([]byte, error)) so this adapter satisfies that
// interface structurally once the consensus dependency is bumped to ship
// the new type.

package quantumvm

import (
	"context"
	"errors"
	"sync"
)

// QWitnessAdapter adapts the Q-Chain Quasar engine to the consensus
// QWitnessProducer interface used by the Quasar round driver.
//
// TODO(pqz): wire to a real per-round Ringtail ceremony driver. The current
// quantumvm.Quasar engine signs per-block by validator id; a per-consensus-
// round driver is required to land a true Q-witness. See LP-020 §9
// Implementation, "Three-lane signing".
type QWitnessAdapter struct {
	mu     sync.RWMutex
	engine *Quasar
}

// NewQWitnessAdapter constructs a Q-witness adapter backed by the given
// Q-Chain Quasar engine. Pass the engine returned by NewQuasar.
func NewQWitnessAdapter(engine *Quasar) *QWitnessAdapter {
	return &QWitnessAdapter{engine: engine}
}

// ErrQWitnessNotWired is returned by QWitnessAdapter.Witness until the
// per-round Ringtail driver lands. The interface is in place so the
// consensus driver can be configured today.
var ErrQWitnessNotWired = errors.New("Q-Chain per-round Ringtail driver not wired (TODO LP-020 §9)")

// Witness produces a Ringtail threshold signature over the round digest.
// Signature matches consensus/protocol/quasar.QWitnessProducer.
//
// Returns ErrQWitnessNotWired today; the round driver treats this as the
// witness being unavailable and finalizes at PolicyQuorum (or PolicyPZ if
// Z is enabled).
func (a *QWitnessAdapter) Witness(ctx context.Context, digest [32]byte) ([]byte, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if a.engine == nil {
		return nil, ErrQWitnessNotWired
	}
	// Eventual implementation: drive a Ringtail 2-round threshold ceremony
	// (a.engine.SignBlock + AddRingtailSignature loop with consensus peers,
	// then TryFinalize) and return the aggregated Ringtail bytes from the
	// resulting AggregatedSignature.
	_ = ctx
	_ = digest
	return nil, ErrQWitnessNotWired
}
