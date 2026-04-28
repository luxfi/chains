// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package types defines the data types of the ThresholdVM substrate.
//
// These types are imported by both M-Chain (chains/mchain) and F-Chain
// (chains/fchain). The substrate has no runtime; types here are pure
// values, the state machine is an explicit-transition function, and
// the registry types in cert/ are constructed (not singletons) by the
// host chain.
package types

import (
	"errors"
	"fmt"
)

// CeremonyState is the position of a ceremony in the shared state
// machine. The same machine is used by every protocol on M-Chain and
// F-Chain; only the per-round payload differs.
type CeremonyState uint8

const (
	StateUnknown    CeremonyState = 0
	StateRegistered CeremonyState = 1 // participant set committed, no shares yet
	StateRound1     CeremonyState = 2 // round-1 commitments published
	StateRound2     CeremonyState = 3 // round-2 shares published
	StateFinalized  CeremonyState = 4 // cert artifact emitted, root advanced
	StateAborted    CeremonyState = 5 // identifiable abort (CGGMP21 etc.) or timeout
)

// String returns a stable label for logs.
func (s CeremonyState) String() string {
	switch s {
	case StateRegistered:
		return "registered"
	case StateRound1:
		return "round1"
	case StateRound2:
		return "round2"
	case StateFinalized:
		return "finalized"
	case StateAborted:
		return "aborted"
	default:
		return "unknown"
	}
}

// CeremonyKind names the protocol the ceremony executes. The kind
// determines which CertLane the finalized artifact uses and which
// verifier validates each round's payload. Adding a new kind appends
// here and adds a CertLane in cert/lane.go — never reorders.
type CeremonyKind uint8

const (
	KindUnknown        CeremonyKind = 0
	KindCGGMP21        CeremonyKind = 1 // M-Chain: ECDSA threshold
	KindFROST          CeremonyKind = 2 // M-Chain: Schnorr/EdDSA threshold
	KindRingtailGen    CeremonyKind = 3 // M-Chain: PQ general-purpose threshold
	KindTFHEKeygen     CeremonyKind = 4 // M-Chain → F-Chain: TFHE bootstrap-key gen
	KindTFHECompute    CeremonyKind = 5 // F-Chain: encrypted compute attestation
	KindTFHEBootstrap  CeremonyKind = 6 // F-Chain: blind-rotate / bootstrap proof
)

// IsMChain reports whether the kind belongs to the M-Chain operational chain.
func (k CeremonyKind) IsMChain() bool {
	return k == KindCGGMP21 || k == KindFROST || k == KindRingtailGen
}

// IsFChain reports whether the kind belongs to the F-Chain operational chain.
func (k CeremonyKind) IsFChain() bool {
	return k == KindTFHECompute || k == KindTFHEBootstrap
}

// IsHandoff reports whether the kind is a cross-chain (M → F) ceremony.
// Handoff ceremonies originate on M-Chain and finalize into F-Chain via
// the bootstrap-handoff envelope.
func (k CeremonyKind) IsHandoff() bool {
	return k == KindTFHEKeygen
}

// CeremonyID is the canonical identifier for a ceremony, derived from
// the Quasar 3.0 round descriptor and the ceremony kind. It is the
// 32-byte hash that ties shares, proofs, and cert subjects together.
type CeremonyID [32]byte

// Ceremony describes a single threshold ceremony on either chain.
//
// Ceremony is a pure data type. State transitions are produced by
// Transition() in this package; the host chain (M-Chain or F-Chain)
// drives transitions on its own block ticks.
type Ceremony struct {
	ID         CeremonyID
	Kind       CeremonyKind
	State      CeremonyState
	Round      uint8 // 1..N, valid only when State is Round1 or Round2
	Threshold  uint16
	Total      uint16 // total participants
	StartEpoch uint64
	Subject    [32]byte // certificate_subject the ceremony binds into
	// PayloadArena is the per-ceremony buffer that all share payloads
	// index into via (offset, len). Owned by the host chain; the
	// substrate never allocates.
	PayloadArena []byte
}

// Validate checks structural invariants. Use at boundaries only; the
// substrate trusts its own callers (the host chain) for routine
// transitions per PHILOSOPHY.md "defensive programming against
// yourself".
func (c *Ceremony) Validate() error {
	if c == nil {
		return errors.New("ceremony: nil")
	}
	if c.Kind == KindUnknown {
		return errors.New("ceremony: kind unset")
	}
	if c.Total == 0 {
		return errors.New("ceremony: total participants is zero")
	}
	// Honest-majority safety floor (LP-076 §Security).
	if uint32(c.Threshold)*2 <= uint32(c.Total) {
		return fmt.Errorf("ceremony: threshold %d <= n/2 for total %d", c.Threshold, c.Total)
	}
	if c.Threshold > c.Total {
		return fmt.Errorf("ceremony: threshold %d > total %d", c.Threshold, c.Total)
	}
	return nil
}

// Transition advances the ceremony state. It is the only function
// that mutates State. Returns the post-transition copy or an error
// if the transition is illegal.
//
// Legal transitions:
//
//	Registered -> Round1
//	Round1     -> Round2
//	Round2     -> Finalized
//	*          -> Aborted   (always permitted)
func (c Ceremony) Transition(next CeremonyState) (Ceremony, error) {
	if next == StateAborted {
		c.State = StateAborted
		return c, nil
	}
	switch c.State {
	case StateRegistered:
		if next != StateRound1 {
			return c, fmt.Errorf("ceremony: registered -> %s not legal", next)
		}
		c.State = StateRound1
		c.Round = 1
	case StateRound1:
		if next != StateRound2 {
			return c, fmt.Errorf("ceremony: round1 -> %s not legal", next)
		}
		c.State = StateRound2
		c.Round = 2
	case StateRound2:
		if next != StateFinalized {
			return c, fmt.Errorf("ceremony: round2 -> %s not legal", next)
		}
		c.State = StateFinalized
	default:
		return c, fmt.Errorf("ceremony: %s -> %s not legal", c.State, next)
	}
	return c, nil
}

// CeremonyRound is the per-round bag of share commitments for a single
// ceremony. The host chain accumulates these in memory while the
// ceremony is in Round1 / Round2 and finalizes them into a CertLane
// artifact at Finalize.
type CeremonyRound struct {
	CeremonyID CeremonyID
	Round      uint8
	Shares     []Share // populated as each participant publishes
}
