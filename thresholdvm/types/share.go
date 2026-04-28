// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

import (
	"errors"
	"fmt"
)

// CertLane mirrors LP-134 §QuasarCertLane. We declare it here in the
// substrate because the share envelope is the wire form on which
// every chain's verifier dispatches. The values must match LP-134
// exactly. New lanes append; values never move.
type CertLane uint8

const (
	LaneBLS              CertLane = 0
	LaneRingtail         CertLane = 1
	LaneMLDSAGroth16     CertLane = 2
	LaneAChainAttest     CertLane = 3
	LaneBChainBridge     CertLane = 4
	LaneMChainCGGMP21    CertLane = 5
	LaneMChainFROST      CertLane = 6
	LaneMChainRingtailGen CertLane = 7
	LaneFChainTFHE       CertLane = 8
	LaneFChainBootstrap  CertLane = 9
)

// IsMChain reports whether the lane is owned by M-Chain.
func (l CertLane) IsMChain() bool {
	return l == LaneMChainCGGMP21 || l == LaneMChainFROST || l == LaneMChainRingtailGen
}

// IsFChain reports whether the lane is owned by F-Chain.
func (l CertLane) IsFChain() bool {
	return l == LaneFChainTFHE || l == LaneFChainBootstrap
}

// Share is the per-participant, per-round share envelope.
//
// The envelope is fixed; per-protocol payload is carried via
// (PayloadOffset, PayloadLen) indirection into a Ceremony's
// PayloadArena. This matches the QuasarCertIngress wire ABI from
// LP-132 §drain_cert_lane: the verifier never decodes the share
// itself, only the payload window it points at.
type Share struct {
	CeremonyID    CeremonyID
	ParticipantID uint32   // index into ParticipantSet.Members
	Round         uint8    // 1..N, ceremony-kind specific
	Lane          CertLane // dispatches to the per-protocol verifier
	PayloadOffset uint32
	PayloadLen    uint32
	Signature     [64]byte // BLS or ML-DSA over (CeremonyID, Round, payload)
}

// PayloadFrom returns a slice into arena described by the share. It
// returns an error only if the share is structurally inconsistent
// with the arena length; payload semantics are the verifier's
// responsibility.
func (s Share) PayloadFrom(arena []byte) ([]byte, error) {
	end := uint64(s.PayloadOffset) + uint64(s.PayloadLen)
	if end > uint64(len(arena)) {
		return nil, fmt.Errorf("share: payload [%d..%d] out of arena (%d)",
			s.PayloadOffset, end, len(arena))
	}
	return arena[s.PayloadOffset : s.PayloadOffset+s.PayloadLen], nil
}

// Validate checks the envelope-level invariants. Payload validation
// is the verifier's job (each protocol verifies its own payload).
func (s Share) Validate(set *ParticipantSet) error {
	if set == nil {
		return errors.New("share: nil participant set")
	}
	if s.CeremonyID != set.CeremonyID {
		return errors.New("share: ceremony id does not match participant set")
	}
	if s.ParticipantID >= uint32(len(set.Members)) {
		return fmt.Errorf("share: participant %d >= set size %d",
			s.ParticipantID, len(set.Members))
	}
	if s.Round == 0 {
		return errors.New("share: round 0 reserved")
	}
	if s.PayloadLen == 0 {
		return errors.New("share: empty payload")
	}
	return nil
}
