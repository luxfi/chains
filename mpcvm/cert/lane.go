// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package cert provides the QuasarCertLane registration and
// certificate-subject binding logic shared by M-Chain and F-Chain.
//
// The lane registry is **not** a global. Each chain constructs its
// own LaneRegistry at boot, registers only the verifiers it owns
// (M-Chain registers lanes 5..7, F-Chain registers lanes 8..9), and
// the substrate refuses cross-registration at runtime — a misrouted
// verifier fails fast.
package cert

import (
	"errors"
	"fmt"

	"github.com/luxfi/chains/mpcvm/types"
)

// LaneVerifier is the contract a chain implements to validate shares
// on a given cert lane. Verifiers are stateless with respect to the
// substrate; any mutable state lives in the chain's own runtime.
type LaneVerifier interface {
	// Lane returns the lane identifier this verifier handles.
	Lane() types.CertLane
	// Verify validates a share's payload against the certificate
	// subject. The payload was extracted via Share.PayloadFrom on
	// the ceremony's PayloadArena.
	Verify(subject [32]byte, share types.Share, payload []byte) error
}

// Owner identifies which operational chain owns a lane registry. The
// substrate uses Owner to enforce orthogonality: an M-Chain registry
// refuses F-Chain lanes and vice versa.
type Owner uint8

const (
	OwnerUnknown Owner = 0
	OwnerMChain  Owner = 1
	OwnerFChain  Owner = 2
)

// LaneRegistry holds the verifier dispatch table for one chain.
//
// One registry per chain process. Constructed at boot, written
// during boot, read-only thereafter. No locks needed: registrations
// happen serially before the chain starts accepting blocks.
type LaneRegistry struct {
	owner    Owner
	verifier map[types.CertLane]LaneVerifier
}

// NewRegistry constructs a registry owned by the given chain.
func NewRegistry(owner Owner) *LaneRegistry {
	return &LaneRegistry{
		owner:    owner,
		verifier: make(map[types.CertLane]LaneVerifier),
	}
}

// Register adds a verifier to the registry. Returns an error if the
// lane does not belong to the registry's owner — this enforces M/F
// orthogonality at the type level.
func (r *LaneRegistry) Register(v LaneVerifier) error {
	if v == nil {
		return errors.New("registry: nil verifier")
	}
	lane := v.Lane()
	switch r.owner {
	case OwnerMChain:
		if !lane.IsMChain() {
			return fmt.Errorf("registry: lane %d is not owned by M-Chain", lane)
		}
	case OwnerFChain:
		if !lane.IsFChain() {
			return fmt.Errorf("registry: lane %d is not owned by F-Chain", lane)
		}
	default:
		return errors.New("registry: owner unset")
	}
	if _, exists := r.verifier[lane]; exists {
		return fmt.Errorf("registry: lane %d already registered", lane)
	}
	r.verifier[lane] = v
	return nil
}

// Verifier resolves a lane to its verifier. Returns an error if no verifier
// is registered — a lane this chain does not own has none, which is how
// Register's ownership rule keeps holding at dispatch time.
func (r *LaneRegistry) Verifier(lane types.CertLane) (LaneVerifier, error) {
	v, ok := r.verifier[lane]
	if !ok {
		return nil, fmt.Errorf("registry: no verifier for lane %d", lane)
	}
	return v, nil
}

// Verify dispatches a share to its lane verifier. Convenience wrapper
// for the chain runtime — validates the share envelope, extracts the
// payload window, and calls the verifier.
func (r *LaneRegistry) Verify(subject [32]byte, share types.Share, arena []byte, set *types.ParticipantSet) error {
	if err := share.Validate(set); err != nil {
		return err
	}
	v, err := r.Verifier(share.Lane)
	if err != nil {
		return err
	}
	payload, err := share.PayloadFrom(arena)
	if err != nil {
		return err
	}
	return v.Verify(subject, share, payload)
}

// Owner reports which chain owns this registry. Used by tests and
// boot-time sanity checks.
func (r *LaneRegistry) Owner() Owner { return r.owner }
