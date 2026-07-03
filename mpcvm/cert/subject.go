// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package cert

import (
	"crypto/sha256"
	"errors"
)

// Roots is the set of upstream roots a Quasar 3.0 certificate_subject
// binds, mirroring the QuasarRoundDescriptor in LP-134.
//
// All seven roots are required, including both MChain and FChain —
// this is the structural property that makes cross-chain replay
// impossible. The substrate does not let a caller skip a root: a zero
// value is still a value, and the chain that owns the root is
// expected to provide its current root on every round.
type Roots struct {
	ParentBlock        [32]byte
	StateRoot          [32]byte
	ExecRoot           [32]byte
	PChainValidator    [32]byte
	QChainCeremony     [32]byte
	ZChainVK           [32]byte
	AChainAttestation  [32]byte
	BChainBridge       [32]byte
	MChainCeremony     [32]byte
	FChainFHE          [32]byte
}

// BindSubject computes certificate_subject = H(... all roots ...).
// The hash domain is sha256 with a 1-byte version tag (0x01 for
// LP-134 v3.1) so future descriptor extensions can change the input
// set without colliding.
func BindSubject(r Roots) [32]byte {
	h := sha256.New()
	h.Write([]byte{0x01}) // LP-134 v3.1 descriptor version
	h.Write(r.ParentBlock[:])
	h.Write(r.StateRoot[:])
	h.Write(r.ExecRoot[:])
	h.Write(r.PChainValidator[:])
	h.Write(r.QChainCeremony[:])
	h.Write(r.ZChainVK[:])
	h.Write(r.AChainAttestation[:])
	h.Write(r.BChainBridge[:])
	h.Write(r.MChainCeremony[:])
	h.Write(r.FChainFHE[:])
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out
}

// VerifySubject re-computes the subject from its inputs and checks it
// matches the value carried on the wire. Used by both M-Chain and
// F-Chain at certificate-ingress time.
func VerifySubject(claimed [32]byte, r Roots) error {
	if BindSubject(r) != claimed {
		return errors.New("subject: claimed certificate_subject does not match descriptor roots")
	}
	return nil
}

// RequireBothChains reports an error if either MChainCeremony or
// FChainFHE is zero — the LP-134 invariant that every round binds
// **both** chain roots, even on rounds where one chain does not
// finalize a ceremony (the unchanged root from the previous round
// satisfies the binding).
func (r Roots) RequireBothChains() error {
	if r.MChainCeremony == ([32]byte{}) {
		return errors.New("subject: mchain_ceremony_root is zero — boot-time root not yet wired")
	}
	if r.FChainFHE == ([32]byte{}) {
		return errors.New("subject: fchain_fhe_root is zero — boot-time root not yet wired")
	}
	return nil
}
