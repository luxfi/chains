// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package types

// Proof is the verification artifact emitted at ceremony Finalize. It
// is consumed by Quasar 3.0's cert pipeline (LP-020) and bound into
// certificate_subject (LP-134).
//
// The substrate defines the envelope; the per-protocol payload (the
// actual signature, group public key, FHE key, etc.) is opaque bytes
// indexed by Lane. Verifiers in cert/lane.go decode it.
type Proof struct {
	CeremonyID CeremonyID
	Kind       CeremonyKind
	Lane       CertLane
	// Payload is the protocol-specific final artifact: a signature
	// for sign-oriented ceremonies, a TFHE evaluation key for keygen
	// ceremonies, etc.
	Payload []byte
	// Aggregate is the aggregate signature over the participant
	// commitments (used when the chain itself attests to the
	// ceremony before forwarding to Quasar).
	Aggregate [64]byte
}

// Empty reports whether p is the zero value.
func (p Proof) Empty() bool {
	return p.Kind == KindUnknown && len(p.Payload) == 0
}
