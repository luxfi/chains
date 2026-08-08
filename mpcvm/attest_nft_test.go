// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/ownership"
)

// TestNFTDomainRegistered proves the additive registration landed and carries the
// shared separator. If the separator ever diverges from chains/ownership, M signs
// over bytes no verifier recomputes and every entitlement silently stops working.
func TestNFTDomainRegistered(t *testing.T) {
	sep, ok := domainSeparators[DomainNFTOwnership]
	require.True(t, ok, "the nft/ownership domain must be registered")
	require.Equal(t, ownership.DomainTag, string(sep),
		"the separator must be chains/ownership's constant, not a copy")
	require.Equal(t, ownership.Domain, string(DomainNFTOwnership))
}

// TestNFTRegistrationIsAdditive proves the new domain did not displace any
// existing one — the property that makes this safe to add to a live registry.
func TestNFTRegistrationIsAdditive(t *testing.T) {
	for _, d := range []AttestationDomain{
		DomainOracleWrite,
		DomainOracleRead,
		DomainSessionComplete,
		DomainEpochBeacon,
		DomainBridgeTransfer,
	} {
		_, ok := domainSeparators[d]
		require.True(t, ok, "pre-existing domain %q must survive registration", d)
	}
}

// TestPayloadAgreesWithVerifier is THE invariant of this seam: what M signs and
// what a node checks must be the same bytes. M builds the payload with
// ComputeAttestationPayload; a node builds it with ownership.Payload, without
// importing this package at all. Nothing else in either codebase forces those two
// functions to agree, so this test is the only thing that does.
func TestPayloadAgreesWithVerifier(t *testing.T) {
	claim := ownership.Claim{Chain: 1, Token: 7, Block: 25443474}
	for i := range claim.Collection {
		claim.Collection[i] = byte(0x31 + i)
	}
	for i := range claim.Owner {
		claim.Owner[i] = byte(0xA0 + i)
	}
	for i := range claim.Node {
		claim.Node[i] = byte(0x10 + i)
	}

	for _, epoch := range []uint64{0, 1, claim.Block, 1 << 40} {
		subject := claim.Subject()
		root := claim.Root()
		require.Equal(t,
			ownership.Payload(subject, root, epoch),
			ComputeAttestationPayload(DomainNFTOwnership, subject, root, epoch),
			"M-Chain and the verifier must hash identical bytes at epoch %d", epoch)
	}
}

// TestNFTDomainIsDistinct proves an ownership attestation cannot be replayed as
// any other message M signs, and vice versa: same subject, same root, same epoch,
// different domain must yield a different payload.
func TestNFTDomainIsDistinct(t *testing.T) {
	var subject, root [32]byte
	subject[0], root[0] = 1, 2

	seen := map[[32]byte]AttestationDomain{}
	for d := range domainSeparators {
		p := ComputeAttestationPayload(d, subject, root, 9)
		if prior, clash := seen[p]; clash {
			t.Fatalf("domains %q and %q produce the same payload", prior, d)
		}
		seen[p] = d
	}
	require.Contains(t, seen, ComputeAttestationPayload(DomainNFTOwnership, subject, root, 9))
}
