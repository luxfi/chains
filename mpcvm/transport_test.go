// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package mpcvm

// transport_test.go — proves the native cross-validator MPC transport.
//
// Each "validator" runs its own ProtocolExecutor and its own MessageRouter view
// onto a shared in-process mesh (inProcRouter). A CMP (CGGMP21) DKG then a
// threshold sign run to completion THROUGH the executor's RunCMPKeygen /
// RunCMPSign path — the exact code that runs in production, only with the
// in-process router substituted for the gossip router. This is what makes
// M-Chain a real native VM instead of the off-chain REST cluster: the ceremony
// completes over the router abstraction, all parties agree on one group key,
// and a T+1 quorum produces a signature that verifies against it.

import (
	"context"
	"crypto/sha256"
	"sync"
	"testing"
	"time"

	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/log"
	"github.com/luxfi/threshold/pkg/party"
	"github.com/luxfi/threshold/pkg/pool"
	cmpconfig "github.com/luxfi/threshold/protocols/cmp/config"
	"github.com/stretchr/testify/require"
)

// runKeygenViaTransport runs a CMP DKG across every party through its executor +
// inProcRouter, returning each party's key config. A fresh mesh is used per
// ceremony (production uses a per-session router), so leaked receive loops from
// one ceremony can never steal another's messages.
func runKeygenViaTransport(
	t *testing.T,
	ctx context.Context,
	executors map[party.ID]*ProtocolExecutor,
	parties []party.ID,
	threshold int,
) map[party.ID]*cmpconfig.Config {
	t.Helper()
	net, routers := newInProcRouters(parties)
	defer net.close()

	var mu sync.Mutex
	var wg sync.WaitGroup
	configs := make(map[party.ID]*cmpconfig.Config, len(parties))
	errs := make(map[party.ID]error, len(parties))
	for _, id := range parties {
		wg.Add(1)
		go func(id party.ID) {
			defer wg.Done()
			cfg, err := executors[id].RunCMPKeygen(ctx, "bridge-dkg", id, parties, threshold, routers[id])
			mu.Lock()
			configs[id], errs[id] = cfg, err
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	for id, err := range errs {
		require.NoErrorf(t, err, "DKG failed for %s", id)
	}
	return configs
}

// runSignViaTransport runs a CMP threshold sign across the signer subset through
// each signer's executor + inProcRouter, returning each signer's signature.
func runSignViaTransport(
	t *testing.T,
	ctx context.Context,
	executors map[party.ID]*ProtocolExecutor,
	configs map[party.ID]*cmpconfig.Config,
	signers []party.ID,
	digest []byte,
) map[party.ID]*ECDSASignature {
	t.Helper()
	net, routers := newInProcRouters(signers)
	defer net.close()

	var mu sync.Mutex
	var wg sync.WaitGroup
	sigs := make(map[party.ID]*ECDSASignature, len(signers))
	errs := make(map[party.ID]error, len(signers))
	for _, id := range signers {
		wg.Add(1)
		go func(id party.ID) {
			defer wg.Done()
			sig, err := executors[id].RunCMPSign(ctx, "bridge-sign", configs[id], signers, digest, routers[id])
			mu.Lock()
			sigs[id], errs[id] = sig, err
			mu.Unlock()
		}(id)
	}
	wg.Wait()
	for id, err := range errs {
		require.NoErrorf(t, err, "sign failed for %s", id)
	}
	return sigs
}

// TestNativeTransport_CrossValidatorDKGAndSign proves a 2-of-3 DKG + threshold
// sign complete through the native MessageRouter transport, agree on one group
// key, and produce a signature that verifies under luxfi/crypto secp256k1 — the
// same verification the M-Chain and B-Chain use.
func TestNativeTransport_CrossValidatorDKGAndSign(t *testing.T) {
	if testing.Short() {
		t.Skip("threshold DKG is slow; skipped in -short")
	}
	parties := []party.ID{"alice", "bob", "charlie"}
	const threshold = 1 // any threshold+1 = 2 validators form a signing quorum

	executors := make(map[party.ID]*ProtocolExecutor, len(parties))
	for _, id := range parties {
		pl := pool.NewPool(4)
		defer pl.TearDown()
		executors[id] = NewProtocolExecutor(pl, log.NewTestLogger(log.DebugLevel))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	// --- DKG across all validators through the transport ---
	configs := runKeygenViaTransport(t, ctx, executors, parties, threshold)

	var groupPub []byte
	for id, cfg := range configs {
		require.NotNilf(t, cfg, "nil config for %s", id)
		pub, err := cfg.PublicPoint().MarshalBinary()
		require.NoError(t, err)
		if groupPub == nil {
			groupPub = pub
		} else {
			require.Equalf(t, groupPub, pub, "group key mismatch at %s", id)
		}
	}
	require.Len(t, groupPub, 33, "compressed secp256k1 group key")

	// --- Threshold sign across a quorum subset through the transport ---
	signers := parties[:threshold+1] // alice, bob
	digest := sha256.Sum256([]byte("LUX_BRIDGE_TRANSFER_v1|native transport proof"))
	sigs := runSignViaTransport(t, ctx, executors, configs, signers, digest[:])

	var sig *ECDSASignature
	for id, s := range sigs {
		require.NotNilf(t, s, "nil signature for %s", id)
		if sig == nil {
			sig = s
		} else {
			require.Equalf(t, sig.R, s.R, "R mismatch at %s", id)
			require.Equalf(t, sig.S, s.S, "S mismatch at %s", id)
		}
	}
	require.NotNil(t, sig)

	// The natively-produced threshold signature verifies against the DKG group
	// key — a valid signature, not just bytes.
	sigBytes := append(append([]byte{}, sig.R...), sig.S...)
	require.Len(t, sigBytes, 64)
	require.True(t, secp256k1.VerifySignature(groupPub, digest[:], sigBytes),
		"threshold signature produced through the native transport must verify")
}
