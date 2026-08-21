// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// release_attestation_test.go — the gate that stands between an attestation and
// real funds, driven at the call site.
//
// bridgeattest pins the METHOD: VerifyAgainst refuses a signature made by a key
// it was not told to expect. Nothing pinned the CALLER. releaseTransfer could be
// handed att.GroupPubKey instead of the configured custody key — the exact
// pre-fix shape — and the whole bridgevm suite stayed green, because no test has
// ever entered this function.
package bridgevm

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/chains/internal/bridgeattest"
	"github.com/luxfi/crypto/secp256k1"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// recordingClient is a destination gateway that never processed anything and
// records every broadcast. Broadcasting IS the release: a transfer that reaches
// SendTransaction has left the chain's control.
type recordingClient struct{ sent int }

func (c *recordingClient) GetTransaction(context.Context, ids.ID) (interface{}, error) {
	return nil, nil
}
func (c *recordingClient) GetConfirmations(context.Context, ids.ID) (uint32, error) { return 64, nil }
func (c *recordingClient) ValidateAddress([]byte) error                             { return nil }
func (c *recordingClient) IsProcessed(context.Context, bridgeattest.BridgeTransfer) (bool, error) {
	return false, nil
}
func (c *recordingClient) SendTransaction(context.Context, interface{}) (ids.ID, error) {
	c.sent++
	return ids.GenerateTestID(), nil
}

// fixedAttester is M-Chain, answering with whatever attestation the test hands
// it — including one an attacker minted and shipped with its own public key.
type fixedAttester struct {
	att    *bridgeattest.Attestation
	called int
}

func (a *fixedAttester) AttestBridgeTransfer(context.Context, bridgeattest.BridgeTransfer) (*bridgeattest.Attestation, error) {
	a.called++
	return a.att, nil
}

func releaseRig(t *testing.T, att *bridgeattest.Attestation) (*VM, *recordingClient, *fixedAttester) {
	t.Helper()
	dst := &recordingClient{}
	ac := &fixedAttester{att: att}
	vm := &VM{log: log.NewNoOpLogger()}
	vm.evmByChainID = map[uint32]ChainClient{2: dst}
	vm.attestClient = ac
	// mpcConfig stays nil: M-Chain's dealerless keygen has not completed, so this
	// chain holds NO custody group key. That is a real operating state — a relayer
	// wired to its gateways before the ceremony finishes — and the one where
	// releasing on an unverifiable attestation costs the most.
	return vm, dst, ac
}

func signedTransfer(t *testing.T, key *secp256k1.PrivateKey) (bridgeattest.BridgeTransfer, *bridgeattest.Attestation) {
	t.Helper()
	bt := bridgeattest.BridgeTransfer{
		SrcChainID: 1,
		DstChainID: 2,
		Amount:     1_000_000,
		Nonce:      7,
	}
	digest := bt.Digest()
	sig, err := secp256k1.Sign(digest[:], key.Bytes())
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return bt, &bridgeattest.Attestation{
		Transfer:    bt,
		Digest:      digest,
		Signature:   sig,
		GroupPubKey: key.PublicKey().CompressedBytes(),
	}
}

// TestReleaseRefusesAnAttestationSignedByItsOwnSuppliedKey is the property that
// stands between a request and real funds.
//
// The attestation is perfectly self-consistent: real transfer, real digest, a
// signature that verifies — under a key the attacker generated and helpfully
// supplied. Verified against THAT key it passes; verified against the key this
// chain was configured with it cannot. The release path must be reading the
// second one.
func TestReleaseRefusesAnAttestationSignedByItsOwnSuppliedKey(t *testing.T) {
	attacker, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	bt, forged := signedTransfer(t, attacker)
	vm, dst, ac := releaseRig(t, forged)

	_, err = vm.releaseTransfer(context.Background(), bt)

	if !errors.Is(err, errBadAttestation) {
		t.Fatalf("release must refuse an attestation verified against a self-supplied key; got %v", err)
	}
	if dst.sent != 0 {
		t.Fatalf("FUNDS RELEASED on a self-signed attestation: %d broadcast(s) to the destination gateway", dst.sent)
	}
	// The rig has to REACH the attestation check, or the refusal above is some
	// earlier error wearing the shape of a safety proof.
	if ac.called != 1 {
		t.Fatalf("release did not reach the attestation step (attest calls=%d) — the refusal "+
			"came from somewhere else and proves nothing about the key check", ac.called)
	}
}

// TestReleaseRefusesWhenNoCustodyKeyIsConfigured states the same rule as an
// operating condition rather than an attack. Before M-Chain's keygen lands there
// is no key whose signature this chain is willing to accept, so there is no
// attestation it can act on. Failing closed here is what makes "verify against
// the key we trust" total: with no such key, nothing verifies.
func TestReleaseRefusesWhenNoCustodyKeyIsConfigured(t *testing.T) {
	custody, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	bt, genuine := signedTransfer(t, custody)
	vm, dst, _ := releaseRig(t, genuine)

	if key := vm.mpcGroupPublicKey(); key != nil {
		t.Fatalf("precondition: this rig must hold no custody key, got %x", key)
	}
	if _, err := vm.releaseTransfer(context.Background(), bt); !errors.Is(err, errBadAttestation) {
		t.Fatalf("a chain with no custody key must release nothing, even on a genuine "+
			"attestation; got %v", err)
	}
	if dst.sent != 0 {
		t.Fatalf("FUNDS RELEASED before custody keygen completed: %d broadcast(s)", dst.sent)
	}
}

// TestReleaseRefusesAMissingAttestation: M returning nothing is not consent.
func TestReleaseRefusesAMissingAttestation(t *testing.T) {
	bt := bridgeattest.BridgeTransfer{SrcChainID: 1, DstChainID: 2, Amount: 5, Nonce: 1}
	vm, dst, _ := releaseRig(t, nil)

	if _, err := vm.releaseTransfer(context.Background(), bt); !errors.Is(err, errBadAttestation) {
		t.Fatalf("a nil attestation must refuse; got %v", err)
	}
	if dst.sent != 0 {
		t.Fatalf("FUNDS RELEASED with no attestation at all: %d broadcast(s)", dst.sent)
	}
}

// TestReleaseSkipsAnAlreadyProcessedTransfer is the positive control for the
// rig: it proves the fixture reaches the destination client and that the
// refusals above are decided later than this point, not by a broken rig.
func TestReleaseSkipsAnAlreadyProcessedTransfer(t *testing.T) {
	custody, err := secp256k1.NewPrivateKey()
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	bt, genuine := signedTransfer(t, custody)
	vm, dst, ac := releaseRig(t, genuine)
	vm.evmByChainID = map[uint32]ChainClient{2: processedClient{dst}}

	if _, err := vm.releaseTransfer(context.Background(), bt); !errors.Is(err, errAlreadyReleased) {
		t.Fatalf("a transfer the gateway already released must converge, not re-broadcast; got %v", err)
	}
	if ac.called != 0 {
		t.Fatalf("an already-released transfer asked M for an attestation %d time(s)", ac.called)
	}
	if dst.sent != 0 {
		t.Fatalf("double release: %d broadcast(s)", dst.sent)
	}
}

// processedClient is a gateway that has already released everything.
type processedClient struct{ *recordingClient }

func (processedClient) IsProcessed(context.Context, bridgeattest.BridgeTransfer) (bool, error) {
	return true, nil
}
