// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// release_confirmations_test.go — the depth check that stands between a lock
// somebody claims and the custody signature that spends against it.
//
// A block carries the depth its proposer wrote down; Verify compares that
// number to the minimum. releaseOnce is where the number is replaced by one
// this node observed. Everything the release rests on — that a lock exists, on
// the chain it names, buried deep enough that a reorg will not take it back —
// is decided there, and only there: M signs the digest it is handed and asks
// nothing about the source.
package bridgevm

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/ids"
)

// sourceClient is the chain a lock is claimed on, answering how deep it is and
// counting the times it was asked.
type sourceClient struct {
	*recordingClient
	depth uint32
	asked int
}

func (c *sourceClient) GetConfirmations(context.Context, ids.ID) (uint32, error) {
	c.asked++
	return c.depth, nil
}

// releaseReq is a request for the transfer signedTransfer builds: source chain
// 1, destination chain 2.
func releaseReq() *BridgeRequest {
	return &BridgeRequest{
		ID:         ids.GenerateTestID(),
		SrcChainID: 1,
		DstChainID: 2,
		Amount:     1_000_000,
		Nonce:      7,
		Recipient:  make([]byte, 20),
		SourceTxID: ids.GenerateTestID(),
	}
}

// confirmationRig is releaseRig plus a source chain and a minimum depth.
func confirmationRig(t *testing.T, depth uint32) (*releaser, *sourceClient, *recordingClient, *fixedAttester) {
	t.Helper()
	vm, dst, ac := releaseRig(t, nil)
	vm.config.MinConfirmations = 12
	src := &sourceClient{recordingClient: &recordingClient{}, depth: depth}
	vm.evmByChainID[1] = src
	return &releaser{vm: vm}, src, dst, ac
}

// TestReleaseRefusesASourceChainItCannotSee is the fail-open.
//
// SrcChainID travels in the event data a release is built from. Name a chain
// this node has no client for and there is nothing to ask how deep the lock is
// — and a skipped check let the release proceed on the strength of the claim
// alone, straight to a threshold signature that authorises the mint.
func TestReleaseRefusesASourceChainItCannotSee(t *testing.T) {
	r, _, dst, ac := confirmationRig(t, 64)
	req := releaseReq()
	req.SrcChainID = 777 // no client for this chain
	transfer, err := req.transfer()
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}

	err = r.releaseOnce(context.Background(), req, transfer)

	if !errors.Is(err, errNoSourceClient) {
		t.Fatalf("a release naming an unknown source chain must refuse; got %v", err)
	}
	if ac.called != 0 {
		t.Fatalf("asked M for a custody signature %d time(s) over a lock this node cannot "+
			"see: the attestation alone authorises the mint, so reaching M is the release", ac.called)
	}
	if dst.sent != 0 {
		t.Fatalf("broadcast %d release(s) with no source chain to confirm them against", dst.sent)
	}
}

// TestReleaseRefusesARequestWithNoSourceTransaction is the same hole through
// the other field: the source chain is known, but the request names no
// transaction on it, so nothing can be looked up.
func TestReleaseRefusesARequestWithNoSourceTransaction(t *testing.T) {
	r, src, dst, ac := confirmationRig(t, 64)
	req := releaseReq()
	req.SourceTxID = ids.Empty
	transfer, err := req.transfer()
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}

	err = r.releaseOnce(context.Background(), req, transfer)

	if !errors.Is(err, errNoSourceTx) {
		t.Fatalf("a release naming no source transaction must refuse; got %v", err)
	}
	if src.asked != 0 {
		t.Fatalf("looked up %d receipt(s) for an empty transaction id", src.asked)
	}
	if ac.called != 0 || dst.sent != 0 {
		t.Fatalf("released with nothing to confirm: attest=%d broadcast=%d", ac.called, dst.sent)
	}
}

// TestReleaseRefusesAShallowLock is the check working on its own terms, and the
// control that says the two refusals above are about the missing evidence
// rather than about releaseOnce refusing everything.
func TestReleaseRefusesAShallowLock(t *testing.T) {
	r, src, dst, ac := confirmationRig(t, 11)
	req := releaseReq()
	transfer, err := req.transfer()
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}

	if err := r.releaseOnce(context.Background(), req, transfer); !errors.Is(err, errInsufficientConfirmations) {
		t.Fatalf("a lock 11 deep under a minimum of 12 must refuse; got %v", err)
	}
	if src.asked != 1 {
		t.Fatalf("source asked %d time(s), want 1", src.asked)
	}
	if ac.called != 0 || dst.sent != 0 {
		t.Fatalf("released on a shallow lock: attest=%d broadcast=%d", ac.called, dst.sent)
	}
}

// TestReleaseProceedsOnADeepLock is the positive control: an observed lock at
// or past the minimum reaches M. Without it every refusal above would be
// satisfied by a releaseOnce that returned an error unconditionally.
func TestReleaseProceedsOnADeepLock(t *testing.T) {
	r, src, _, ac := confirmationRig(t, 12)
	req := releaseReq()
	transfer, err := req.transfer()
	if err != nil {
		t.Fatalf("transfer: %v", err)
	}

	// The rig holds no custody key, so the release is refused at the
	// attestation check — after the depth check, which is what this asserts.
	if err := r.releaseOnce(context.Background(), req, transfer); !errors.Is(err, errBadAttestation) {
		t.Fatalf("a lock at the minimum must pass the depth check and be decided by the "+
			"attestation; got %v", err)
	}
	if src.asked != 1 {
		t.Fatalf("source asked %d time(s), want 1", src.asked)
	}
	if ac.called != 1 {
		t.Fatalf("attestation requested %d time(s), want 1", ac.called)
	}
}
