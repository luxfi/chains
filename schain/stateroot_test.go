// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// stateroot_test.go — the Milestone-1 PART A proof for the Lux S-Chain manifest
// STATE ROOT. The state root is what makes the chain safe for more than one
// validator: every block header binds a deterministic commitment over the
// committed manifest keyspace, and Block.Verify recomputes that commitment on
// every validator and REJECTS a block whose claimed root does not match. These
// tests prove the three properties that gate multi-validator safety:
//
//  1. DETERMINISM      — the same manifests always hash to the same root, so two
//     honest validators that applied identical txs agree.
//  2. CHANGE-SENSITIVITY — any change to a manifest (fileIds/size/etag) or to the
//     object set changes the root, so divergent state cannot share a root.
//  3. VERIFY REJECTION — a block whose claimed root does not match the root
//     recomputed from its txs is rejected (errStateRootMismatch), so a proposer
//     whose post-apply state diverges cannot get its block accepted.
package schain

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/metric"

	"github.com/luxfi/chains/schain/state"
	"github.com/luxfi/chains/schain/txs"
)

// mustTx builds the wire bytes for a PutManifest tx (test convenience).
func mustTx(t *testing.T, bucket, object string, fileIDs []string, size int64, etag string) []byte {
	t.Helper()
	return txs.NewPutManifestTx(bucket, object, fileIDs, size, etag).Bytes()
}

// sha256Bytes is the block-id hash the VM uses, exposed for tests that re-derive
// a block id after tampering with the header.
func sha256Bytes(b []byte) [32]byte { return sha256.Sum256(b) }

// newStateOverZapdb opens a real on-disk zapdb-backed state.State (through the
// versiondb-equivalent durable interface) so the root walk is exercised over the
// same engine production uses, not a mock.
func newStateOverZapdb(t *testing.T) *state.State {
	t.Helper()
	db, err := zapdb.New(t.TempDir(), nil, "schain-root-test", metric.NewRegistry())
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	st := state.New(db)
	if err := st.Initialize(); err != nil {
		t.Fatalf("init state: %v", err)
	}
	return st
}

// TestRootDeterminism proves the root is a pure function of the committed manifest
// keyspace: identical (bucket,object)->manifest sets — written in DIFFERENT order
// into two independent stores — produce the IDENTICAL root. This is the property
// that lets two honest validators agree on a block's root.
func TestRootDeterminism(t *testing.T) {
	a := newStateOverZapdb(t)
	b := newStateOverZapdb(t)

	// Same logical state, written in opposite order.
	puts := []struct {
		bucket, object string
		m              state.Manifest
	}{
		{"alpha", "x", state.Manifest{FileIDs: []string{"1,2a"}, Size: 10, ETag: "e1"}},
		{"alpha", "y", state.Manifest{FileIDs: []string{"3b"}, Size: 20, ETag: "e2"}},
		{"beta", "z", state.Manifest{FileIDs: []string{"4c", "5d"}, Size: 30, ETag: "e3"}},
	}
	for _, p := range puts {
		if err := a.PutManifest(p.bucket, p.object, p.m); err != nil {
			t.Fatalf("a.PutManifest: %v", err)
		}
	}
	for i := len(puts) - 1; i >= 0; i-- {
		p := puts[i]
		if err := b.PutManifest(p.bucket, p.object, p.m); err != nil {
			t.Fatalf("b.PutManifest: %v", err)
		}
	}

	ra, err := a.Root()
	if err != nil {
		t.Fatalf("a.Root: %v", err)
	}
	rb, err := b.Root()
	if err != nil {
		t.Fatalf("b.Root: %v", err)
	}
	if ra != rb {
		t.Fatalf("root not deterministic across write order: %s != %s", ra, rb)
	}
	if ra == ids.Empty {
		t.Fatal("root is empty for non-empty manifest state")
	}

	// And a re-read of the same store yields the same root (no hidden per-call state).
	if again, _ := a.Root(); again != ra {
		t.Fatalf("root unstable across calls: %s != %s", again, ra)
	}
}

// TestRootChangeSensitivity proves any change to the manifest state changes the
// root: a new object, a changed etag, a changed size, and a changed fileIds each
// move the root. Divergent state can therefore never hide behind a matching root.
func TestRootChangeSensitivity(t *testing.T) {
	base := func() *state.State {
		s := newStateOverZapdb(t)
		if err := s.PutManifest("b", "o", state.Manifest{FileIDs: []string{"1"}, Size: 1, ETag: "e"}); err != nil {
			t.Fatalf("seed: %v", err)
		}
		return s
	}

	root := func(s *state.State) ids.ID {
		r, err := s.Root()
		if err != nil {
			t.Fatalf("Root: %v", err)
		}
		return r
	}

	baseRoot := root(base())

	cases := []struct {
		name  string
		mutate func(*state.State)
	}{
		{"new object", func(s *state.State) {
			_ = s.PutManifest("b", "o2", state.Manifest{FileIDs: []string{"9"}, Size: 1, ETag: "e"})
		}},
		{"changed etag", func(s *state.State) {
			_ = s.PutManifest("b", "o", state.Manifest{FileIDs: []string{"1"}, Size: 1, ETag: "DIFFERENT"})
		}},
		{"changed size", func(s *state.State) {
			_ = s.PutManifest("b", "o", state.Manifest{FileIDs: []string{"1"}, Size: 999, ETag: "e"})
		}},
		{"changed fileIds", func(s *state.State) {
			_ = s.PutManifest("b", "o", state.Manifest{FileIDs: []string{"1", "2"}, Size: 1, ETag: "e"})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := base()
			tc.mutate(s)
			if got := root(s); got == baseRoot {
				t.Fatalf("%s did not change the root (%s) — divergent state shares a root", tc.name, got)
			}
		})
	}
}

// TestVerifyRejectsBadStateRoot is the multi-validator safety proof: a block whose
// header claims a root that does NOT match the root recomputed from its txs is
// rejected by Verify with errStateRootMismatch, and its staged writes are dropped.
// A correctly-rooted block over the same txs verifies. This is what stops a
// diverging proposer from getting a block accepted.
func TestVerifyRejectsBadStateRoot(t *testing.T) {
	ctx := context.Background()

	// (1) A block built honestly verifies: BuildBlock computes the correct root
	// into the header, Verify recomputes the same root and accepts.
	good, _ := newTestVM(t)
	tx := mustTx(t, "b", "o", []string{"1"}, 1, "e")
	if err := good.SubmitTx(tx); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	blk, err := good.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("honest block rejected by Verify: %v", err)
	}

	// (2) A block carrying a TAMPERED claimed root over the same txs is rejected.
	// We drive a fresh VM, build the block, then corrupt the header's stateRoot
	// before re-deriving the id (as a malicious proposer would have to) and assert
	// Verify rejects it with errStateRootMismatch.
	bad, _ := newTestVM(t)
	tx2 := mustTx(t, "b", "o", []string{"1"}, 1, "e")
	if err := bad.SubmitTx(tx2); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	badBlk, err := bad.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	concrete, ok := badBlk.(*Block)
	if !ok {
		t.Fatalf("block type = %T, want *Block", badBlk)
	}
	// Tamper the claimed root (a wrong commitment) and re-derive the id so the
	// block is internally self-consistent except for the divergent root.
	concrete.stateRoot = ids.ID{0xDE, 0xAD, 0xBE, 0xEF}
	hash := sha256Bytes(concrete.Bytes())
	copy(concrete.id[:], hash[:])

	err = concrete.Verify(ctx)
	if err == nil {
		t.Fatal("Verify accepted a block with a tampered state root")
	}
	if !errors.Is(err, errStateRootMismatch) {
		t.Fatalf("Verify error = %v, want errStateRootMismatch", err)
	}
	// The tampered block's staged writes must NOT have leaked into the durable base.
	if baseHasManifest(t, bad, "b", "o") {
		t.Fatal("rejected (bad-root) block's manifest reached durable base")
	}
}
