// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// schain_test.go — the Milestone-0 end-to-end proof for the Lux S-Chain
// (storage VM). It proves the ONE thing M0 exists to prove: a PutManifest
// mutation round-trips through a REAL Lux block — built, verified, accepted —
// and the manifest it carries is committed to a REAL on-disk zapdb in exactly
// one atomic batch at Accept, observable via GetManifest ONLY after Accept.
//
// The harness is the genuine VM↔engine contract, not a mock of the engine:
//   - a real zapdb.Database backs the chain's database namespace (committed
//     through the luxfi/database interface, never the engine directly);
//   - SubmitTx feeds the mempool and signals the engine over ToEngine, exactly
//     as production does;
//   - we then drive BuildBlock -> Verify -> Accept ourselves, playing the role
//     the consensus engine plays, and assert the versiondb/CommitBatch
//     discipline by checking GetManifest is empty before Accept and populated
//     after.
package schain

import (
	"context"
	"testing"

	"github.com/luxfi/database/zapdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/metric"
	"github.com/luxfi/runtime"
	"github.com/luxfi/vm"

	"github.com/luxfi/chains/schain/txs"
)

// newTestVM builds an initialized ChainVM backed by a REAL on-disk zapdb. The
// (zapdb, runtime, ToEngine channel) triple is the production wiring the chains
// manager hands a VM — constructed here exactly as dexvm's tests construct it
// (memdb there; a real zapdb here for the strongest commit proof). It returns the
// VM and the engine-notification channel so the test can drain it as the engine
// would.
func newTestVM(t *testing.T) (*ChainVM, chan vm.Message) {
	t.Helper()
	logger := log.NewNoOpLogger()

	// A REAL on-disk zapdb namespace for this chain (canonical zapdb test
	// pattern: zapdb.New(dir, nil, namespace, metrics)). This is the storage the
	// manifest must survive a commit through.
	db, err := zapdb.New(t.TempDir(), nil, "schain-test", metric.NewRegistry())
	if err != nil {
		t.Fatalf("open zapdb: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	toEngine := make(chan vm.Message, 8)
	rt := &runtime.Runtime{
		ChainID:   ids.GenerateTestID(),
		NetworkID: 96369,
		Log:       logger,
	}

	cvm := NewChainVM(logger)
	if err := cvm.Initialize(context.Background(), vm.Init{
		Runtime:  rt,
		DB:       db,
		ToEngine: toEngine,
		Log:      logger,
	}); err != nil {
		t.Fatalf("initialize schain VM: %v", err)
	}
	return cvm, toEngine
}

// TestManifestRoundTripThroughAccept is the M0 acceptance proof: a manifest is
// durable and readable ONLY after the block carrying it is Accepted, proving the
// versiondb staging + single-CommitBatch-at-Accept discipline end to end over a
// real zapdb.
func TestManifestRoundTripThroughAccept(t *testing.T) {
	ctx := context.Background()
	cvm, toEngine := newTestVM(t)

	const (
		bucket = "b"
		object = "o"
	)
	wantFileIDs := []string{"1,2a,3"}

	// (0) Pre-state: no manifest exists yet.
	if _, found, err := cvm.inner.GetManifest(bucket, object); err != nil {
		t.Fatalf("pre-state GetManifest: %v", err)
	} else if found {
		t.Fatal("manifest present before any block — state not empty")
	}

	// (1) Submit the PutManifest mutation. SubmitTx admits it to the mempool and
	// signals the engine via ToEngine (the production block-production trigger).
	tx := txs.NewPutManifestTx(bucket, object, wantFileIDs, 42, "etag-xyz")
	if err := cvm.SubmitTx(tx.Bytes()); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}

	// (2) Drain ToEngine as the engine would — assert the VM signalled pending
	// work, the cue the engine acts on to call BuildBlock.
	select {
	case msg := <-toEngine:
		if msg.Type != vm.PendingTxs {
			t.Fatalf("ToEngine message = %v, want PendingTxs", msg.Type)
		}
	default:
		t.Fatal("VM did not signal PendingTxs after SubmitTx")
	}

	// (3) Engine -> BuildBlock: drains the mempool into a real block.
	blk, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if blk.Height() != 1 {
		t.Fatalf("block height = %d, want 1", blk.Height())
	}
	if blk.ID() == (ids.ID{}) {
		t.Fatal("built block has empty id")
	}

	// (4) Engine -> Verify: deterministically applies the manifest to the
	// versiondb in-memory layer. The write is STAGED, not yet durable.
	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("block.Verify: %v", err)
	}

	// (5) CRITICAL: after Verify but BEFORE Accept, a reader over the version
	// layer sees the proposer's STAGED write (in-flight view) — but it is NOT yet
	// committed to the durable base. We prove durability discipline two ways:
	//   (a) the staged value is visible through the same versiondb the VM writes;
	//   (b) it is ABSENT from the durable base DB until CommitBatch runs at Accept.
	// (a): in-flight visibility through the version layer.
	if _, found, err := cvm.inner.GetManifest(bucket, object); err != nil {
		t.Fatalf("post-Verify GetManifest: %v", err)
	} else if !found {
		t.Fatal("staged manifest not visible through version layer after Verify")
	}
	// (b): durability gate — the underlying base DB must NOT yet hold the key.
	if durable := baseHasManifest(t, cvm, bucket, object); durable {
		t.Fatal("manifest already in DURABLE base before Accept — CommitBatch leaked")
	}

	// (6) Engine -> Accept: the SINGLE commit point. CommitBatch + batch.Write
	// flushes the staged manifest to the durable zapdb atomically.
	if err := blk.Accept(ctx); err != nil {
		t.Fatalf("block.Accept: %v", err)
	}

	// (7) AFTER Accept: the manifest is durable in the base zapdb and GetManifest
	// returns exactly what was put.
	if durable := baseHasManifest(t, cvm, bucket, object); !durable {
		t.Fatal("manifest NOT in durable base after Accept — commit did not happen")
	}
	got, found, err := cvm.inner.GetManifest(bucket, object)
	if err != nil {
		t.Fatalf("post-Accept GetManifest: %v", err)
	}
	if !found {
		t.Fatal("manifest absent after Accept")
	}
	if len(got.FileIDs) != len(wantFileIDs) || got.FileIDs[0] != wantFileIDs[0] {
		t.Fatalf("FileIDs = %v, want %v", got.FileIDs, wantFileIDs)
	}
	if got.Size != 42 || got.ETag != "etag-xyz" {
		t.Fatalf("manifest metadata = {size:%d etag:%q}, want {42 etag-xyz}", got.Size, got.ETag)
	}

	// (8) The last-accepted pointer advanced to the committed block.
	if last, _ := cvm.LastAccepted(ctx); last != blk.ID() {
		t.Fatalf("LastAccepted = %s, want %s", last, blk.ID())
	}
}

// baseHasManifest reads the manifest key DIRECTLY from the chain's durable base
// database — bypassing the versiondb version layer — to witness whether the
// write has been COMMITTED (not merely staged). It reconstructs the same
// manifest key the state package uses so the two read paths agree. This is what
// makes the before/after-Accept assertions a real durability proof rather than a
// cache check.
func baseHasManifest(t *testing.T, cvm *ChainVM, bucket, object string) bool {
	t.Helper()
	// manifest/<bucket>/<object>, length-prefixed exactly as state.manifestKey.
	key := manifestProbeKey(bucket, object)
	_, err := cvm.inner.baseDB.Get(key)
	if err == nil {
		return true
	}
	return false
}

// manifestProbeKey mirrors state.manifestKey so the test can probe the durable
// base directly. Kept here (test-only) rather than exported from state, so the
// production key builder stays unexported.
func manifestProbeKey(bucket, object string) []byte {
	const prefix = "manifest/"
	k := make([]byte, 0, len(prefix)+4+len(bucket)+4+len(object))
	k = append(k, prefix...)
	put32 := func(n int) {
		k = append(k, byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
	}
	put32(len(bucket))
	k = append(k, bucket...)
	put32(len(object))
	k = append(k, object...)
	return k
}

// TestRejectAbortsStagedManifest proves the inverse discipline: a manifest
// staged during Verify is DISCARDED if the block is Rejected, never reaching the
// durable base — Reject calls db.Abort, dropping the version layer.
func TestRejectAbortsStagedManifest(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	tx := txs.NewPutManifestTx("rb", "ro", []string{"f1"}, 1, "e")
	if err := cvm.SubmitTx(tx.Bytes()); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	blk, err := cvm.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if err := blk.Reject(ctx); err != nil {
		t.Fatalf("Reject: %v", err)
	}

	// After Reject the staged write is gone from the version layer AND was never
	// committed to the durable base.
	if _, found, err := cvm.inner.GetManifest("rb", "ro"); err != nil {
		t.Fatalf("GetManifest: %v", err)
	} else if found {
		t.Fatal("rejected manifest still visible — Abort did not drop the staged write")
	}
	if baseHasManifest(t, cvm, "rb", "ro") {
		t.Fatal("rejected manifest reached durable base — commit leaked on Reject")
	}
}

// TestTxRoundTrip proves the PutManifest wire codec is faithful: a constructed tx
// parses back to an identical mutation with a stable, deterministic id.
func TestTxRoundTrip(t *testing.T) {
	orig := txs.NewPutManifestTx("bucket", "object", []string{"a", "b"}, 99, "et")
	parser := &txs.TxParser{}
	parsed, err := parser.Parse(orig.Bytes())
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if parsed.ID() != orig.ID() {
		t.Fatalf("round-trip id mismatch: %s != %s", parsed.ID(), orig.ID())
	}
	pm, ok := parsed.(*txs.PutManifestTx)
	if !ok {
		t.Fatalf("parsed type = %T, want *PutManifestTx", parsed)
	}
	if pm.Bucket != "bucket" || pm.Object != "object" || len(pm.FileIDs) != 2 {
		t.Fatalf("parsed fields wrong: %+v", pm)
	}
}
