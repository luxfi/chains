// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// object_roundtrip_test.go — the Milestone-1 PART B proof for the Lux S-Chain:
// the S3 OBJECT path with the on-chain-metadata / off-chain-blob split, proven
// end to end. A PutObject streams the blob to a volume (OFF chain) and commits
// only the small manifest to the VM through a real block (ON chain); a GetObject
// reads the manifest back from the VM and reconstructs the blob from the volume.
//
// The proof asserts the CORE INVARIANT directly: the blob bytes live in the
// volume and NEVER appear in any block's bytes, while the manifest IS in block
// state. The harness drives the genuine VM (BuildBlock -> Verify -> Accept),
// playing the consensus engine, exactly as the M0 proof does.
package schain

import (
	"bytes"
	"context"
	"testing"

	"github.com/luxfi/chains/schain/object"
	"github.com/luxfi/chains/schain/txs"
)

// chainAdapter adapts *ChainVM to object.Chain. PutManifest submits the tx and
// drives it through a real block to Accept (the consensus role); GetManifest
// reads committed state. This is the ONLY glue the object path needs — and it is
// where the real consensus engine sits in production (the VM does not self-drive
// blocks; the engine does). It lives in the test because M1 proves the data model,
// not a running network.
type chainAdapter struct {
	t   *testing.T
	cvm *ChainVM
}

func (a *chainAdapter) PutManifest(ctx context.Context, bucket, objectKey string, m object.Manifest) error {
	a.t.Helper()
	tx := txs.NewPutManifestTx(bucket, objectKey, m.FileIDs, m.Size, m.ETag)
	if err := a.cvm.SubmitTx(tx.Bytes()); err != nil {
		return err
	}
	blk, err := a.cvm.BuildBlock(ctx)
	if err != nil {
		return err
	}
	if err := blk.Verify(ctx); err != nil {
		return err
	}
	if err := blk.Accept(ctx); err != nil {
		return err
	}
	if err := a.cvm.SetPreference(ctx, blk.ID()); err != nil {
		return err
	}
	return nil
}

func (a *chainAdapter) GetManifest(bucket, objectKey string) (object.Manifest, bool, error) {
	m, found, err := a.cvm.inner.GetManifest(bucket, objectKey)
	if err != nil || !found {
		return object.Manifest{}, found, err
	}
	return object.Manifest{FileIDs: m.FileIDs, Size: m.Size, ETag: m.ETag}, true, nil
}

// TestObjectRoundTripSplit is the PART B acceptance proof. It puts an object,
// proves the blob is OFF chain (in the volume, absent from every block) and the
// manifest is ON chain (in committed block state), then gets the object back and
// proves it byte-reconstructs from the off-chain blob the on-chain manifest names.
func TestObjectRoundTripSplit(t *testing.T) {
	ctx := context.Background()
	cvm, _ := newTestVM(t)

	vol := object.NewMemVolume()
	store := object.New(vol, &chainAdapter{t: t, cvm: cvm})

	const (
		bucket = "photos"
		objectKey = "cat.jpg"
	)
	blob := bytes.Repeat([]byte("LUX-STORAGE-BLOB-"), 4096) // ~68 KiB of real bytes

	// (0) Nothing yet.
	if _, _, found, err := store.GetObject(ctx, bucket, objectKey); err != nil {
		t.Fatalf("pre-state GetObject: %v", err)
	} else if found {
		t.Fatal("object present before any PutObject")
	}

	// (1) PUT: blob -> volume (off chain), manifest -> VM through a real block.
	m, err := store.PutObject(ctx, bucket, objectKey, blob)
	if err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	if len(m.FileIDs) != 1 {
		t.Fatalf("manifest fileIds = %v, want exactly 1 fid", m.FileIDs)
	}
	if m.Size != int64(len(blob)) {
		t.Fatalf("manifest size = %d, want %d", m.Size, len(blob))
	}
	if m.ETag == "" {
		t.Fatal("manifest etag empty")
	}
	fid := m.FileIDs[0]

	// (2) OFF-CHAIN PROOF: the blob lives in the volume...
	if !vol.Has(fid) {
		t.Fatalf("blob fid %s not in volume", fid)
	}
	// ...and the blob bytes appear in NO accepted block's serialized bytes — only
	// the small manifest (fid + size + etag) does. This is the split invariant:
	// consensus state is metadata; the bytes are off chain.
	for id, blk := range cvm.blocks {
		if blk.status != StatusAccepted {
			continue
		}
		raw := blk.Bytes()
		if bytes.Contains(raw, blob) {
			t.Fatalf("BLOB BYTES FOUND in accepted block %s — blob leaked on chain", id)
		}
		// A large blob (68 KiB) cannot fit in a manifest-only block; assert the
		// block is small (header + one small PutManifest tx + root), proving only
		// metadata was committed.
		if len(raw) > 4096 {
			t.Fatalf("accepted block %s is %d bytes — too large to be manifest-only", id, len(raw))
		}
	}

	// (3) ON-CHAIN PROOF: the manifest IS committed to block state, readable via
	// the VM's GetManifest (durable, post-Accept).
	got, found, err := cvm.inner.GetManifest(bucket, objectKey)
	if err != nil || !found {
		t.Fatalf("manifest not on chain after PutObject (found=%v err=%v)", found, err)
	}
	if len(got.FileIDs) != 1 || got.FileIDs[0] != fid {
		t.Fatalf("on-chain fileIds = %v, want [%s]", got.FileIDs, fid)
	}
	if got.Size != int64(len(blob)) || got.ETag != m.ETag {
		t.Fatalf("on-chain metadata = {size:%d etag:%q}, want {%d %q}", got.Size, got.ETag, len(blob), m.ETag)
	}

	// (4) GET: read manifest from chain, stream blob from volume, reconstruct.
	out, gm, found, err := store.GetObject(ctx, bucket, objectKey)
	if err != nil || !found {
		t.Fatalf("GetObject: found=%v err=%v", found, err)
	}
	if !bytes.Equal(out, blob) {
		t.Fatalf("reconstructed blob != original (got %d bytes, want %d)", len(out), len(blob))
	}
	if gm.ETag != m.ETag {
		t.Fatalf("GET etag = %q, want %q", gm.ETag, m.ETag)
	}
}
