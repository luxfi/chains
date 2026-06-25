// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package object

import (
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
)

// Manifest is the on-chain metadata for one object: the file ids of its blobs
// (off chain), the total size, and the content etag. It mirrors the schain
// state.Manifest / txs.PutManifestTx fields — the consensus-sized record that is
// the ONLY thing the object path commits to a block.
type Manifest struct {
	FileIDs []string
	Size    int64
	ETag    string
}

// Chain is the S-Chain VM surface the object path drives. It is the consensus
// seam: PutManifest submits the metadata tx and SEALS it through a block (the
// caller-supplied sealer plays the consensus engine's build->verify->accept), and
// GetManifest reads committed manifest state back. *schain.ChainVM satisfies this
// via a thin adapter (see the chains/schain object_roundtrip_test.go harness),
// keeping object/ free of an import cycle on package schain.
type Chain interface {
	// PutManifest submits a PutManifest{bucket,object,fileIds,size,etag} tx and
	// drives it to Accept, returning only after the manifest is committed.
	PutManifest(ctx context.Context, bucket, object string, m Manifest) error
	// GetManifest returns the committed manifest for (bucket, object).
	GetManifest(bucket, object string) (Manifest, bool, error)
}

// Store is the S3 object path: it splits each object into an OFF-CHAIN blob (to
// the Volume) and an ON-CHAIN manifest (to the Chain). It owns neither — it is
// the thin orchestrator that proves the split.
type Store struct {
	vol   Volume
	chain Chain
}

// New builds an object Store over a volume (off-chain blobs) and a chain
// (on-chain manifests).
func New(vol Volume, chain Chain) *Store {
	return &Store{vol: vol, chain: chain}
}

// PutObject is the S3 PUT path:
//
//  1. stream the blob to the volume (OFF chain) -> fid;  the blob NEVER enters a
//     block.
//  2. submit PutManifest{bucket, object, [fid], size, etag} to the chain (ON
//     chain) and drive it to Accept.
//
// It returns the committed manifest. ETag is the S3-canonical base64(md5(blob)),
// matching the form hanzo/s3's volume upload returns (ContentMd5), so the on-chain
// etag is identical whether the blob went through the stub or the real volume.
func (s *Store) PutObject(ctx context.Context, bucket, object string, blob []byte) (Manifest, error) {
	if len(blob) == 0 {
		return Manifest{}, ErrEmptyBlob
	}

	// (1) OFF-CHAIN: blob -> volume needle -> fid.
	fid, err := s.vol.Write(blob)
	if err != nil {
		return Manifest{}, fmt.Errorf("put object: volume write: %w", err)
	}

	// (2) ON-CHAIN: the small manifest only.
	sum := md5.Sum(blob)
	m := Manifest{
		FileIDs: []string{fid},
		Size:    int64(len(blob)),
		ETag:    base64.StdEncoding.EncodeToString(sum[:]),
	}
	if err := s.chain.PutManifest(ctx, bucket, object, m); err != nil {
		return Manifest{}, fmt.Errorf("put object: commit manifest: %w", err)
	}
	return m, nil
}

// GetObject is the S3 GET path:
//
//  1. read the manifest from the chain (ON chain) — the fids + size + etag.
//  2. stream each fid's blob from the volume (OFF chain) and concatenate them
//     back into the original object bytes.
//
// found is false when no manifest exists for (bucket, object).
func (s *Store) GetObject(ctx context.Context, bucket, object string) (blob []byte, m Manifest, found bool, err error) {
	m, found, err = s.chain.GetManifest(bucket, object)
	if err != nil {
		return nil, Manifest{}, false, fmt.Errorf("get object: read manifest: %w", err)
	}
	if !found {
		return nil, Manifest{}, false, nil
	}

	// Reassemble the blob from the off-chain needles the manifest names.
	out := make([]byte, 0, m.Size)
	for _, fid := range m.FileIDs {
		part, rerr := s.vol.Read(fid)
		if rerr != nil {
			return nil, m, true, fmt.Errorf("get object: volume read %s: %w", fid, rerr)
		}
		out = append(out, part...)
	}
	return out, m, true, nil
}
