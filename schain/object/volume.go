// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// Package object wires the S3 OBJECT path to the S-Chain storage VM, proving the
// on-chain-metadata / off-chain-blob split end to end:
//
//   - On PUT, the blob bytes are streamed to a VOLUME server (a needle write) —
//     OFF chain. The volume returns a file id (fid) per blob. The blob NEVER
//     enters a block.
//   - The small MANIFEST {bucket, object, fileIds, size, etag} is submitted as a
//     PutManifest tx to the S-Chain VM — ON chain. Only this consensus-sized
//     metadata becomes block state.
//   - On GET, the manifest is read back from the VM (GetManifest), the fids it
//     names are streamed from the volume, and the original blob is reconstructed.
//
// The Volume interface below is the SEAM. For M1 it is satisfied by a faithful
// in-memory stub (memvolume.go) whose Write/Read mirror the hanzo/s3 volume
// contract: Write(blob) -> fid, Read(fid) -> blob. For M2, the real hanzo/s3
// volume client (github.com/hanzoai/s3 s3/operation.SubmitFiles, which assigns a
// volume + streams the needle and returns SubmitResult.Fid) plugs in HERE, behind
// this identical interface — see the M2 PLUG POINT note on Volume. Keeping the
// seam in chains/schain (rather than importing the hanzoai/s3 module into the
// luxfi/chains module) respects the org/module boundary while proving the exact
// data model the real client will satisfy.
package object

import "errors"

var (
	// ErrBlobNotFound is returned by Volume.Read when no blob is stored under fid.
	ErrBlobNotFound = errors.New("object: blob not found in volume")
	// ErrEmptyBlob rejects a PutObject with no bytes (M1 stores at least one fid).
	ErrEmptyBlob = errors.New("object: empty blob")
)

// Volume is the OFF-CHAIN blob store seam. It is the minimal projection of the
// hanzo/s3 volume server the object path needs: write bytes, get a file id back;
// read a file id, get the bytes back. The fid is opaque to this package — it is
// the volume's own address (the SeaweedFS-style "volumeId,needleIdCookie" string
// the real s3 volume returns).
//
// M2 PLUG POINT: replace the in-memory stub (NewMemVolume) with a thin adapter
// over github.com/hanzoai/s3 s3/operation.SubmitFiles:
//
//	Write(blob)  -> SubmitFiles(...).Fid           (assign volume + stream needle)
//	Read(fid)    -> GET http://<volume>/<fid>      (stream needle bytes back)
//
// No code in object.go / the VM changes — only this interface's implementation.
type Volume interface {
	// Write streams blob to the volume (OFF chain) and returns its file id.
	Write(blob []byte) (fid string, err error)
	// Read streams the blob bytes for fid back from the volume. Returns
	// ErrBlobNotFound if no such blob exists.
	Read(fid string) (blob []byte, err error)
}
