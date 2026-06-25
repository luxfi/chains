// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package object

import (
	"fmt"
	"sync"
)

// MemVolume is a faithful in-memory stand-in for the hanzo/s3 volume server,
// used to prove the object round-trip for M1 without a running volume daemon. It
// honours the Volume contract exactly: Write assigns a fresh file id in the
// SeaweedFS "volumeId,needleIdCookie" form the real volume returns, stores the
// bytes under it (the needle), and Read returns those bytes verbatim. It is the
// OFF-CHAIN store — nothing here ever touches a block.
//
// M2 swaps this for the real volume client; the VM and object.go are unaffected
// because both sides speak only the Volume interface.
type MemVolume struct {
	mu       sync.Mutex
	volumeID uint32
	nextKey  uint64
	blobs    map[string][]byte
}

// NewMemVolume returns an empty in-memory volume bound to a single logical
// volumeId (a real deployment shards across many; one suffices for the M1 proof).
func NewMemVolume() *MemVolume {
	return &MemVolume{
		volumeID: 1,
		blobs:    make(map[string][]byte),
	}
}

// Write stores blob under a fresh fid and returns the fid. The fid format mirrors
// needle.FileId.String() ("volumeId,needleIdCookie") so the manifest's fileIds
// are byte-identical in shape to what the real volume yields — the M2 client is a
// drop-in.
func (v *MemVolume) Write(blob []byte) (string, error) {
	if len(blob) == 0 {
		return "", ErrEmptyBlob
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.nextKey++
	// cookie is a fixed nonzero stand-in; the real volume randomises it.
	fid := fmt.Sprintf("%d,%x%x", v.volumeID, v.nextKey, uint32(0x2a))
	stored := make([]byte, len(blob))
	copy(stored, blob)
	v.blobs[fid] = stored
	return fid, nil
}

// Read returns the bytes stored under fid, or ErrBlobNotFound.
func (v *MemVolume) Read(fid string) ([]byte, error) {
	v.mu.Lock()
	defer v.mu.Unlock()
	blob, ok := v.blobs[fid]
	if !ok {
		return nil, ErrBlobNotFound
	}
	out := make([]byte, len(blob))
	copy(out, blob)
	return out, nil
}

// Has reports whether fid is present — used by tests to assert the blob lives in
// the volume (off chain) and not in any block.
func (v *MemVolume) Has(fid string) bool {
	v.mu.Lock()
	defer v.mu.Unlock()
	_, ok := v.blobs[fid]
	return ok
}
