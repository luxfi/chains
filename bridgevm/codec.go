// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"sort"
	"time"

	"github.com/luxfi/ids"
)

// Hand-rolled big-endian binary serialization for bridgevm types.
//
// One canonical wire layout per type. No version prefix (hard cut,
// forward-only). Each type owns a marshalX / unmarshalX pair.
// Length-prefixed []byte/string uses u32. Length-prefixed slices of
// structs use u32 element count. Maps with non-comparable iteration
// order are written in sorted key order for byte-identical output.
//
// Field order is fixed and stable. Renames or reorderings require a
// chain reset.

const (
	maxByteSliceLen = math.MaxUint32 // 4 GiB ceiling per []byte field
	nodeIDLen       = 20             // ids.NodeID = ids.ShortID = [20]byte
)

var (
	errShortBuffer   = errors.New("bridgevm: short buffer")
	errOversizeSlice = errors.New("bridgevm: slice exceeds max size")
	errTrailingBytes = errors.New("bridgevm: trailing bytes after struct")
)

// --- low-level primitive writers ---------------------------------------------

func writeUint8(buf []byte, off int, v uint8) int {
	buf[off] = v
	return off + 1
}

func writeUint32(buf []byte, off int, v uint32) int {
	binary.BigEndian.PutUint32(buf[off:off+4], v)
	return off + 4
}

func writeUint64(buf []byte, off int, v uint64) int {
	binary.BigEndian.PutUint64(buf[off:off+8], v)
	return off + 8
}

func writeBytes(buf []byte, off int, v []byte) int {
	off = writeUint32(buf, off, uint32(len(v)))
	copy(buf[off:], v)
	return off + len(v)
}

func writeString(buf []byte, off int, v string) int {
	off = writeUint32(buf, off, uint32(len(v)))
	copy(buf[off:], v)
	return off + len(v)
}

func writeID(buf []byte, off int, v ids.ID) int {
	copy(buf[off:off+ids.IDLen], v[:])
	return off + ids.IDLen
}

func writeNodeID(buf []byte, off int, v ids.NodeID) int {
	copy(buf[off:off+nodeIDLen], v[:])
	return off + nodeIDLen
}

// --- low-level primitive readers (return value, new offset, error) -----------

func readUint8(buf []byte, off int) (uint8, int, error) {
	if off+1 > len(buf) {
		return 0, off, errShortBuffer
	}
	return buf[off], off + 1, nil
}

func readUint32(buf []byte, off int) (uint32, int, error) {
	if off+4 > len(buf) {
		return 0, off, errShortBuffer
	}
	return binary.BigEndian.Uint32(buf[off : off+4]), off + 4, nil
}

func readUint64(buf []byte, off int) (uint64, int, error) {
	if off+8 > len(buf) {
		return 0, off, errShortBuffer
	}
	return binary.BigEndian.Uint64(buf[off : off+8]), off + 8, nil
}

func readBytes(buf []byte, off int) ([]byte, int, error) {
	n, off, err := readUint32(buf, off)
	if err != nil {
		return nil, off, err
	}
	if uint64(off)+uint64(n) > uint64(len(buf)) {
		return nil, off, errShortBuffer
	}
	out := make([]byte, n)
	copy(out, buf[off:off+int(n)])
	return out, off + int(n), nil
}

func readString(buf []byte, off int) (string, int, error) {
	b, off, err := readBytes(buf, off)
	if err != nil {
		return "", off, err
	}
	return string(b), off, nil
}

func readID(buf []byte, off int) (ids.ID, int, error) {
	if off+ids.IDLen > len(buf) {
		return ids.Empty, off, errShortBuffer
	}
	var id ids.ID
	copy(id[:], buf[off:off+ids.IDLen])
	return id, off + ids.IDLen, nil
}

func readNodeID(buf []byte, off int) (ids.NodeID, int, error) {
	if off+nodeIDLen > len(buf) {
		return ids.NodeID{}, off, errShortBuffer
	}
	var nid ids.NodeID
	copy(nid[:], buf[off:off+nodeIDLen])
	return nid, off + nodeIDLen, nil
}

// --- byte-slice sizing helpers -----------------------------------------------

func sizeBytes(v []byte) int  { return 4 + len(v) }
func sizeString(v string) int { return 4 + len(v) }

// --- BridgeRequest -----------------------------------------------------------
//
// Wire layout:
//   id(32) | sourceChain(len4|string) | destChain(len4|string) |
//   asset(32) | amount(8) | recipient(len4|bytes) | sourceTxID(32) |
//   confirmations(4) | status(len4|string) |
//   nSignatures(4) | (len4|bytes)*                       (MPCSignatures)
//   createdAtUnixNano(8)

func sizeBridgeRequest(r *BridgeRequest) int {
	n := ids.IDLen + sizeString(r.SourceChain) + sizeString(r.DestChain) +
		ids.IDLen + 8 + sizeBytes(r.Recipient) + ids.IDLen + 4 +
		sizeString(r.Status) + 4
	for _, sig := range r.MPCSignatures {
		n += sizeBytes(sig)
	}
	n += 8 // CreatedAt UnixNano
	return n
}

func marshalBridgeRequest(r *BridgeRequest) ([]byte, error) {
	if r == nil {
		return nil, errors.New("bridgevm: marshal nil bridge request")
	}
	if err := boundBridgeRequest(r); err != nil {
		return nil, err
	}
	buf := make([]byte, sizeBridgeRequest(r))
	off := 0
	off = writeID(buf, off, r.ID)
	off = writeString(buf, off, r.SourceChain)
	off = writeString(buf, off, r.DestChain)
	off = writeID(buf, off, r.Asset)
	off = writeUint64(buf, off, r.Amount)
	off = writeBytes(buf, off, r.Recipient)
	off = writeID(buf, off, r.SourceTxID)
	off = writeUint32(buf, off, r.Confirmations)
	off = writeString(buf, off, r.Status)
	off = writeUint32(buf, off, uint32(len(r.MPCSignatures)))
	for _, sig := range r.MPCSignatures {
		off = writeBytes(buf, off, sig)
	}
	off = writeUint64(buf, off, uint64(r.CreatedAt.UnixNano()))
	if off != len(buf) {
		return nil, fmt.Errorf("bridgevm: bridge request marshal size mismatch: wrote %d want %d", off, len(buf))
	}
	return buf, nil
}

// unmarshalBridgeRequest reads a request from buf starting at off and returns
// the new offset. Designed for streaming use inside Block decoding.
func unmarshalBridgeRequest(buf []byte, off int, r *BridgeRequest) (int, error) {
	if r == nil {
		return off, errors.New("bridgevm: unmarshal into nil bridge request")
	}
	var err error
	if r.ID, off, err = readID(buf, off); err != nil {
		return off, err
	}
	if r.SourceChain, off, err = readString(buf, off); err != nil {
		return off, err
	}
	if r.DestChain, off, err = readString(buf, off); err != nil {
		return off, err
	}
	if r.Asset, off, err = readID(buf, off); err != nil {
		return off, err
	}
	if r.Amount, off, err = readUint64(buf, off); err != nil {
		return off, err
	}
	if r.Recipient, off, err = readBytes(buf, off); err != nil {
		return off, err
	}
	if r.SourceTxID, off, err = readID(buf, off); err != nil {
		return off, err
	}
	if r.Confirmations, off, err = readUint32(buf, off); err != nil {
		return off, err
	}
	if r.Status, off, err = readString(buf, off); err != nil {
		return off, err
	}
	var n uint32
	if n, off, err = readUint32(buf, off); err != nil {
		return off, err
	}
	if n > maxByteSliceLen {
		return off, errOversizeSlice
	}
	r.MPCSignatures = make([][]byte, n)
	for i := uint32(0); i < n; i++ {
		if r.MPCSignatures[i], off, err = readBytes(buf, off); err != nil {
			return off, err
		}
	}
	var ns uint64
	if ns, off, err = readUint64(buf, off); err != nil {
		return off, err
	}
	r.CreatedAt = time.Unix(0, int64(ns))
	return off, nil
}

// --- Block -------------------------------------------------------------------
//
// Wire layout:
//   parentID(32) | blockHeight(8) | blockTimestamp(8) |
//   nBridgeRequests(4) | BridgeRequest*
//   nMPCSignatures(4) | { nodeID(20) | sig(len4|bytes) }*   (sorted by NodeID)

func sizeBlock(b *Block) int {
	n := ids.IDLen + 8 + 8 + 4
	for _, req := range b.BridgeRequests {
		n += sizeBridgeRequest(req)
	}
	n += 4
	for _, sig := range b.MPCSignatures {
		n += nodeIDLen + sizeBytes(sig)
	}
	return n
}

func marshalBlock(b *Block) ([]byte, error) {
	if b == nil {
		return nil, errors.New("bridgevm: marshal nil block")
	}
	if err := boundBlock(b); err != nil {
		return nil, err
	}
	buf := make([]byte, sizeBlock(b))
	off := 0
	off = writeID(buf, off, b.ParentID_)
	off = writeUint64(buf, off, b.BlockHeight)
	off = writeUint64(buf, off, uint64(b.BlockTimestamp))

	off = writeUint32(buf, off, uint32(len(b.BridgeRequests)))
	for _, req := range b.BridgeRequests {
		reqBytes, err := marshalBridgeRequest(req)
		if err != nil {
			return nil, err
		}
		copy(buf[off:], reqBytes)
		off += len(reqBytes)
	}

	off = writeUint32(buf, off, uint32(len(b.MPCSignatures)))
	nodeIDs := make([]ids.NodeID, 0, len(b.MPCSignatures))
	for nid := range b.MPCSignatures {
		nodeIDs = append(nodeIDs, nid)
	}
	sort.Slice(nodeIDs, func(i, j int) bool {
		return bytes.Compare(nodeIDs[i][:], nodeIDs[j][:]) < 0
	})
	for _, nid := range nodeIDs {
		off = writeNodeID(buf, off, nid)
		off = writeBytes(buf, off, b.MPCSignatures[nid])
	}

	if off != len(buf) {
		return nil, fmt.Errorf("bridgevm: block marshal size mismatch: wrote %d want %d", off, len(buf))
	}
	return buf, nil
}

func unmarshalBlock(buf []byte, b *Block) error {
	if b == nil {
		return errors.New("bridgevm: unmarshal into nil block")
	}
	off := 0
	var err error

	if b.ParentID_, off, err = readID(buf, off); err != nil {
		return err
	}
	if b.BlockHeight, off, err = readUint64(buf, off); err != nil {
		return err
	}
	var ts uint64
	if ts, off, err = readUint64(buf, off); err != nil {
		return err
	}
	b.BlockTimestamp = int64(ts)

	var n uint32
	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > maxByteSliceLen {
		return errOversizeSlice
	}
	b.BridgeRequests = make([]*BridgeRequest, n)
	for i := uint32(0); i < n; i++ {
		req := &BridgeRequest{}
		if off, err = unmarshalBridgeRequest(buf, off, req); err != nil {
			return err
		}
		b.BridgeRequests[i] = req
	}

	if n, off, err = readUint32(buf, off); err != nil {
		return err
	}
	if n > maxByteSliceLen {
		return errOversizeSlice
	}
	if n > 0 {
		b.MPCSignatures = make(map[ids.NodeID][]byte, n)
	}
	for i := uint32(0); i < n; i++ {
		var nid ids.NodeID
		if nid, off, err = readNodeID(buf, off); err != nil {
			return err
		}
		var sig []byte
		if sig, off, err = readBytes(buf, off); err != nil {
			return err
		}
		b.MPCSignatures[nid] = sig
	}

	if off != len(buf) {
		return errTrailingBytes
	}
	return nil
}

// --- bounds checking ---------------------------------------------------------

// boundBlock rejects pathological inputs whose lengths would overflow our u32
// length prefixes. Callers should treat input as untrusted.
func boundBlock(b *Block) error {
	if len(b.BridgeRequests) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(b.MPCSignatures) > maxByteSliceLen {
		return errOversizeSlice
	}
	for _, req := range b.BridgeRequests {
		if err := boundBridgeRequest(req); err != nil {
			return err
		}
	}
	for _, sig := range b.MPCSignatures {
		if len(sig) > maxByteSliceLen {
			return errOversizeSlice
		}
	}
	return nil
}

func boundBridgeRequest(r *BridgeRequest) error {
	if r == nil {
		return errors.New("bridgevm: nil bridge request")
	}
	if len(r.SourceChain) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(r.DestChain) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(r.Recipient) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(r.Status) > maxByteSliceLen {
		return errOversizeSlice
	}
	if len(r.MPCSignatures) > maxByteSliceLen {
		return errOversizeSlice
	}
	for _, sig := range r.MPCSignatures {
		if len(sig) > maxByteSliceLen {
			return errOversizeSlice
		}
	}
	return nil
}

