// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/luxfi/consensus/core/choices"
	"github.com/luxfi/consensus/engine/dag/vertex"
	"github.com/luxfi/ids"

	"github.com/luxfi/chains/dexvm/txs"
)

var _ vertex.DAGVM = (*ChainVM)(nil)

// OrderKey is the conflict key for the proxy: (poolId, side, orderID) for relay
// envelopes, or the consumed source-UTXO id for imports. Two vertices conflict
// iff their OrderKey sets intersect — relays/cancels touching the same resting
// order, or imports claiming the same exported UTXO. The proxy does NOT match,
// so this is a transport-level conflict key, not a matching one.
type OrderKey struct {
	// Market is the 32-byte poolId (hex) for order relays, or "utxo" for the
	// atomic-import double-spend key.
	Market  string
	Side    uint8
	OrderID ids.ID
}

// DexVertex represents a DAG vertex in the DEX proxy chain.
type DexVertex struct {
	id     ids.ID
	bytes  []byte
	height uint64
	epoch  uint32
	// timestamp is the proposer-chosen block time, carried in the serialized
	// vertex bytes and committed by computeID. Verify MUST use this value (NOT
	// the local wall clock) so every validator processing the same vertex feeds
	// the IDENTICAL time into deriveBlockHash -> receipt keys + computeStateRoot,
	// yielding the same StateRoot. This mirrors the linear Block.timestamp path
	// (block.go); injecting clock.Time() here forked StateRoot across validators.
	timestamp time.Time
	parents   []ids.ID
	txIDs     []ids.ID
	status    choices.Status
	rawTxs    [][]byte
	keys      []OrderKey
	// carriedFills are the proposer's confirmed d-chain fills, obtained once at
	// BuildVertex and serialized into the vertex bytes; every validator settles
	// from them without relaying (RED finding #9). fillSig is the reserved
	// trustless-path attestation (empty today). Carrying these CHANGES THE VERTEX
	// WIRE FORMAT — a network-upgrade-gated, lockstep validator change.
	carriedFills []carriedFill
	fillSig      []byte
	result       *BlockResult
	vm           *ChainVM
}

func (v *DexVertex) ID() ids.ID             { return v.id }
func (v *DexVertex) Bytes() []byte          { return v.bytes }
func (v *DexVertex) Height() uint64         { return v.height }
func (v *DexVertex) Epoch() uint32          { return v.epoch }
func (v *DexVertex) Timestamp() time.Time   { return v.timestamp }
func (v *DexVertex) Parents() []ids.ID      { return v.parents }
func (v *DexVertex) Txs() []ids.ID          { return v.txIDs }
func (v *DexVertex) Status() choices.Status { return v.status }

func (v *DexVertex) Verify(ctx context.Context) error {
	if v.vm == nil || v.vm.inner == nil {
		return errVMNotInitialized
	}
	// Use the proposer-carried timestamp, NOT v.vm.inner.clock.Time(): the wall
	// clock differs per validator and flows through deriveBlockHash into receipt
	// keys + computeStateRoot, which would fork the StateRoot for the same
	// vertex. The carried time is consensus-agreed (committed by computeID).
	result, err := v.vm.inner.ProcessBlock(ctx, v.height, v.timestamp, v.rawTxs)
	if err != nil {
		return err
	}
	// Attach the carried fills (RED #9): settleCarried at accept settles purely
	// from these + the deterministic relay plan. Verify performs NO d-chain I/O on
	// any node — the proposer relayed once at BuildVertex.
	result.carriedFills = v.carriedFills
	result.fillSig = v.fillSig
	v.result = result
	return nil
}

func (v *DexVertex) Accept(ctx context.Context) error {
	v.status = choices.Accepted
	v.vm.lock.Lock()
	defer v.vm.lock.Unlock()
	v.vm.lastAcceptedID = v.id
	v.vm.lastAcceptedHeight = v.height
	v.vm.blocks[v.id] = &Block{
		vm:        v.vm,
		id:        v.id,
		parentID:  v.parents[0],
		height:    v.height,
		timestamp: v.timestamp,
		txs:       v.rawTxs,
		status:    StatusAccepted,
	}
	// Run the deferred relay plan (the irreversible d-chain leg) and commit the
	// proxy's state batch ATOMICALLY with the cross-chain shared-memory operations
	// (the settlement leg). This is the single commit point (the platformvm
	// acceptor.go pattern): the relay never fires during Verify, so a Rejected
	// vertex never strands a d-chain match; a failed atomic apply leaves NO
	// committed state, so a d-side fill cannot strand without its C-side settle.
	return v.vm.inner.acceptBlock(ctx, v.result)
}

func (v *DexVertex) Reject(ctx context.Context) error {
	v.status = choices.Rejected
	if v.vm.inner.db != nil {
		v.vm.inner.db.Abort()
	}
	return nil
}

// conflictKeySet returns the set of OrderKeys for conflict detection.
func (v *DexVertex) conflictKeySet() map[OrderKey]struct{} {
	s := make(map[OrderKey]struct{}, len(v.keys))
	for _, k := range v.keys {
		s[k] = struct{}{}
	}
	return s
}

// Conflicts returns true if this vertex and other share any (symbol, side, orderID) tuple.
func (v *DexVertex) Conflicts(other *DexVertex) bool {
	ours := v.conflictKeySet()
	for _, k := range other.keys {
		if _, ok := ours[k]; ok {
			return true
		}
	}
	return false
}

// ConflictsVertex performs the same check against the vertex.Vertex interface.
func (v *DexVertex) ConflictsVertex(other vertex.Vertex) bool {
	ov, ok := other.(*DexVertex)
	if !ok {
		return false
	}
	return v.Conflicts(ov)
}

// extractOrderKeys extracts transport-level conflict keys from raw tx bytes.
// The proxy's conflicts are: order relays/places/cancels touching the same
// (poolId, side, orderID), and imports claiming the same exported source UTXO.
// Parsing goes through the canonical TxParser so the key reflects the real wire
// fields (not an ad-hoc JSON probe).
func extractOrderKeys(rawTxs [][]byte) []OrderKey {
	parser := &txs.TxParser{}
	var keys []OrderKey
	for _, raw := range rawTxs {
		tx, err := parser.Parse(raw)
		if err != nil {
			continue
		}
		switch t := tx.(type) {
		case *txs.PlaceOrderTx:
			keys = append(keys, OrderKey{Market: marketHex(t.PoolID), Side: t.Side})
		case *txs.CancelOrderTx:
			keys = append(keys, OrderKey{Market: marketHex(t.PoolID), OrderID: orderIDToKey(t.OrderID)})
		case *txs.RelayOrderTx:
			// Relays serialize an opaque frame; bind the conflict to the
			// collateral ref so two relays spending the same locked collateral
			// in one round conflict.
			keys = append(keys, OrderKey{Market: "relay", OrderID: t.CollateralRef})
		case *txs.ImportTx:
			// Each imported UTXO is a single-claim conflict key (no double-import).
			for _, in := range t.ImportedInputs {
				keys = append(keys, OrderKey{Market: "utxo", OrderID: in.UTXOID})
			}
		}
	}
	return keys
}

// marketHex renders a 32-byte poolId as a stable hex string for the conflict
// key (Go map keys must be comparable; a [32]byte already is, but the Market
// field is a string shared with the "utxo"/"relay" sentinels).
func marketHex(poolID [32]byte) string {
	return hex.EncodeToString(poolID[:])
}

// orderIDToKey embeds a uint64 order id into an ids.ID conflict key.
func orderIDToKey(orderID uint64) ids.ID {
	var id ids.ID
	binary.BigEndian.PutUint64(id[:8], orderID)
	return id
}

func (v *DexVertex) computeID() ids.ID {
	h := sha256.New()
	binary.Write(h, binary.BigEndian, v.height)
	binary.Write(h, binary.BigEndian, v.epoch)
	// Commit to the proposer-chosen timestamp so the vertex id binds the exact
	// time fed into ProcessBlock (a tampered timestamp yields a different id, and
	// two proposals with the same txs but different times don't collide).
	binary.Write(h, binary.BigEndian, v.timestamp.UnixNano())
	for _, p := range v.parents {
		h.Write(p[:])
	}
	for _, raw := range v.rawTxs {
		txHash := sha256.Sum256(raw)
		h.Write(txHash[:])
	}
	// Commit to the carried fills (RED #9) so the vertex id binds the settlement
	// data every validator consumes — a peer cannot swap the proposer's fills (or
	// the reserved signature) while keeping the same id. The canonical encoding is
	// the same one serialized into the vertex bytes.
	h.Write(encodeCarriedFills(v.carriedFills, v.fillSig))
	return ids.ID(h.Sum(nil))
}

// BuildVertex drains pending txs and batches non-conflicting ones.
func (cvm *ChainVM) BuildVertex(ctx context.Context) (vertex.Vertex, error) {
	cvm.lock.Lock()
	defer cvm.lock.Unlock()

	if !cvm.initialized {
		return nil, errVMNotInitialized
	}
	if len(cvm.pendingTxs) == 0 {
		return nil, errNoBlocksBuilt
	}

	// Greedily batch non-conflicting txs
	usedKeys := make(map[OrderKey]struct{})
	var batch [][]byte
	var batchKeys []OrderKey
	var remaining [][]byte

	for _, raw := range cvm.pendingTxs {
		keys := extractOrderKeys([][]byte{raw})
		conflict := false
		for _, k := range keys {
			if _, ok := usedKeys[k]; ok {
				conflict = true
				break
			}
		}
		if conflict {
			remaining = append(remaining, raw)
			continue
		}
		for _, k := range keys {
			usedKeys[k] = struct{}{}
		}
		batch = append(batch, raw)
		batchKeys = append(batchKeys, keys...)
	}
	cvm.pendingTxs = remaining

	if len(batch) == 0 {
		return nil, errNoBlocksBuilt
	}

	txIDs := make([]ids.ID, len(batch))
	for i, raw := range batch {
		h := sha256.Sum256(raw)
		txIDs[i] = ids.ID(h)
	}

	parentID := cvm.lastAcceptedID
	// The proposer chooses the block time here (wall clock), then carries it in
	// the serialized bytes so every validator's Verify uses the IDENTICAL value
	// — the consensus-agreement point, exactly like the linear BuildBlock. Clamp
	// to be non-decreasing vs the last processed block so block time never goes
	// backwards on a re-proposal/clock skew.
	ts := cvm.inner.clock.Time()
	if last := cvm.inner.GetLastBlockTime(); ts.Before(last) {
		ts = last
	}
	height := cvm.lastAcceptedHeight + 1

	// Proposer build: plan + relay-once + obtain the carried fills. obtainFills is
	// the single d-chain relay for this vertex, network-wide (RED #9); every
	// validator settles from the carried fills below without relaying.
	result, err := cvm.inner.BuildBlockResult(ctx, height, ts, batch)
	if err != nil {
		return nil, fmt.Errorf("dexvm: build vertex result: %w", err)
	}

	v := &DexVertex{
		height:       height,
		epoch:        0,
		timestamp:    ts,
		parents:      []ids.ID{parentID},
		txIDs:        txIDs,
		rawTxs:       batch,
		keys:         batchKeys,
		carriedFills: result.carriedFills,
		fillSig:      result.fillSig,
		result:       result,
		status:       choices.Processing,
		vm:           cvm,
	}
	v.id = v.computeID()
	v.bytes = serializeDexVertex(v)
	return v, nil
}

// ParseVertex deserializes a vertex from bytes.
func (cvm *ChainVM) ParseVertex(ctx context.Context, b []byte) (vertex.Vertex, error) {
	v, err := deserializeDexVertex(b, cvm)
	if err != nil {
		return nil, err
	}
	return v, nil
}

func serializeDexVertex(v *DexVertex) []byte {
	buf := make([]byte, 0, 256)
	b8 := make([]byte, 8)
	b4 := make([]byte, 4)

	binary.BigEndian.PutUint64(b8, v.height)
	buf = append(buf, b8...)
	binary.BigEndian.PutUint32(b4, v.epoch)
	buf = append(buf, b4...)
	// Proposer-chosen block time (UnixNano) — every validator parses this exact
	// value and feeds it to ProcessBlock, keeping StateRoot deterministic.
	binary.BigEndian.PutUint64(b8, uint64(v.timestamp.UnixNano()))
	buf = append(buf, b8...)
	binary.BigEndian.PutUint32(b4, uint32(len(v.parents)))
	buf = append(buf, b4...)
	for _, p := range v.parents {
		buf = append(buf, p[:]...)
	}
	binary.BigEndian.PutUint32(b4, uint32(len(v.rawTxs)))
	buf = append(buf, b4...)
	for _, raw := range v.rawTxs {
		binary.BigEndian.PutUint32(b4, uint32(len(raw)))
		buf = append(buf, b4...)
		buf = append(buf, raw...)
	}
	// Carried-fills section (RED #9): the proposer's confirmed fills + reserved
	// signature, every validator settles from these. Same encoding as the linear
	// block. NETWORK-UPGRADE-GATED, LOCKSTEP vertex wire-format change.
	buf = append(buf, encodeCarriedFills(v.carriedFills, v.fillSig)...)
	return buf
}

func deserializeDexVertex(data []byte, cvm *ChainVM) (*DexVertex, error) {
	// Minimum: height(8) + epoch(4) + timestamp(8) + parentCount(4).
	if len(data) < 24 {
		return nil, fmt.Errorf("dex vertex data too short: %d", len(data))
	}
	pos := 0
	height := binary.BigEndian.Uint64(data[pos:])
	pos += 8
	epoch := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	timestamp := time.Unix(0, int64(binary.BigEndian.Uint64(data[pos:])))
	pos += 8
	pc := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	parents := make([]ids.ID, pc)
	for i := uint32(0); i < pc; i++ {
		if pos+32 > len(data) {
			return nil, errInvalidBlock
		}
		copy(parents[i][:], data[pos:pos+32])
		pos += 32
	}
	if pos+4 > len(data) {
		return nil, errInvalidBlock
	}
	tc := binary.BigEndian.Uint32(data[pos:])
	pos += 4
	rawTxs := make([][]byte, 0, tc)
	txIDs := make([]ids.ID, 0, tc)
	for i := uint32(0); i < tc; i++ {
		if pos+4 > len(data) {
			return nil, errInvalidBlock
		}
		tl := binary.BigEndian.Uint32(data[pos:])
		pos += 4
		if pos+int(tl) > len(data) {
			return nil, errInvalidBlock
		}
		raw := make([]byte, tl)
		copy(raw, data[pos:pos+int(tl)])
		rawTxs = append(rawTxs, raw)
		h := sha256.Sum256(raw)
		txIDs = append(txIDs, ids.ID(h))
		pos += int(tl)
	}

	// Carried-fills section (RED #9): must be exactly consumed to end-of-vertex.
	entries, sig, consumed, ferr := decodeCarriedFills(data[pos:])
	if ferr != nil {
		return nil, errInvalidBlock
	}
	if pos+consumed != len(data) {
		return nil, errInvalidBlock
	}

	v := &DexVertex{
		height:       height,
		epoch:        epoch,
		timestamp:    timestamp,
		parents:      parents,
		txIDs:        txIDs,
		rawTxs:       rawTxs,
		keys:         extractOrderKeys(rawTxs),
		carriedFills: entries,
		fillSig:      sig,
		status:       choices.Unknown,
		vm:           cvm,
		bytes:        data,
	}
	v.id = v.computeID()
	return v, nil
}
