// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package dexvm

import (
	"encoding/binary"
	"fmt"
	"math"
)

// carried_fills.go — the CARRIED-FILLS primitive of the stateless atomic ZAP
// proxy: the block/vertex-borne record of the d-chain matcher's confirmed fills.
//
// ─────────────────────────────────────────────────────────────────────────────
// CONSENSUS-SAFETY RATIONALE (RED finding #9 — per-validator relay forks the
// chain). The proxy's block output MUST be a pure function of (height, carried
// time, tx bytes). A clob_submit relay is STATE-MUTATING on the d-chain AND its
// returned fills depend on WHEN the call lands (the book moves between calls). If
// each validator issues its own relay while processing a block, each receives
// independently-timed fills => different settlement export => different StateRoot
// => the network forks. (Proven by TestRED_PerValidatorRelay_SplitsConsensus.)
//
// THE FIX (this primitive). The relay is performed EXACTLY ONCE for the whole
// network — by the block PROPOSER, at BuildBlock/BuildVertex (VM.obtainFills) —
// and the confirmed fills are CARRIED in the block/vertex bytes. Every validator
// (including the proposer at Verify) settles purely from these carried fills
// (VM.settleCarried); no validator ever relays during Verify or Accept. The
// matcher is therefore hit at most once per order, network-wide, and every node
// reproduces byte-identical settlement => identical StateRoot.
//
// ─────────────────────────────────────────────────────────────────────────────
// WIRE FORMAT — NETWORK-UPGRADE-GATED, LOCKSTEP VALIDATOR CHANGE. Carrying fills
// in the block/vertex bytes CHANGES THE BLOCK/VERTEX WIRE FORMAT (block.go
// Block.Bytes/parseBlock and dag_vertex.go serialize/deserializeDexVertex). It is
// consensus-breaking: a node on the old format cannot parse a new block and vice
// versa. It MUST be activated in lockstep across the whole validator set behind a
// network upgrade (the genesis/upgrade gate is the operator's call — see the
// human sign-off note in the package README/commit). The fills section is
// length-prefixed and self-delimiting so the format is unambiguous.
//
// TRUST SURFACE — bounded, interim. Trusting a single proposer to report the
// fills introduces a proposer-trust surface (a lying proposer could carry
// fabricated fills). It is BOUNDED BY VALUE CONSERVATION, not by trust: the
// settle path (settleFromFills) refuses spent > locked (the proxy never mints),
// so the blast radius of a lying proposer is at most ONE taker's own escrow —
// never supply inflation. This is the canonical model TODAY because the venue is
// single-operator. The trustless path (the d-chain SIGNS its fills; a P3Q ->
// starkfri verifier checks the signature on-chain) rides the RESERVED signature
// field below, so making the proxy trustless later needs NO second wire-format
// bump.
//
// FROZEN-FRAME NOTE. This is the BLOCK format, NOT the ZAP fill frame. The 17-byte
// FillWireSize ZAP frame (relay.go / dex/pkg/zapwire / precompile) is UNCHANGED;
// the per-fill encoding here reuses the same price[8]+size[8]+side[1] layout for
// continuity but is a distinct, block-level structure.

// carriedFill binds one settling relay's confirmed fills to its position in the
// block. txIndex is the relay tx's index in the block (the same coordinate that
// keys the idempotency receipt and seeds the deterministic settlement export), so
// settleCarried can match carried fills back to the planned relay and settle the
// correct collateral with a byte-identical export identity on every validator.
type carriedFill struct {
	// txIndex is the relay tx's position in the block.
	txIndex uint32
	// fills are the d-chain matcher's confirmed fills for that relay (possibly
	// empty: a zero-fill submit still carries an entry so the validator settles a
	// full refund rather than guessing).
	fills []Fill
}

// maxCarriedFillEntries / maxFillsPerEntry bound the carried-fills section so a
// malformed or hostile block cannot force an unbounded allocation at parse time.
// They are generous relative to MaxTxsPerBlock yet finite; a block exceeding them
// is rejected as malformed wire.
const (
	maxCarriedFillEntries = 1 << 20
	maxFillsPerEntry      = 1 << 20
)

// encodeCarriedFills serializes the carried-fills section appended to a block /
// vertex:
//
//	entryCount[4]
//	  for each entry:
//	    txIndex[4]
//	    fillCount[4]
//	    fillCount × ( price[8] | size[8] | side[1] )   // FillWireSize bytes each
//	sigLen[4]
//	sig[sigLen]                                          // reserved (empty today)
//
// The sig field is the RESERVED d-chain fill-attestation slot (see the trustless
// path note above): carried now so the future signed-fills upgrade needs no
// further wire-format change. Today it is always empty.
func encodeCarriedFills(entries []carriedFill, sig []byte) []byte {
	size := 4
	for _, e := range entries {
		size += 4 + 4 + len(e.fills)*FillWireSize
	}
	size += 4 + len(sig)

	buf := make([]byte, size)
	off := 0
	binary.BigEndian.PutUint32(buf[off:], uint32(len(entries)))
	off += 4
	for _, e := range entries {
		binary.BigEndian.PutUint32(buf[off:], e.txIndex)
		off += 4
		binary.BigEndian.PutUint32(buf[off:], uint32(len(e.fills)))
		off += 4
		for _, f := range e.fills {
			binary.BigEndian.PutUint64(buf[off:off+8], math.Float64bits(f.Price))
			binary.BigEndian.PutUint64(buf[off+8:off+16], math.Float64bits(f.Size))
			buf[off+16] = f.Side
			off += FillWireSize
		}
	}
	binary.BigEndian.PutUint32(buf[off:], uint32(len(sig)))
	off += 4
	copy(buf[off:], sig)
	return buf
}

// decodeCarriedFills parses the carried-fills section written by
// encodeCarriedFills. It returns the entries, the reserved signature, the number
// of bytes consumed, and any error. Every field is range-checked so a hostile or
// truncated block cannot inject a malformed fill into settlement or over-allocate:
//   - the per-fill price/size must be finite and strictly positive and side ∈
//     {0,1} (the SAME boundary invariant DecodeFills enforces on the ZAP wire),
//     so no impossible Fill ever reaches settleFromFills;
//   - counts are bounded (maxCarriedFillEntries / maxFillsPerEntry);
//   - the section must be exactly consumed by the declared lengths.
//
// data is the carried-fills section ONLY (the block/vertex parser passes the
// remaining bytes after the txs). consumed lets a caller assert the section ends
// the block (no trailing garbage).
func decodeCarriedFills(data []byte) (entries []carriedFill, sig []byte, consumed int, err error) {
	if len(data) < 4 {
		return nil, nil, 0, fmt.Errorf("carried fills: section too short: %d", len(data))
	}
	off := 0
	n := int(binary.BigEndian.Uint32(data[off:]))
	off += 4
	if n < 0 || n > maxCarriedFillEntries {
		return nil, nil, 0, fmt.Errorf("carried fills: entry count out of range: %d", n)
	}
	entries = make([]carriedFill, 0, n)
	for i := 0; i < n; i++ {
		if off+8 > len(data) {
			return nil, nil, 0, fmt.Errorf("carried fills: truncated entry header %d", i)
		}
		txIndex := binary.BigEndian.Uint32(data[off:])
		off += 4
		fc := int(binary.BigEndian.Uint32(data[off:]))
		off += 4
		if fc < 0 || fc > maxFillsPerEntry {
			return nil, nil, 0, fmt.Errorf("carried fills: fill count out of range: %d", fc)
		}
		if off+fc*FillWireSize > len(data) {
			return nil, nil, 0, fmt.Errorf("carried fills: truncated fills for entry %d (count=%d)", i, fc)
		}
		fills := make([]Fill, 0, fc)
		for j := 0; j < fc; j++ {
			p := float64FromBits(data[off : off+8])
			s := float64FromBits(data[off+8 : off+16])
			side := data[off+16]
			off += FillWireSize
			if !isFinitePositive(p) {
				return nil, nil, 0, fmt.Errorf("carried fills: entry %d fill %d invalid price %v", i, j, p)
			}
			if !isFinitePositive(s) {
				return nil, nil, 0, fmt.Errorf("carried fills: entry %d fill %d invalid size %v", i, j, s)
			}
			if side > 1 {
				return nil, nil, 0, fmt.Errorf("carried fills: entry %d fill %d invalid side %d", i, j, side)
			}
			fills = append(fills, Fill{Price: p, Size: s, Side: side})
		}
		entries = append(entries, carriedFill{txIndex: txIndex, fills: fills})
	}
	if off+4 > len(data) {
		return nil, nil, 0, fmt.Errorf("carried fills: missing signature length")
	}
	sigLen := int(binary.BigEndian.Uint32(data[off:]))
	off += 4
	if sigLen < 0 || off+sigLen > len(data) {
		return nil, nil, 0, fmt.Errorf("carried fills: signature length out of range: %d", sigLen)
	}
	if sigLen > 0 {
		sig = make([]byte, sigLen)
		copy(sig, data[off:off+sigLen])
	}
	off += sigLen
	return entries, sig, off, nil
}

// fillsForTx returns the carried fills bound to txIndex, and whether an entry was
// present. An ABSENT entry (found=false) means the block carried no fills for that
// relay — the settle treats it as a full refund (nothing realized). A PRESENT but
// empty entry (found=true, len==0) is an explicit zero-fill, settled identically;
// the distinction is kept so a proposer can be explicit and a validator never has
// to infer intent.
func fillsForTx(entries []carriedFill, txIndex uint32) ([]Fill, bool) {
	for _, e := range entries {
		if e.txIndex == txIndex {
			return e.fills, true
		}
	}
	return nil, false
}
