// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package bridgevm

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/luxfi/database"
	"github.com/luxfi/ids"
)

// The bridge's spend state: which transfers it has settled, and how much has
// moved to each destination on each day. Both are written in the same commit
// as the block that moves them, so a restart resumes where the chain is
// rather than where memory was. Held in memory alone, the daily counter reset
// to zero on every restart and an operator restart was a free reset of the
// cap; a cap that can be forgotten is not a cap.
//
// Everything here is a function of committed state and the block's own
// contents, so every node computes the same answer.

// dayLength is the window the daily cap is measured over. The window is cut
// from the BLOCK's timestamp, never the wall clock: consensus decides what
// time it is, so every node closes the window on the same block.
const dayLength = 86400

var (
	settledPrefix = []byte("bridge/settled/") // + 32-byte transfer digest
	movedPrefix   = []byte("bridge/moved/")   // + 8-byte day + 4-byte destination chain
)

// errReplay reports a transfer this chain has already settled.
var errReplay = errors.New("bridgevm: transfer already settled")

func settledKey(id ids.ID) []byte {
	return append(append([]byte(nil), settledPrefix...), id[:]...)
}

func movedKey(day int64, dst uint32) []byte {
	k := make([]byte, 0, len(movedPrefix)+12)
	k = append(k, movedPrefix...)
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(day))
	k = append(k, buf[:]...)
	binary.BigEndian.PutUint32(buf[:4], dst)
	return append(k, buf[:4]...)
}

// settled is what a settlement record holds. The record IS the fact — this
// transfer has been settled by this chain — and the block that settled it is
// already named by the chain itself, so a copy of it here would be a second
// record of the same thing, able to disagree.
var settled = []byte{1}

// spend is the bridge's state as of one block: committed state, plus whatever
// the blocks between it and the accepted tip have already decided.
//
// moved holds ABSOLUTE totals, seeded from the database the first time a
// window is touched and carried whole to descendants. An overlay of deltas
// would double-count as soon as an ancestor was accepted, because the
// database then holds the same amount the overlay still remembers.
//
// settled is an overlay, which is right for a set: the database only ever
// gains entries, so committed-or-remembered is the answer either way.
type spend struct {
	db      database.KeyValueReader
	moved   map[string]uint64
	settled map[ids.ID]struct{}
}

func newSpend(db database.KeyValueReader) *spend {
	return &spend{db: db, moved: map[string]uint64{}, settled: map[ids.ID]struct{}{}}
}

// clone is what a child block starts from. The maps are copied because the
// child accumulates into them and its parent may still be asked the same
// questions by a sibling.
func (s *spend) clone() *spend {
	out := &spend{db: s.db, moved: make(map[string]uint64, len(s.moved)), settled: make(map[ids.ID]struct{}, len(s.settled))}
	for k, v := range s.moved {
		out.moved[k] = v
	}
	for k := range s.settled {
		out.settled[k] = struct{}{}
	}
	return out
}

func (s *spend) movedOn(day int64, dst uint32) (uint64, error) {
	key := movedKey(day, dst)
	if v, ok := s.moved[string(key)]; ok {
		return v, nil
	}
	raw, err := s.db.Get(key)
	switch {
	case errors.Is(err, database.ErrNotFound):
		return 0, nil
	case err != nil:
		return 0, err
	}
	v, err := readCounter(raw)
	if err != nil {
		return 0, err
	}
	s.moved[string(key)] = v
	return v, nil
}

func (s *spend) isSettled(id ids.ID) (bool, error) {
	if _, ok := s.settled[id]; ok {
		return true, nil
	}
	has, err := s.db.Has(settledKey(id))
	if err != nil {
		return false, err
	}
	return has, nil
}

// record marks the transfer settled and charges its amount to the window. It
// runs only after admit has said yes.
func (s *spend) record(day int64, req *BridgeRequest, was uint64) {
	s.settled[req.ID] = struct{}{}
	s.moved[string(movedKey(day, req.DstChainID))] = was + req.Amount
}

func readCounter(raw []byte) (uint64, error) {
	if len(raw) != 8 {
		return 0, fmt.Errorf("bridgevm: counter is %d bytes, want 8", len(raw))
	}
	return binary.BigEndian.Uint64(raw), nil
}

func counterBytes(v uint64) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], v)
	return out[:]
}

// admissible is everything about a transfer that can be decided without
// asking the chain what it has already done: it is well formed, it is what it
// says it is, and it is within the per-transfer cap.
//
// It runs where a lock is first read as well as where a block is checked. A
// transfer that fails here can never be carried by any block, and holding one
// would have it proposed, refused, and proposed again for as long as the node
// runs.
func admissible(cfg *BridgeConfig, req *BridgeRequest) error {
	transfer, err := req.transfer()
	if err != nil {
		return err
	}
	// The request's id IS its transfer. Without this the id is a label the
	// proposer chooses, so the same deposit rides in under a hundred ids and
	// the replay guard, the daily counter and the release all key off a name
	// that has nothing to do with what is being moved.
	if ids.ID(transfer.Digest()) != req.ID {
		return fmt.Errorf("bridgevm: request %s is not the digest of the transfer it carries", req.ID)
	}
	if req.SrcChainID == 0 {
		return fmt.Errorf("bridgevm: request %s names no source chain", req.ID)
	}
	if req.SrcChainID == req.DstChainID {
		return fmt.Errorf("bridgevm: request %s bridges chain %d to itself", req.ID, req.SrcChainID)
	}
	if req.Amount == 0 {
		return fmt.Errorf("bridgevm: request %s moves nothing", req.ID)
	}
	if req.Amount > cfg.MaxBridgeAmount {
		return fmt.Errorf("bridgevm: request %s moves %d, over the %d per-transfer cap",
			req.ID, req.Amount, cfg.MaxBridgeAmount)
	}
	return nil
}

// admit is the ONE rule for whether a block may carry this transfer at this
// point in the chain, and it records the transfer when the answer is yes.
//
// Assembly asks it and Verify asks it, over the same state, in the same
// order. Two rules would disagree eventually, and the first transfer they
// disagreed about would be one the builder keeps proposing and every node
// keeps refusing — block production stops and does not resume.
func (s *spend) admit(cfg *BridgeConfig, day int64, req *BridgeRequest) error {
	if err := admissible(cfg, req); err != nil {
		return err
	}
	already, err := s.isSettled(req.ID)
	if err != nil {
		return err
	}
	if already {
		return fmt.Errorf("%w: %s", errReplay, req.ID)
	}
	was, err := s.movedOn(day, req.DstChainID)
	if err != nil {
		return err
	}
	// Written as a subtraction so a total near the top of the range cannot
	// wrap past the cap.
	if req.Amount > cfg.DailyBridgeLimit-was {
		return fmt.Errorf("bridgevm: request %s would move %d to chain %d, over the %d daily cap (%d already moved)",
			req.ID, req.Amount, req.DstChainID, cfg.DailyBridgeLimit, was)
	}
	s.record(day, req, was)
	return nil
}

// write stages what the block decided: one settlement record per transfer and
// the day's running total per destination. It reads back through the same
// view it writes to, so two transfers to one destination in one block see
// each other.
func (b *Block) write(db database.Database) error {
	day := b.BlockTimestamp / dayLength
	for _, req := range b.BridgeRequests {
		if err := db.Put(settledKey(req.ID), settled); err != nil {
			return err
		}
		key := movedKey(day, req.DstChainID)
		var was uint64
		raw, err := db.Get(key)
		switch {
		case errors.Is(err, database.ErrNotFound):
		case err != nil:
			return err
		default:
			if was, err = readCounter(raw); err != nil {
				return err
			}
		}
		if err := db.Put(key, counterBytes(was+req.Amount)); err != nil {
			return err
		}
	}
	return nil
}

// spendAt is the state a block built on parent starts from.
//
// A parent this node verified carries the answer already, folded over
// everything its own ancestors decided. A parent that carries none is the
// accepted tip, whose effects are committed, so committed state IS the answer.
// Which of the two a parent is, is settled by the caller: Verify checks it
// against the tip, and a proposal is handed its parent by the store.
//
// It reads the database directly rather than the store, because a proposal
// asks this while the store's lock is already held on its behalf.
func (vm *VM) spendAt(parent *Block) *spend {
	if parent.spend != nil {
		return parent.spend.clone()
	}
	return newSpend(vm.chain.Base())
}

// movedToday reports what has moved to dst on the day the given time falls
// in, from committed state — the same counter the cap is enforced against,
// read rather than kept a second time.
func (vm *VM) movedToday(at int64, dst uint32) (uint64, error) {
	return newSpend(vm.chain.Base()).movedOn(at/dayLength, dst)
}
