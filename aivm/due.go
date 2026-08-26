// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"github.com/holiman/uint256"

	"github.com/luxfi/geth/common"
)

// A task that nobody settles pays nobody. Operators are selected, they commit,
// they reveal — and the verdict that turns those reveals into credit, slashing
// and a receipt only happens when Settle runs. This file is what makes it run:
// every block settles the tasks whose reveal window has closed, so a task
// reaches its verdict by the chain advancing rather than by anyone asking.
//
// The set settled by a block is a function of the state and the height alone.
// That is what lets a follower reach the same verdict without being told: it
// applies the block's imports, runs the same pass at the same height over the
// same state, and compares receipt roots. A divergence in who was paid changes
// the root, which Verify already refuses.

// Settling requires enumerating tasks, and engine state is keyed by slot hash
// with nothing to iterate. So live tasks are held in an array in state: appended
// when the task is created, removed when it reaches a verdict. It holds only the
// tasks still awaiting one, so the work a block does is bounded by what is open
// rather than by everything the chain has ever done.
var (
	nsLiveCount = []byte("av/live.cnt") // number of live-task entries
	nsLiveTask  = []byte("av/live")     // live-task array element (index -> task id)
)

func liveCount(st QuorumState) uint32 {
	return uint32(st.GetState(slotNS(nsLiveCount)).Big().Uint64())
}

func setLiveCount(st QuorumState, n uint32) {
	st.SetState(slotNS(nsLiveCount), h32(uint256.NewInt(uint64(n))))
}

func liveAt(st QuorumState, i uint32) common.Hash {
	return st.GetState(slotNSIdx(nsLiveTask, i))
}

func setLiveAt(st QuorumState, i uint32, id common.Hash) {
	st.SetState(slotNSIdx(nsLiveTask, i), id)
}

// trackLive records a task as awaiting a verdict.
func trackLive(st QuorumState, taskID common.Hash) {
	n := liveCount(st)
	setLiveAt(st, n, taskID)
	setLiveCount(st, n+1)
}

// dropLive removes the entry at i by moving the last entry into its place. The
// order of the array is therefore not the order tasks arrived, which costs
// nothing: every node performs the identical swap against identical state, so
// they agree on the array as much as on anything else in it.
func dropLive(st QuorumState, i uint32) {
	n := liveCount(st)
	if n == 0 || i >= n {
		return
	}
	last := n - 1
	if i != last {
		setLiveAt(st, i, liveAt(st, last))
	}
	setLiveAt(st, last, common.Hash{})
	setLiveCount(st, last)
}

// SettleDue gives a verdict to every task whose reveal window closed at or
// before height, and returns how many it settled.
//
// A task is due when the chain has passed its reveal deadline: until then
// operators may still reveal, and settling early would decide the question
// against whoever answered fastest. Once past it, waiting longer cannot change
// the answer, so the verdict is taken.
//
// A task that cannot settle is dropped from the live array rather than retried
// forever. Its escrow is unchanged by the failure, and leaving it in place would
// mean every later block re-attempts the same refusal.
func (e *Engine) SettleDue(st QuorumState, lg QuorumLedger, height uint64) uint32 {
	var settled uint32
	for i := uint32(0); i < liveCount(st); {
		id := liveAt(st, i)
		task := readTask(st, id)

		switch {
		case task.Status == TaskNone:
			// No such task: an entry that outlived what it named.
			dropLive(st, i)
		case isSet(st.GetState(slotHash(nsSettled, id))):
			dropLive(st, i)
		case height <= task.RevealDeadline:
			// The window is open; operators may still answer.
			i++
		default:
			if _, err := e.Settle(st, lg, id, height); err == nil {
				settled++
			}
			dropLive(st, i)
		}
	}
	return settled
}

// LiveTasks reports how many tasks are awaiting a verdict.
func (e *Engine) LiveTasks(st QuorumState) uint32 { return liveCount(st) }
