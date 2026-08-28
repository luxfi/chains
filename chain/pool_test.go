// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/ids"
)

type entry struct {
	id ids.ID
}

func at(n byte) entry { return entry{id: ids.ID{n}} }

func claimOf(e entry) ids.ID { return e.id }

func newTestPool(max int) *Pool[entry, ids.ID] { return NewPool(max, claimOf) }

func TestAPoolHandsBackWhatItWasGivenInOrder(t *testing.T) {
	p := newTestPool(8)
	require.NoError(t, p.Add(at(1)))
	require.NoError(t, p.Add(at(2)))
	require.NoError(t, p.Add(at(3)))

	require.Equal(t, []entry{at(1), at(2), at(3)}, p.Take(0))
	require.Equal(t, []entry{at(1), at(2)}, p.Take(2))
	require.Equal(t, 3, p.Len())
}

func TestTakingDoesNotDrain(t *testing.T) {
	p := newTestPool(8)
	require.NoError(t, p.Add(at(1)))

	// A block SELECTS from the pool. An engine may discard a proposal without
	// ever rejecting it, and a pool that drained would go with it.
	require.Len(t, p.Take(0), 1)
	require.Len(t, p.Take(0), 1)
	require.Equal(t, 1, p.Len())
}

func TestASecondClaimOnQueuedWorkIsRefused(t *testing.T) {
	p := newTestPool(8)
	require.NoError(t, p.Add(at(1)))
	require.ErrorIs(t, p.Add(at(1)), ErrHeld)
	require.Equal(t, 1, p.Len())
	require.True(t, p.Holds(ids.ID{1}))
	require.False(t, p.Holds(ids.ID{2}))
}

func TestAFullPoolRefusesRatherThanGrows(t *testing.T) {
	p := newTestPool(2)
	require.NoError(t, p.Add(at(1)))
	require.NoError(t, p.Add(at(2)))
	require.ErrorIs(t, p.Add(at(3)), ErrFull)
	require.Equal(t, 2, p.Len())
}

// TestAClaimDoesNotOutliveItsEntry is the property the derived claim set
// exists for: once the work is done, what it held is free again. A set kept
// alongside the queue rather than derived from it leaks exactly here, and what
// it then refuses is work nothing is going to do.
func TestAClaimDoesNotOutliveItsEntry(t *testing.T) {
	p := newTestPool(8)
	require.NoError(t, p.Add(at(1)))
	require.NoError(t, p.Add(at(2)))

	p.Drop([]entry{at(1)})

	require.Equal(t, []entry{at(2)}, p.Take(0))
	require.False(t, p.Holds(ids.ID{1}), "the dropped entry holds nothing")
	require.True(t, p.Holds(ids.ID{2}), "the one still queued does")
	require.NoError(t, p.Add(at(1)), "and its claim can be made again")
}

func TestDroppingNothingChangesNothing(t *testing.T) {
	p := newTestPool(8)
	require.NoError(t, p.Add(at(1)))
	p.Drop(nil)
	require.Equal(t, 1, p.Len())
	require.True(t, p.Holds(ids.ID{1}))
}

func TestDroppingWhatWasNeverQueuedLeavesTheRestAlone(t *testing.T) {
	p := newTestPool(8)
	require.NoError(t, p.Add(at(1)))
	p.Drop([]entry{at(9)})
	require.Equal(t, []entry{at(1)}, p.Take(0))
	require.True(t, p.Holds(ids.ID{1}))
}

func TestAddingTellsConsensusThereIsSomethingToBuild(t *testing.T) {
	p := newTestPool(8)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	woke := make(chan error, 1)
	go func() {
		_, err := p.Wait(ctx)
		woke <- err
	}()

	require.NoError(t, p.Add(at(1)))
	select {
	case err := <-woke:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("a chain builds nothing until it is told; nothing told it")
	}
}

func TestConcurrentUseOfAPoolDoesNotRace(t *testing.T) {
	p := newTestPool(256)
	done := make(chan struct{})

	for i := 0; i < 4; i++ {
		go func() {
			for {
				select {
				case <-done:
					return
				default:
					p.Take(4)
					p.Len()
					p.Holds(ids.ID{1})
				}
			}
		}()
	}

	for n := 0; n < 200; n++ {
		e := at(byte(n % 200))
		_ = p.Add(e)
		p.Drop([]entry{e})
	}
	close(done)
	require.Zero(t, p.Len())
}
