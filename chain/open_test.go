// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package chain

import (
	"errors"
	"testing"

	"github.com/luxfi/database"
	"github.com/stretchr/testify/require"
)

// unreadableDB fails the tip read specifically, which is how a dead volume or a
// closed handle presents: the key is there, the bytes will not come back.
type unreadableDB struct {
	database.Database
	err   error
	short bool
}

var errUnreadable = errors.New("volume gone")

func (d *unreadableDB) Get(key []byte) ([]byte, error) {
	if string(key) == string(tipKey) {
		if d.short {
			return []byte{1, 2, 3}, nil
		}
		return nil, d.err
	}
	return d.Database.Get(key)
}

// A chain that cannot read its tip does not know where it is. Reading that
// failure as "nothing recorded yet" starts a live chain over at genesis and
// lets it build height 1 on state it cannot see — durably, with the caller
// told it succeeded. Only ABSENCE means a fresh chain.
func TestOpenRefusesAnUnreadableTip(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.store.Accept(newBlock(1, f.genesis.ID(), 1)))

	// The same database, reopened behind a handle that cannot answer for the tip.
	broken := New[*testBlock](&unreadableDB{Database: f.base, err: errUnreadable}, nil)

	_, fresh, err := broken.Open(f.genesis, f.parse)
	require.ErrorIs(t, err, errUnreadable, "the cause must survive the wrap")
	require.False(t, fresh, "an unreadable tip is not a first run")
}

// A tip of the wrong width is corruption, not absence. Rounding it down to a
// fresh chain would discard a live chain because one field was damaged.
func TestOpenRefusesAWrongWidthTip(t *testing.T) {
	f := newFixture(t)
	require.NoError(t, f.store.Accept(newBlock(1, f.genesis.ID(), 1)))

	broken := New[*testBlock](&unreadableDB{Database: f.base, short: true}, nil)

	_, fresh, err := broken.Open(f.genesis, f.parse)
	require.Error(t, err)
	require.ErrorContains(t, err, "want")
	require.False(t, fresh)
}
