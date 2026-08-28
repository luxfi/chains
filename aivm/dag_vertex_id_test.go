// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package aivm

import (
	"testing"

	"github.com/luxfi/ids"
	"github.com/stretchr/testify/require"
)

func txID(b byte) ids.ID {
	var id ids.ID
	id[0] = b
	return id
}

// A vertex id must distinguish vertices that differ. Leaving the transaction
// ids out of the hash made the payload unauthenticated: two vertices carrying
// different work under the same job names shared an id, so a peer asking for
// one could be served the other and could not tell.
func TestVertexIDCoversTheTransactions(t *testing.T) {
	base := &AIVertex{
		height:  7,
		epoch:   1,
		parents: []ids.ID{txID(9)},
		jobIDs:  []string{"job-a", "job-b"},
		txIDs:   []ids.ID{txID(1), txID(2)},
	}
	other := *base
	other.txIDs = []ids.ID{txID(1), txID(3)}

	require.NotEqual(t, base.computeID(), other.computeID(),
		"a vertex carrying different transactions must not share an id")
}

// Concatenating variable-length names without separation is not an encoding:
// ["ab","c"] and ["a","bc"] produce the same bytes, so two distinct vertices
// collide and each is a valid substitute for the other.
func TestVertexIDDoesNotCollideAcrossJobFraming(t *testing.T) {
	mk := func(jobs ...string) *AIVertex {
		return &AIVertex{height: 1, parents: []ids.ID{txID(1)}, jobIDs: jobs}
	}

	for _, pair := range [][2][]string{
		{{"ab", "c"}, {"a", "bc"}},
		{{"a", "b", "c"}, {"abc"}},
		{{""}, {}},
		{{"a", ""}, {"", "a"}},
	} {
		require.NotEqual(t, mk(pair[0]...).computeID(), mk(pair[1]...).computeID(),
			"%v and %v must not share an id", pair[0], pair[1])
	}
}

// The parent set is framed for the same reason, and height and epoch still
// separate otherwise-identical vertices.
func TestVertexIDSeparatesEveryField(t *testing.T) {
	base := &AIVertex{
		height:  3,
		epoch:   2,
		parents: []ids.ID{txID(1), txID(2)},
		txIDs:   []ids.ID{txID(5)},
		jobIDs:  []string{"j"},
	}
	id := base.computeID()

	for name, mutate := range map[string]func(*AIVertex){
		"height":     func(v *AIVertex) { v.height++ },
		"epoch":      func(v *AIVertex) { v.epoch++ },
		"parent":     func(v *AIVertex) { v.parents = []ids.ID{txID(1), txID(3)} },
		"parent set": func(v *AIVertex) { v.parents = []ids.ID{txID(1)} },
		"tx set":     func(v *AIVertex) { v.txIDs = nil },
		"job":        func(v *AIVertex) { v.jobIDs = []string{"k"} },
	} {
		v := *base
		mutate(&v)
		require.NotEqual(t, id, v.computeID(), "changing the %s must change the id", name)
	}
}

// The same vertex hashes the same way every time — an id that moved between
// calls would make a block unfindable by the id its peers were given.
func TestVertexIDIsStable(t *testing.T) {
	v := &AIVertex{
		height:  1,
		parents: []ids.ID{txID(1)},
		txIDs:   []ids.ID{txID(2)},
		jobIDs:  []string{"job"},
	}
	require.Equal(t, v.computeID(), v.computeID())
}
