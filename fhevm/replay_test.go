// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/mpcvm/fhe"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// F COMMITS NO STATE ROOT, and these tests are what stands in its place.
//
// The package's design turns on determinism: F owns its persistence rather than
// writing through the FHE runtime's Registry, because that Registry stamps
// time.Now() and two validators replaying one block would then store different
// bytes. That argument is only worth making if the property it protects is
// actually checked — and a chain with no state root has nothing in consensus
// that checks it. Two validators could diverge and neither would learn.
//
// So the property is checked here instead, the only way it can be from outside
// consensus: replay the same block on two independently-built nodes and require
// the resulting databases to be byte-identical. That catches a wall clock, a
// random value, an unordered map walk and a float, all at once, and it catches
// them by the effect they have rather than by the names they are spelled with.
//
// Committing a root IN consensus needs something this VM does not have: a state
// layer per in-flight block. Today Verify reads committed state, so a proposer
// cannot know its post-state until Accept, and a root checked only at Accept
// would be a halt an adversary could trigger by proposing a wrong one —
// strictly worse than no root. The same missing layer is why a child of a
// verified-but-unaccepted block cannot be verified (see LLM.md). One
// architectural change closes both; neither is closed by half of it.

// dump serializes every key F has written, in a fixed order, so two databases
// can be compared exactly. Prefixes are walked in a fixed sequence and each
// iterator returns its keys sorted, so the result depends on the DATA and
// nothing else.
func dump(t *testing.T, vm *VM) string {
	t.Helper()
	h := sha256.New()
	var b strings.Builder
	for _, prefix := range []string{
		CiphertextPrefix, PermitPrefix, DecryptPrefix, EpochPrefix, BlockPrefix,
		string(noncePrefix), string(heightPrefix), "fee/",
	} {
		it := vm.state.NewIteratorWithPrefix([]byte(prefix))
		for it.Next() {
			b.WriteString(hex.EncodeToString(it.Key()))
			b.WriteByte('=')
			b.WriteString(hex.EncodeToString(it.Value()))
			b.WriteByte('\n')
			h.Write(it.Key())
			h.Write(it.Value())
		}
		require.NoError(t, it.Error())
		it.Release()
	}
	// The full listing is returned so a failure names the row that differs; the
	// hash is written into it so an identical listing is visibly identical.
	return hex.EncodeToString(h.Sum(nil)) + "\n" + b.String()
}

// replayNode builds a node from bytes identical to every other node's, so that
// any difference in the result comes from applying the block and nothing else.
// That includes the chain id: these nodes are validators of ONE chain, as
// production's are, and the id is not a parameter because there is nothing for
// a caller to vary. A harness that handed each node its own would be describing
// a shape that does not exist, and would excuse the binding it should be
// checking.
func replayNode(t *testing.T, genesis []byte) *VM {
	t.Helper()
	logger := log.NewNoOpLogger()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: testChainID, NetworkID: 96369, Log: logger},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  genesis,
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// TestReplayIsByteIdentical is the property the whole persistence decision
// rests on: two validators handed the same blocks write the same database.
func TestReplayIsByteIdentical(t *testing.T) {
	owner, grantee := newTestKey(t), newTestKey(t)
	committee, members := newCommittee(t, 3)
	alloc := fundAll(append(append([]testKey{}, members...), owner, grantee)...)

	genesis, err := json.Marshal(Genesis{
		Version: 1, Timestamp: 1_700_000_000, Alloc: alloc,
		Committee: committee, Threshold: 2, PublicKey: []byte("network-fhe-public-key"),
	})
	require.NoError(t, err)
	// The producer runs the whole lifecycle, so the blocks exercise every
	// operation and every record type.
	producer := replayNode(t, genesis)
	producer.clock.Set(timeAt(1_700_000_100))

	handle, permitID := seedPermit(t, producer, owner, grantee, fhe.PermitOpDecrypt, 0)
	acceptOne(t, producer, requestTx(t, grantee, testScheme, handle, permitID, 0, 1))
	requestID := deriveRequestID(handle, grantee.addr, 1)
	result := digestOf("agreed-result")
	acceptOne(t, producer, fulfillTx(t, members[0], requestID, result, 1))
	acceptOne(t, producer, fulfillTx(t, members[1], requestID, result, 1))
	next, _ := newCommittee(t, 3)
	acceptOne(t, producer, advanceTx(t, members[0], 1, next, 2, []byte("epoch-1-key"), 2))
	acceptOne(t, producer, advanceTx(t, members[1], 1, next, 2, []byte("epoch-1-key"), 2))
	acceptOne(t, producer, revokeTx(t, owner, permitID, 3))

	require.Equal(t, uint64(8), producer.height, "one block per operation, every kind exercised")
	require.Equal(t, uint64(1), producer.CurrentEpoch(), "the committee rotated")

	// Collect the chain as it went out on the wire.
	var wire [][]byte
	for h := uint64(1); h <= producer.height; h++ {
		id, err := producer.GetBlockIDAtHeight(context.Background(), h)
		require.NoError(t, err)
		blk, err := producer.GetBlock(context.Background(), id)
		require.NoError(t, err)
		wire = append(wire, blk.Bytes())
	}

	// Two fresh nodes replay it. Their clocks differ from the producer's and
	// from each other's, because chain time must come from the block.
	a := replayNode(t, genesis)
	a.clock.Set(timeAt(1_900_000_000))
	b := replayNode(t, genesis)
	b.clock.Set(timeAt(2_100_000_000))

	for _, node := range []*VM{a, b} {
		for _, raw := range wire {
			blk, err := node.ParseBlock(context.Background(), raw)
			require.NoError(t, err)
			require.NoError(t, blk.Verify(context.Background()))
			require.NoError(t, blk.Accept(context.Background()))
		}
	}

	require.Equal(t, dump(t, producer), dump(t, a),
		"a replaying node must write byte-for-byte what the producer wrote")
	require.Equal(t, dump(t, a), dump(t, b),
		"and two replaying nodes must agree with each other")

	// The replayed state is not merely equal, it is the right state.
	require.Equal(t, uint64(1), a.CurrentEpoch())
	rec, ok := a.Decrypt(requestID)
	require.True(t, ok)
	require.Equal(t, fhe.RequestCompleted, rec.Status)
	require.Equal(t, result, rec.ResultHandle)
	pm, ok := a.Permit(permitID)
	require.True(t, ok)
	require.Equal(t, StatusRevoked, pm.Status)
}

// TestReplayIsIndependentOfWallClock pins the specific hazard the persistence
// decision was made to avoid: a record whose timestamp came from the validator
// rather than the block. Both nodes replay with wildly different clocks; if any
// stored field read a clock, the dumps diverge.
func TestReplayIsIndependentOfWallClock(t *testing.T) {
	k := newTestKey(t)
	committee, keys := newCommittee(t, 1)
	genesis, err := json.Marshal(Genesis{
		Version: 1, Timestamp: 1_700_000_000,
		Alloc:     fundAll(append(keys, k)...),
		Committee: committee, Threshold: 1, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)
	producer := replayNode(t, genesis)
	producer.clock.Set(timeAt(1_700_000_500))
	acceptOne(t, producer, registerTx(t, k, testScheme, digestOf("stamped"), 1))
	raw := producer.lastBlock.Bytes()

	follower := replayNode(t, genesis)
	follower.clock.Set(timeAt(1_700_090_000)) // a day later
	blk, err := follower.ParseBlock(context.Background(), raw)
	require.NoError(t, err)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))

	require.Equal(t, dump(t, producer), dump(t, follower))

	rec, ok := follower.Ciphertext(deriveHandle(digestOf("stamped"), testScheme))
	require.True(t, ok)
	require.Equal(t, int64(1_700_000_500), rec.RegisteredAt,
		"the record carries the block's time, not the node's")
}

// TestNoWallClockInTheApplyPath is the cheap companion to the replay tests: it
// names the sources of nondeterminism directly, so a new one is caught at the
// line that introduces it rather than by a dump that differs.
//
// The one clock F may read is vm.clock, and only outside consensus — admission
// filtering and the read surface, where a wrong answer costs a retry rather
// than a fork. Nothing under Accept may read it.
func TestNoWallClockInTheApplyPath(t *testing.T) {
	// Qualified by PACKAGE, because a bare method name says nothing: log.Int is
	// not math/rand.Int, and a check that cannot tell them apart is a check
	// nobody will keep.
	forbidden := map[string]map[string]string{
		"time": {"Now": "wall-clock time diverges between validators"},
		"rand": {"": "randomness in an applied path diverges"},
		"runtime": {
			"GOMAXPROCS": "a result must not depend on the machine",
			"NumCPU":     "a result must not depend on the machine",
		},
	}
	// The apply path: what Accept reaches. state.go holds the derivations,
	// transaction.go the effects, block.go the settlement, batch.go admission.
	for _, name := range []string{"transaction.go", "block.go", "state.go", "batch.go"} {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, name, nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		ast.Inspect(f, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			pkg, ok := sel.X.(*ast.Ident)
			if !ok {
				return true
			}
			calls, watched := forbidden[pkg.Name]
			if !watched {
				return true
			}
			if why, any := calls[""]; any {
				t.Errorf("%s calls %s.%s at %s — %s", name, pkg.Name, sel.Sel.Name,
					fset.Position(sel.Pos()), why)
				return true
			}
			if why, bad := calls[sel.Sel.Name]; bad {
				t.Errorf("%s calls %s.%s at %s — %s", name, pkg.Name, sel.Sel.Name,
					fset.Position(sel.Pos()), why)
			}
			return true
		})
	}

	// And the package as a whole imports no source of randomness.
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, e.Name(), nil, parser.SkipObjectResolution)
		require.NoError(t, err)
		for _, imp := range f.Imports {
			for _, bad := range []string{`"math/rand"`, `"crypto/rand"`, `"math/rand/v2"`} {
				require.NotEqualf(t, bad, imp.Path.Value, "%s imports %s", e.Name(), bad)
			}
		}
	}
}
