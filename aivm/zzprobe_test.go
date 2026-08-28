package aivm

import (
	"context"
	"testing"
	"time"

	"github.com/holiman/uint256"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/luxfi/zap"
	"github.com/stretchr/testify/require"
)

func probeVM(t *testing.T, db *memdb.Database) *VM {
	t.Helper()
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       db,
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}))
	vm.SetCommitVerifier(VerifierFunc(func(CIntent) error { return nil }))
	return vm
}

// P1: does Accept persist the tip? Restart on the same DB and see what head we name.
func TestProbe_P1_RestartLosesTip(t *testing.T) {
	db := memdb.New()
	vm := probeVM(t, db)
	ctx := context.Background()
	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blk.Verify(ctx))
	require.NoError(t, blk.Accept(ctx))
	head, _ := vm.LastAccepted(ctx)
	require.Equal(t, blk.ID(), head)

	vm2 := probeVM(t, db)
	head2, _ := vm2.LastAccepted(ctx)
	t.Logf("tip before restart=%s after restart=%s", head, head2)
	if head2 != head {
		t.Errorf("P1 CONFIRMED: restart forgot the accepted tip (came back at %s)", head2)
	}
}

// P2: does Verify check the parent is the tip / the height follows?
func TestProbe_P2_NoTipCheck(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	b1, _ := vm.BuildBlock(ctx)
	require.NoError(t, b1.Verify(ctx))
	require.NoError(t, b1.Accept(ctx))

	// A block naming a parent that is not the tip, at an arbitrary height.
	orphan := &Block{ParentID_: ids.GenerateTestID(), Height_: 99, Timestamp_: time.Now(), vm: vm}
	orphan.ID_ = orphan.computeID()
	err := orphan.Verify(ctx)
	t.Logf("verify(orphan parent, height 99) = %v", err)
	if err == nil {
		t.Errorf("P2 CONFIRMED: a block with an unknown parent and a jumped height verifies")
	}
	// And one that rewinds height below the tip.
	rewind := &Block{ParentID_: b1.Parent(), Height_: 1, Timestamp_: time.Now(), vm: vm}
	rewind.ID_ = rewind.computeID()
	if err := rewind.Verify(ctx); err == nil {
		if err := rewind.Accept(ctx); err == nil {
			head, _ := vm.LastAccepted(ctx)
			t.Errorf("P2 CONFIRMED: an old sibling was accepted and became the head (%s)", head)
		}
	}
}

// P3/P4: one shared staging versiondb across every pending block.
func TestProbe_P3_CrossBlockStaging(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, _ := vm.QuorumEngine()
	seedOperators(t, vm, e, st, reward)

	// Block A: no intent. Block B: one intent (writes engine state).
	blkA, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blkA.Verify(ctx))

	intent := buildIntent(e, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), reward)
	vm.EnqueueCommittedIntent(intent)
	blkB, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blkB.Verify(ctx))

	// Accept only A. B's writes must NOT become durable.
	require.NoError(t, blkA.Accept(ctx))

	raw := NewDBState(vm.db)
	if isSet(raw.GetState(slotHash(nsIntentSeen, intent.IntentID))) {
		t.Errorf("P3 CONFIRMED: Accept(A) committed block B's staged intent to the durable DB")
	}
}

func TestProbe_P4_RejectDropsSiblingWrites(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, _ := vm.QuorumEngine()
	seedOperators(t, vm, e, st, reward)

	intent := buildIntent(e, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), reward)
	vm.EnqueueCommittedIntent(intent)
	blkA, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blkA.Verify(ctx))

	blkB, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blkB.Verify(ctx))
	require.NoError(t, blkB.Reject(ctx))

	require.NoError(t, blkA.Accept(ctx))
	raw := NewDBState(vm.db)
	if !isSet(raw.GetState(slotHash(nsIntentSeen, intent.IntentID))) {
		t.Errorf("P4 CONFIRMED: Reject(B) dropped block A's staged writes; Accept(A) committed nothing")
	}
}

func seedOperators(t *testing.T, vm *VM, e *Engine, st QuorumState, reward *uint256.Int) {
	t.Helper()
	requester := addrOf(0xF0)
	fund := new(uint256.Int).Mul(reward, uint256.NewInt(64))
	opening := map[common.Address]*uint256.Int{requester: fund}
	ops := make([]common.Address, consciousEligible)
	for i := range ops {
		ops[i] = addrOf(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	require.NoError(t, vm.FundLedger(opening))
	_, _, lg := vm.QuorumEngine()
	for i, op := range ops {
		require.NoError(t, e.RegisterOperator(st, lg, op,
			new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), hashOf(0xAB), hashOf(byte(0x80+i))))
	}
}

// P6: is the wire canonical? Feed padding the parser ignores and compare ids.
func TestProbe_P6_WireMalleable(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	blk := &Block{ParentID_: ids.GenerateTestID(), Height_: 7, Timestamp_: time.Unix(0, 1700000000)}
	blk.Tasks = nil
	canonical, err := blk.Marshal()
	require.NoError(t, err)

	parsed, err := vm.ParseBlock(ctx, canonical)
	require.NoError(t, err)
	require.Equal(t, canonical, parsed.Bytes())

	// zap builder pads; probe whether a longer buffer with the same declared root
	// still parses.
	padded := append(append([]byte(nil), canonical...), 0x00)
	if _, err := vm.ParseBlock(ctx, padded); err == nil {
		t.Errorf("P6 CONFIRMED: a trailing byte past the content still parses")
	} else {
		t.Logf("padded parse rejected: %v", err)
	}
}

// P6b: unpackObjs/unpackJSON ignore blob remainder; splitIDs ignores a short tail.
func TestProbe_P6b_BlobRemainderIgnored(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	// Build a block wire by hand with an intent blob longer than the declared lens.
	in := CIntent{IntentID: hashOf(1), Fee: uint256.NewInt(1), RewardPerOperator: uint256.NewInt(1)}
	one := marshalCIntent(in)
	lens := []uint32{uint32(len(one))}
	blob := append(append([]byte(nil), one...), 0xDE, 0xAD, 0xBE, 0xEF) // 4 stray bytes

	b := zap.NewBuilder(zap.HeaderSize + blkSize + len(blob) + 256)
	lensOff := writeU32List(b, lens)
	ob := b.StartObject(blkSize)
	ob.SetUint8(blkKind, uint8(kindBlock))
	ob.SetUint64(blkHeight, 3)
	ob.SetList(blkIntentLens, lensOff, len(lens))
	ob.SetBytes(blkIntentBlob, blob)
	ob.FinishAsRoot()
	wire := b.Finish()

	parsed, err := vm.ParseBlock(ctx, wire)
	if err == nil {
		t.Errorf("P6b CONFIRMED: %d stray bytes in the intent blob were ignored; id=%s", 4, parsed.ID())
	} else {
		t.Logf("stray blob bytes rejected: %v", err)
	}
}

// P7: is there any size bound on an inbound block?
func TestProbe_P7_NoSizeBound(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	big := make([]ProviderReg, 0, 20000)
	for i := 0; i < 20000; i++ {
		big = append(big, ProviderReg{ProviderID: string(make([]byte, 400))})
	}
	blk := &Block{Height_: 1, ProviderRegs: big}
	wire, err := blk.Marshal()
	require.NoError(t, err)
	t.Logf("block wire size = %d bytes", len(wire))
	if _, err := vm.ParseBlock(ctx, wire); err == nil && len(wire) > 4<<20 {
		t.Errorf("P7 CONFIRMED: a %d-byte block parsed with no size bound", len(wire))
	}
}

// P8: is a block bound to the chain it was built on?
func TestProbe_P8_NoChainBinding(t *testing.T) {
	ctx := context.Background()
	vmA := probeVM(t, memdb.New())
	vmB := probeVM(t, memdb.New())
	blk, err := vmA.BuildBlock(ctx)
	require.NoError(t, err)
	wire := blk.Bytes()
	foreign, err := vmB.ParseBlock(ctx, wire)
	if err == nil && foreign.ID() == blk.ID() {
		t.Errorf("P8 CONFIRMED: a block built on chain A parses byte-identically on chain B (id %s)", foreign.ID())
	}
}

// P9: chain time. Does Verify bound the timestamp at all?
func TestProbe_P9_UnboundedTimestamp(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	b1, _ := vm.BuildBlock(ctx)
	require.NoError(t, b1.Verify(ctx))
	require.NoError(t, b1.Accept(ctx))

	future := &Block{ParentID_: b1.ID(), Height_: 2, Timestamp_: time.Now().Add(1000 * time.Hour), vm: vm}
	future.ID_ = future.computeID()
	if err := future.Verify(ctx); err == nil {
		t.Errorf("P9 CONFIRMED: a timestamp 1000h in the future verifies")
	}
	past := &Block{ParentID_: b1.ID(), Height_: 2, Timestamp_: b1.Timestamp().Add(-time.Hour), vm: vm}
	past.ID_ = past.computeID()
	if err := past.Verify(ctx); err == nil {
		t.Errorf("P9 CONFIRMED: a timestamp BEFORE the parent's verifies")
	}
}

// P10/P11: what does the vertex id actually cover?
func TestProbe_P10_VertexIDDoesNotCoverPayload(t *testing.T) {
	vm := probeVM(t, memdb.New())
	v := &AIVertex{height: 1, epoch: 0, parents: []ids.ID{ids.Empty}, jobIDs: []string{"job-1"}, vm: vm}
	v.id = v.computeID()
	v2 := &AIVertex{height: 1, epoch: 0, parents: []ids.ID{ids.Empty}, jobIDs: []string{"job-1"},
		txIDs: []ids.ID{ids.GenerateTestID()}, vm: vm}
	if v.computeID() == v2.computeID() {
		t.Errorf("P10 CONFIRMED: vertex id ignores txIDs — payload is unauthenticated")
	}
	a := &AIVertex{height: 1, jobIDs: []string{"ab", "c"}}
	b := &AIVertex{height: 1, jobIDs: []string{"a", "bc"}}
	if a.computeID() == b.computeID() {
		t.Errorf("P11 CONFIRMED: jobIDs are concatenated unseparated — [ab,c] and [a,bc] collide")
	}
}

// P12: packJSON drops the marshal error.
func TestProbe_P12_UnmarshalableTaskSilentlyEmptied(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	blk := &Block{Height_: 1, ProviderRegs: []ProviderReg{{ProviderID: string([]byte{0xff, 0xfe})}}}
	// json.Marshal fails on invalid UTF-8? No — it escapes. Use a RawMessage instead.
	wire, err := blk.Marshal()
	require.NoError(t, err)
	if _, err := vm.ParseBlock(ctx, wire); err != nil {
		t.Logf("P12: parse of an odd ProviderReg failed: %v", err)
	}
}

// P13: is the merkle proof index authenticated?
func TestProbe_P13_ProofIndexUnbound(t *testing.T) {
	leaves := []common.Hash{hashOf(1), hashOf(2), hashOf(3), hashOf(4)}
	hashed := make([]common.Hash, len(leaves))
	for i, l := range leaves {
		hashed[i] = leafHash(l)
	}
	root := merkleRoot(hashed)
	p := merkleProof(hashed, 0)
	require.True(t, VerifyReceiptProof(leaves[0], p, root))
	// Same siblings, a wildly out-of-range index whose low bits match.
	p2 := MerkleProof{Index: p.Index + 1<<uint(len(p.Siblings)), Siblings: p.Siblings}
	if VerifyReceiptProof(leaves[0], p2, root) {
		t.Errorf("P13 CONFIRMED: proof verifies at index %d in a 4-leaf tree", p2.Index)
	}
	// Truncated proof against a deeper tree.
	if VerifyReceiptProof(leaves[0], MerkleProof{Index: 0, Siblings: nil}, leafHash(leaves[0])) {
		t.Logf("P13: a zero-sibling proof verifies against a single-leaf root (expected)")
	}
}

// P18: Initialize with no Runtime.
func TestProbe_P18_NilRuntime(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("P18 CONFIRMED: Initialize panics with a nil Runtime: %v", r)
		}
	}()
	vm := &VM{}
	err := vm.Initialize(context.Background(), vmcore.Init{DB: memdb.New()})
	t.Logf("Initialize(no runtime) = %v", err)
}
