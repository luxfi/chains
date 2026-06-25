// Copyright (C) 2019-2025, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// allocate_test.go — the Stage 1 end-to-end proof for the leaderless
// pinned-writer ALLOCATOR. It proves the property that replaces raft's
// single-serialized-writer role WITHOUT a leader election: the HRW owner of a
// range is the only validator whose AllocateTx commits, the counter is monotonic
// + contiguous across blocks, disjoint ranges allocate independently through
// their respective owners, and the same range serializes through its one owner —
// all gated deterministically at block Verify with NO network I/O.
//
//	owner allocates       → AllocateTx from the range owner commits; GetAlloc
//	                        reflects it after Accept; [base, base+Count) is
//	                        contiguous + monotonic across blocks.
//	non-owner REJECTED    → an AllocateTx for range R from a non-owner proposer
//	                        fails Verify (the pinned-writer safety property —
//	                        same-range double-write impossible).
//	parallel distinct     → allocations to different ranges by their respective
//	                        owners proceed independently.
//	state root covers it  → committing an allocation changes the block's state
//	                        root, and Verify rejects a block whose claimed root
//	                        does not match.
package schain

import (
	"context"
	"errors"
	"testing"

	"github.com/luxfi/ids"

	"github.com/luxfi/chains/schain/pinning"
	"github.com/luxfi/chains/schain/txs"
)

// validatorMembers builds a deterministic, equal-weight validator set of n nodes.
// NodeID i has byte[0]=i+1 (matching pinning_test.node), so tests can name an
// owner by recomputing pinning.Owner over the same set.
func validatorMembers(n int) []pinning.Member {
	ms := make([]pinning.Member, n)
	for i := range ms {
		var id ids.NodeID
		id[0] = byte(i + 1)
		ms[i] = pinning.Member{NodeID: id, Weight: 10}
	}
	return ms
}

// withValidatorSet installs a BlockContextBuilder that pins the given validator
// set at every height with `proposer` as the block proposer — the Stage 1 stand-in
// for the consensus-runtime seam. Every height resolves to the SAME deterministic
// (set, proposer, epoch), so the owner verdict is reproducible.
func withValidatorSet(cvm *ChainVM, members []pinning.Member, proposer ids.NodeID) {
	cvm.SetBlockContextBuilder(func(_ context.Context, height uint64) (BlockContext, error) {
		return BlockContext{Members: members, Proposer: proposer, Epoch: height}, nil
	})
}

// ownerOf returns the HRW owner of range R under members — the only proposer
// whose AllocateTx for R may commit.
func ownerOf(t *testing.T, rng string, members []pinning.Member) ids.NodeID {
	t.Helper()
	owner, ok := pinning.Owner([]byte(rng), members)
	if !ok {
		t.Fatalf("no owner for range %q", rng)
	}
	return owner
}

// allocate drives one AllocateTx through the full Build -> Verify -> Accept cycle
// and returns the [base, base+Count) range it reserved (read from committed state
// before/after). A nil error means the block committed; a non-nil error is the
// Verify rejection (the owner gate firing).
func allocate(t *testing.T, cvm *ChainVM, rng string, count uint32) (base, next uint64, err error) {
	t.Helper()
	ctx := context.Background()

	base, gerr := cvm.inner.state.GetAlloc(rng)
	if gerr != nil {
		t.Fatalf("GetAlloc(pre): %v", gerr)
	}

	tx := txs.NewAllocateTx(rng, count)
	if serr := cvm.SubmitTx(tx.Bytes()); serr != nil {
		t.Fatalf("SubmitTx: %v", serr)
	}
	blk, berr := cvm.BuildBlock(ctx)
	if berr != nil {
		// The owner gate also fires on the PROPOSER side: a non-owner cannot even
		// build a block carrying an AllocateTx it has no right to emit. Unwrap the
		// BuildBlock wrapper so callers match on the underlying gate error. The
		// mempool is drained on a failed build, so the rejected tx does not leak
		// into a later block.
		return base, base, unwrapBuild(berr)
	}
	if verr := blk.Verify(ctx); verr != nil {
		return base, base, verr // owner gate (or other) rejection — block not accepted
	}
	if aerr := blk.Accept(ctx); aerr != nil {
		t.Fatalf("Accept: %v", aerr)
	}
	next, gerr = cvm.inner.state.GetAlloc(rng)
	if gerr != nil {
		t.Fatalf("GetAlloc(post): %v", gerr)
	}
	return base, next, nil
}

// unwrapBuild strips BuildBlock's wrapper so a caller can match on the underlying
// owner-gate error (errNonOwnerAllocate / errNoValidatorSet), which fires
// proposer-side inside BuildBlock's ProcessBlock for a block the proposer has no
// right to build.
func unwrapBuild(err error) error {
	switch {
	case errors.Is(err, errNonOwnerAllocate):
		return errNonOwnerAllocate
	case errors.Is(err, errNoValidatorSet):
		return errNoValidatorSet
	default:
		return err
	}
}

// TestVerifierRejectsNonOwnerBlock is the verifier-side safety proof: a MALICIOUS
// proposer (the range owner) builds a valid AllocateTx block, but an HONEST
// verifier — which reconstructs the SAME frozen validator set but resolves the
// block's proposer as a NON-owner — rejects it at Verify with errNonOwnerAllocate.
// This is the property peers rely on: a node cannot get a non-owner allocation
// accepted, because every honest verifier recomputes ownership and refuses.
func TestVerifierRejectsNonOwnerBlock(t *testing.T) {
	ctx := context.Background()
	members := validatorMembers(5)
	const rng = "bucket-A"
	owner := ownerOf(t, rng, members)
	var nonOwner ids.NodeID
	for _, m := range members {
		if m.NodeID != owner {
			nonOwner = m.NodeID
			break
		}
	}

	// Proposer (owner) builds a legitimate block.
	proposer, _ := newTestVM(t)
	withValidatorSet(proposer, members, owner)
	tx := txs.NewAllocateTx(rng, 4)
	if err := proposer.SubmitTx(tx.Bytes()); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	blk, err := proposer.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("owner BuildBlock: %v", err)
	}
	blkBytes := blk.Bytes()

	// Honest verifier reconstructs the same set but, on its view, the block's
	// proposer resolves to a NON-owner (e.g. the verifier learns the true proposer
	// identity from the consensus header and it is not the range owner). It must
	// reject the block.
	verifier, _ := newTestVM(t)
	withValidatorSet(verifier, members, nonOwner)
	parsed, err := verifier.ParseBlock(ctx, blkBytes)
	if err != nil {
		t.Fatalf("verifier ParseBlock: %v", err)
	}
	if err := parsed.Verify(ctx); !errors.Is(err, errNonOwnerAllocate) {
		t.Fatalf("verifier accepted non-owner block: err = %v, want errNonOwnerAllocate", err)
	}
	// Nothing leaked into the verifier's committed state.
	if n, _ := verifier.inner.state.GetAlloc(rng); n != 0 {
		t.Fatalf("rejected block leaked allocation on verifier: counter = %d, want 0", n)
	}
}

// TestOwnerAllocatesContiguousMonotonic proves: an AllocateTx from the range
// OWNER commits; the reserved id range is [base, base+Count); and across multiple
// blocks the counter is contiguous + strictly monotonic (block N's next == block
// N+1's base). This is the allocator behaviour raft gave via its single leader —
// now from the HRW owner with no election.
func TestOwnerAllocatesContiguousMonotonic(t *testing.T) {
	cvm, _ := newTestVM(t)
	members := validatorMembers(5)
	const rng = "bucket-A"
	owner := ownerOf(t, rng, members)
	withValidatorSet(cvm, members, owner)

	// Block 1: reserve 8 ids from a fresh counter → [0, 8).
	base, next, err := allocate(t, cvm, rng, 8)
	if err != nil {
		t.Fatalf("owner allocate rejected: %v", err)
	}
	if base != 0 || next != 8 {
		t.Fatalf("first allocation = [%d,%d), want [0,8)", base, next)
	}

	// Block 2: reserve 5 more → [8, 13). Contiguous with block 1, monotonic.
	base2, next2, err := allocate(t, cvm, rng, 5)
	if err != nil {
		t.Fatalf("second owner allocate rejected: %v", err)
	}
	if base2 != next {
		t.Fatalf("allocation not contiguous: block2 base %d != block1 next %d", base2, next)
	}
	if base2 != 8 || next2 != 13 {
		t.Fatalf("second allocation = [%d,%d), want [8,13)", base2, next2)
	}

	// Committed counter reflects the total.
	if n, _ := cvm.inner.state.GetAlloc(rng); n != 13 {
		t.Fatalf("committed counter = %d, want 13", n)
	}
}

// TestNonOwnerAllocateRejected is the pinned-writer SAFETY proof: an AllocateTx
// for range R proposed by a node that is NOT Owner(R) is rejected at Verify
// (errNonOwnerAllocate), its staged write never reaches the durable base, and the
// counter stays untouched. This is why the same range can never have two writers
// — and therefore the same id can never be allocated twice.
func TestNonOwnerAllocateRejected(t *testing.T) {
	cvm, _ := newTestVM(t)
	members := validatorMembers(5)
	const rng = "bucket-A"
	owner := ownerOf(t, rng, members)

	// Pick a proposer that is NOT the owner.
	var nonOwner ids.NodeID
	for _, m := range members {
		if m.NodeID != owner {
			nonOwner = m.NodeID
			break
		}
	}
	if nonOwner == owner || nonOwner == (ids.NodeID{}) {
		t.Fatal("could not find a non-owner validator")
	}
	withValidatorSet(cvm, members, nonOwner)

	_, _, err := allocate(t, cvm, rng, 4)
	if err == nil {
		t.Fatal("non-owner AllocateTx was accepted — pinned-writer safety violated")
	}
	if !errors.Is(err, errNonOwnerAllocate) {
		t.Fatalf("Verify error = %v, want errNonOwnerAllocate", err)
	}
	// The counter must be untouched (no leaked allocation).
	if n, _ := cvm.inner.state.GetAlloc(rng); n != 0 {
		t.Fatalf("rejected allocate moved the counter to %d, want 0", n)
	}
}

// TestEmptyValidatorSetFailsClosed proves the gate fails CLOSED: with no validator
// set, no AllocateTx may commit (ownership cannot be proven, so we never default
// to "the proposer is the owner"). Matches pinning.TestEmptySet's invariant at the
// VM layer.
func TestEmptyValidatorSetFailsClosed(t *testing.T) {
	cvm, _ := newTestVM(t)
	// No BlockContextBuilder installed → empty context → no members.
	_, _, err := allocate(t, cvm, "any-range", 1)
	if err == nil {
		t.Fatal("allocate committed with no validator set — gate did not fail closed")
	}
	if !errors.Is(err, errNoValidatorSet) {
		t.Fatalf("error = %v, want errNoValidatorSet", err)
	}
}

// TestParallelDistinctRangesIndependentOwners proves disjoint ranges allocate
// independently through their RESPECTIVE owners: we find two ranges with
// DIFFERENT owners, and each owner's AllocateTx for its own range commits while
// neither touches the other's counter. This is the win over raft — no single
// leader serializes A and B; their owners decide independently.
func TestParallelDistinctRangesIndependentOwners(t *testing.T) {
	members := validatorMembers(5)

	// Find two ranges owned by different validators.
	rngA, rngB := "", ""
	ownerA, ownerB := ids.NodeID{}, ids.NodeID{}
	for i := 0; i < 200 && (rngA == "" || rngB == ""); i++ {
		r := "range-" + string(rune('a'+i%26)) + string(rune('0'+i/26))
		o := ownerOf(t, r, members)
		if rngA == "" {
			rngA, ownerA = r, o
			continue
		}
		if o != ownerA {
			rngB, ownerB = r, o
		}
	}
	if rngB == "" {
		t.Fatal("could not find two ranges with distinct owners (expected ~80% chance per pair)")
	}

	// Owner A allocates in range A on its own VM view.
	cvmA, _ := newTestVM(t)
	withValidatorSet(cvmA, members, ownerA)
	baseA, nextA, err := allocate(t, cvmA, rngA, 3)
	if err != nil {
		t.Fatalf("owner A allocate in range A rejected: %v", err)
	}
	if baseA != 0 || nextA != 3 {
		t.Fatalf("range A allocation = [%d,%d), want [0,3)", baseA, nextA)
	}
	// Owner A is NOT the owner of range B → its allocate for B is rejected.
	if _, _, err := allocate(t, cvmA, rngB, 3); !errors.Is(err, errNonOwnerAllocate) {
		t.Fatalf("owner A allocate in range B: err = %v, want errNonOwnerAllocate", err)
	}
	// Range B's counter on this view is untouched.
	if n, _ := cvmA.inner.state.GetAlloc(rngB); n != 0 {
		t.Fatalf("range B counter moved on owner A's view = %d, want 0", n)
	}

	// Owner B allocates in range B on its own VM view — independently, no leader.
	cvmB, _ := newTestVM(t)
	withValidatorSet(cvmB, members, ownerB)
	baseB, nextB, err := allocate(t, cvmB, rngB, 7)
	if err != nil {
		t.Fatalf("owner B allocate in range B rejected: %v", err)
	}
	if baseB != 0 || nextB != 7 {
		t.Fatalf("range B allocation = [%d,%d), want [0,7)", baseB, nextB)
	}
}

// TestSameRangeSerializesThroughOneOwner proves the same range serializes through
// its ONE owner: only the owner's AllocateTxs advance the counter, contiguously,
// and a non-owner's attempt is rejected — so even back-to-back allocations to the
// same range yield a single, non-overlapping id sequence (no double-allocation).
func TestSameRangeSerializesThroughOneOwner(t *testing.T) {
	cvm, _ := newTestVM(t)
	members := validatorMembers(5)
	const rng = "hot-bucket"
	owner := ownerOf(t, rng, members)
	withValidatorSet(cvm, members, owner)

	// Owner reserves 10, then 10 more: [0,10) then [10,20) — serialized, contiguous.
	if base, next, err := allocate(t, cvm, rng, 10); err != nil || base != 0 || next != 10 {
		t.Fatalf("alloc 1 = [%d,%d) err=%v, want [0,10) nil", base, next, err)
	}
	if base, next, err := allocate(t, cvm, rng, 10); err != nil || base != 10 || next != 20 {
		t.Fatalf("alloc 2 = [%d,%d) err=%v, want [10,20) nil", base, next, err)
	}

	// A non-owner cannot interleave a write into the same range.
	var nonOwner ids.NodeID
	for _, m := range members {
		if m.NodeID != owner {
			nonOwner = m.NodeID
			break
		}
	}
	withValidatorSet(cvm, members, nonOwner)
	if _, _, err := allocate(t, cvm, rng, 5); !errors.Is(err, errNonOwnerAllocate) {
		t.Fatalf("non-owner interleave: err = %v, want errNonOwnerAllocate", err)
	}
	// Counter unchanged by the rejected non-owner write.
	if n, _ := cvm.inner.state.GetAlloc(rng); n != 20 {
		t.Fatalf("counter after rejected non-owner write = %d, want 20", n)
	}
}

// TestStateRootCoversAllocThroughVerify proves the block state root covers the
// allocator end-to-end: an honestly-built AllocateTx block verifies (its claimed
// root matches the recomputed root that now includes the advanced counter), and a
// block whose claimed root is tampered is rejected by Verify with
// errStateRootMismatch — so an allocator divergence cannot get a block accepted.
func TestStateRootCoversAllocThroughVerify(t *testing.T) {
	ctx := context.Background()
	members := validatorMembers(5)
	const rng = "rooted-range"
	owner := ownerOf(t, rng, members)

	// (1) Honest allocate block verifies, and its root differs from the empty root
	// (proving the advanced counter is folded into the committed root).
	good, _ := newTestVM(t)
	withValidatorSet(good, members, owner)

	emptyRoot, err := good.inner.state.Root()
	if err != nil {
		t.Fatalf("empty Root: %v", err)
	}
	tx := txs.NewAllocateTx(rng, 4)
	if err := good.SubmitTx(tx.Bytes()); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	blk, err := good.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	if err := blk.Verify(ctx); err != nil {
		t.Fatalf("honest allocate block rejected: %v", err)
	}
	if afterRoot, _ := good.inner.state.Root(); afterRoot == emptyRoot {
		t.Fatal("allocate did not change the manifest+alloc state root")
	}
	if err := blk.Accept(ctx); err != nil {
		t.Fatalf("Accept: %v", err)
	}

	// (2) A block with a TAMPERED claimed root over the same allocate tx is
	// rejected with errStateRootMismatch (and its staged write is dropped).
	bad, _ := newTestVM(t)
	withValidatorSet(bad, members, owner)
	tx2 := txs.NewAllocateTx(rng, 4)
	if err := bad.SubmitTx(tx2.Bytes()); err != nil {
		t.Fatalf("SubmitTx: %v", err)
	}
	badBlk, err := bad.BuildBlock(ctx)
	if err != nil {
		t.Fatalf("BuildBlock: %v", err)
	}
	concrete, ok := badBlk.(*Block)
	if !ok {
		t.Fatalf("block type = %T, want *Block", badBlk)
	}
	concrete.stateRoot = ids.ID{0xDE, 0xAD, 0xBE, 0xEF}
	hash := sha256Bytes(concrete.Bytes())
	copy(concrete.id[:], hash[:])

	if err := concrete.Verify(ctx); !errors.Is(err, errStateRootMismatch) {
		t.Fatalf("Verify error = %v, want errStateRootMismatch", err)
	}
	if n, _ := bad.inner.state.GetAlloc(rng); n != 0 {
		t.Fatalf("rejected (bad-root) block leaked an allocation: counter = %d, want 0", n)
	}
}
