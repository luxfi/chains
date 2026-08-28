// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package zkvm

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/stretchr/testify/require"

	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
)

// refusingWrites fails every Put. A store that cannot record what a block
// decides must say so, so the block takes the whole commit with it.
type refusingWrites struct {
	database.Database
	err error
}

func (d *refusingWrites) Put([]byte, []byte) error { return d.err }

func TestValidateBasicRefusals(t *testing.T) {
	proof := &ZKProof{ProofType: "stark", ProofData: []byte("p")}
	out := []*ShieldedOutput{{Commitment: []byte("c")}}
	tin := []*TransparentInput{{TxID: ids.ID{1}, Amount: 1, Address: []byte("a")}}
	tout := []*TransparentOutput{{Amount: 1, Address: []byte("b")}}

	for _, tt := range []struct {
		name string
		tx   *Transaction
		want error
	}{
		{"a type no version of this chain has", &Transaction{Type: TransactionType(9)}, errInvalidTransactionType},
		{"nothing spent", &Transaction{Type: TransactionTypeTransfer}, errNoInputs},
		{"nothing created", &Transaction{
			Type: TransactionTypeTransfer, Nullifiers: [][]byte{{1}},
		}, errNoOutputs},
		{"no proof", &Transaction{
			Type: TransactionTypeTransfer, Nullifiers: [][]byte{{1}}, Outputs: out,
		}, errMissingProof},
		{"no expiry", &Transaction{
			Type: TransactionTypeTransfer, Nullifiers: [][]byte{{1}}, Outputs: out, Proof: proof,
		}, errNoExpiry},
		{"a transfer that transfers nothing shielded", &Transaction{
			Type: TransactionTypeTransfer, TransparentInputs: tin, TransparentOutputs: tout,
			Proof: proof, Expiry: 1,
		}, errInvalidTransferTransaction},
		{"a shield with nothing transparent to shield", &Transaction{
			Type: TransactionTypeShield, Nullifiers: [][]byte{{1}}, Outputs: out,
			Proof: proof, Expiry: 1,
		}, errInvalidShieldTransaction},
		{"an unshield with nothing to unshield into", &Transaction{
			Type: TransactionTypeUnshield, Nullifiers: [][]byte{{1}}, Outputs: out,
			Proof: proof, Expiry: 1,
		}, errInvalidUnshieldTransaction},
	} {
		t.Run(tt.name, func(t *testing.T) {
			require.ErrorIs(t, tt.tx.ValidateBasic(), tt.want)
		})
	}

	// The shapes that do hold.
	for _, tx := range []*Transaction{
		{Type: TransactionTypeTransfer, Nullifiers: [][]byte{{1}}, Outputs: out, Proof: proof, Expiry: 1},
		{Type: TransactionTypeShield, TransparentInputs: tin, Outputs: out, Proof: proof, Expiry: 1},
		{Type: TransactionTypeUnshield, Nullifiers: [][]byte{{1}}, TransparentOutputs: tout, Proof: proof, Expiry: 1},
		{Type: TransactionTypeMint, Nullifiers: [][]byte{{1}}, Outputs: out, Proof: proof, Expiry: 1},
	} {
		require.NoError(t, tx.ValidateBasic())
	}

	tx := &Transaction{Nullifiers: [][]byte{{1}, {2}}}
	require.Equal(t, tx.Nullifiers, tx.GetNullifiers())
	require.Equal(t, [][]byte{[]byte("c")}, (&Transaction{Outputs: out}).GetOutputCommitments())
}

// A block that cannot record its spends records nothing: Write is discarded
// whole, so a spend that cannot be written takes the block with it.
func TestABlockThatCannotWriteSpendsNothing(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	blk := build(t, vm, spendTx(nullifier(1)))
	require.NoError(t, blk.Verify(ctx))

	boom := errors.New("disk gone")
	vm.nullifierDB.db = &refusingWrites{Database: vm.nullifierDB.db, err: boom}
	require.ErrorIs(t, blk.Write(nil), boom)

	// And the same for its outputs, and for the root it commits to.
	vm.nullifierDB.db = memdb.New()
	vm.utxoDB.db = &refusingWrites{Database: vm.utxoDB.db, err: boom}
	require.ErrorIs(t, blk.Write(nil), boom)

	vm.utxoDB.db = memdb.New()
	vm.nullifierDB.spent = map[string]uint64{}
	vm.root.db = &refusingWrites{Database: vm.root.db, err: boom}
	require.ErrorIs(t, blk.Write(nil), boom)
}

func TestAVertexThatCannotWriteSpendsNothing(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	tx := spendTx(nullifier(1))
	acceptProofs(vm, tx)
	require.NoError(t, vm.mempool.AddTransaction(tx))
	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	vtx := built.(*Vertex)

	boom := errors.New("disk gone")
	vm.nullifierDB.db = &refusingWrites{Database: vm.nullifierDB.db, err: boom}
	require.ErrorIs(t, vtx.Write(nil), boom)

	vm.nullifierDB.db = memdb.New()
	vm.nullifierDB.spent = map[string]uint64{}
	vm.utxoDB.db = &refusingWrites{Database: vm.utxoDB.db, err: boom}
	require.ErrorIs(t, vtx.Write(nil), boom)
}

// A vertex batches spends that do not collide, and skips one that does.
func TestVertexBatchesOnlyDisjointSpends(t *testing.T) {
	ctx := context.Background()
	vm := newVM(t)

	shared := nullifier(1)
	first := spendTx(shared, nullifier(2))
	rival := spendTx(shared, nullifier(3))
	other := spendTx(nullifier(4))
	acceptProofs(vm, first, rival, other)

	// Straight into the pool: AddTransaction refuses the second spend of a
	// note, and this is about what ASSEMBLY does when both are present.
	for _, tx := range []*Transaction{first, rival, other} {
		mp := &MempoolTx{tx: tx, fee: tx.Fee}
		vm.mempool.txs[tx.ID] = mp
		vm.mempool.txHeap = append(vm.mempool.txHeap, mp)
	}

	built, err := vm.BuildVertex(ctx)
	require.NoError(t, err)
	require.Len(t, built.(*Vertex).txs, 2, "the colliding spend is left behind, the disjoint one is not")
}

func TestUTXOStoreFailures(t *testing.T) {
	boom := errors.New("disk gone")

	udb, err := NewUTXODB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	udb.db = &refusingWrites{Database: udb.db, err: boom}
	require.ErrorIs(t, udb.AddUTXO(&UTXO{Commitment: []byte("c")}), boom)

	// A read that FAILED is not a UTXO that is absent.
	udb.db = &brokenDB{Database: memdb.New(), err: boom}
	_, err = udb.GetUTXO([]byte("c"))
	require.ErrorIs(t, err, boom)

	// A record that is not a UTXO is a failure, not an empty one.
	db := memdb.New()
	require.NoError(t, db.Put(makeUTXOKey([]byte("c")), []byte("not a frame")))
	udb, err = NewUTXODB(db, log.NoLog{})
	require.NoError(t, err, "an unreadable record is skipped at load")
	require.Zero(t, udb.GetUTXOCount())
	_, err = udb.GetUTXO([]byte("c"))
	require.Error(t, err)

	// A key too short to carry a commitment is not one of ours.
	db = memdb.New()
	require.NoError(t, db.Put([]byte{utxoPrefix}, []byte("x")))
	udb, err = NewUTXODB(db, log.NoLog{})
	require.NoError(t, err)
	require.Zero(t, udb.GetUTXOCount())

	// A set that cannot be read at startup is not an empty set.
	_, err = NewUTXODB(&failIterDB{Database: memdb.New(), err: boom}, log.NoLog{})
	require.ErrorIs(t, err, boom)
}

func TestNullifierStoreCannotWrite(t *testing.T) {
	boom := errors.New("disk gone")
	ndb, err := NewNullifierDB(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	ndb.db = &refusingWrites{Database: ndb.db, err: boom}
	require.ErrorIs(t, ndb.MarkNullifierSpent([]byte("n"), 1), boom)
	require.Zero(t, ndb.GetNullifierCount(), "a spend that was not written is not a spend")
}

// The committed root is read, not guessed. A read that FAILED, or a record
// that is not a root, is a node that does not know where the chain is — and
// the honest answer is to refuse to open, not to start over at the empty root
// and disagree with the network on every block from then on.
func TestRootRefusesWhatItCannotRead(t *testing.T) {
	boom := errors.New("disk gone")

	_, err := NewRoot(&brokenDB{Database: memdb.New(), err: boom}, log.NoLog{})
	require.ErrorIs(t, err, boom)

	db := memdb.New()
	require.NoError(t, db.Put(rootKey, []byte("short")))
	_, err = NewRoot(db, log.NoLog{})
	require.ErrorContains(t, err, "want 32")

	// A root it cannot RECORD is a root it does not hold.
	r, err := NewRoot(memdb.New(), log.NoLog{})
	require.NoError(t, err)
	before := append([]byte(nil), r.Get()...)
	r.db = &refusingWrites{Database: r.db, err: boom}
	require.ErrorIs(t, r.Finalize(make([]byte, 32)), boom)
	require.Equal(t, before, r.Get())

	r.Close()
	require.Nil(t, r.Get())
}

// A pool drains what the chain has passed. Nothing else does, and a pool full
// of transactions no block can carry refuses every honest arrival.
func TestPruneExpired(t *testing.T) {
	mp := NewMempool(10, log.NoLog{})

	live := spendTx(nullifier(1))
	live.Expiry = 100
	live.ID = live.ComputeID()
	stale := spendTx(nullifier(2))
	stale.Expiry = 5
	stale.ID = stale.ComputeID()

	require.NoError(t, mp.AddTransaction(live))
	require.NoError(t, mp.AddTransaction(stale))
	require.Equal(t, 2, mp.Size())

	mp.PruneExpired(3)
	require.Equal(t, 2, mp.Size(), "nothing has expired yet")

	mp.PruneExpired(50)
	require.Equal(t, 1, mp.Size())
	require.True(t, mp.HasTransaction(live.ID))
	require.False(t, mp.HasTransaction(stale.ID))

	// Removing something the pool does not hold is not a removal.
	mp.RemoveTransaction(ids.GenerateTestID())
	require.Equal(t, 1, mp.Size())
}

// A vertex whose transaction count runs past the bytes it was sent is not a
// vertex, at either boundary.
func TestVertexTruncatedAtTheTxCount(t *testing.T) {
	vm := newVM(t)
	u32 := func(v uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, v)
		return b
	}
	head := make([]byte, 8)
	binary.BigEndian.PutUint64(head, 1)
	head = append(head, append(u32(0), u32(0)...)...) // epoch, parentCount

	// Two declared transactions, and one whole transaction after them: the
	// declared count is backed by enough bytes to pass the allocation bound and
	// runs out before the second length prefix.
	body := spendTx(nullifier(1)).Marshal()
	raw := append(append([]byte(nil), head...), u32(2)...)
	raw = append(raw, u32(uint32(len(body)))...)
	raw = append(raw, body...)
	_, err := vm.ParseVertex(context.Background(), raw)
	require.ErrorIs(t, err, errInvalidBlock)
}

// Every point a verifier reads has to be in the prime-order subgroup and must
// not be the point at infinity. gnark encodes infinity as all-zero bytes and
// reports it as in-subgroup, and a pairing DROPS any term whose argument is
// infinity — so an element at infinity removes a factor from the equation the
// proof is supposed to satisfy.
func TestEveryPointIsChecked(t *testing.T) {
	zeroG1 := make([]byte, 64)
	zeroG2 := make([]byte, 128)

	key := groth16Key(2)
	for _, tt := range []struct {
		name string
		at   int
		with []byte
	}{
		{"Beta", 64, zeroG2},
		{"Gamma", 64 + 128, zeroG2},
		{"Delta", 64 + 256, zeroG2},
		{"K[0]", 64 + 384 + 4, zeroG1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			broken := append([]byte(nil), key...)
			copy(broken[tt.at:], tt.with)
			vk, err := deserializeVerifyingKey(broken)
			require.NoError(t, err, "infinity decodes; that is why it must be checked")
			require.ErrorContains(t, validateVerifyingKey(vk), tt.name)
		})
	}

	// The same for the proof's own points.
	frame := groth16Frame()
	for _, tt := range []struct {
		name string
		at   int
		with []byte
	}{
		{"Bs", 64, zeroG2},
		{"Krs", 192, zeroG1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			broken := append([]byte(nil), frame...)
			copy(broken[tt.at:], tt.with)
			_, err := deserializeGroth16Proof(broken)
			require.ErrorContains(t, err, tt.name)
		})
	}

	// And a well-formed point passes both checks.
	_, _, g1, g2 := bn254.Generators()
	require.NoError(t, checkG1(&g1))
	require.NoError(t, checkG2(&g2))

	var infinity bn254.G1Affine
	require.ErrorIs(t, checkG1(&infinity), errAtInfinity)
	var infinity2 bn254.G2Affine
	require.ErrorIs(t, checkG2(&infinity2), errAtInfinity)
}

// A key or a proof that does not decode is not judged; the failure names which
// half of the pair could not be read.
func TestGnarkPathReportsWhatItCouldNotRead(t *testing.T) {
	pv := keyedVerifier(t, map[string][]byte{string(TransactionTypeTransfer): groth16Key(1)})

	proof := &ZKProof{ProofType: "groth16", ProofData: groth16Frame()}

	// A key long enough to decode, with a point that is not on the curve.
	broken := append([]byte(nil), groth16Key(1)...)
	for i := 0; i < 8; i++ {
		broken[i] = 0xFF
	}
	require.ErrorContains(t, pv.verifyGroth16WithGnark(proof, broken), "deserialize verifying key")

	// A proof long enough to decode, with a point that is not on the curve.
	badProof := &ZKProof{ProofType: "groth16", ProofData: append([]byte(nil), groth16Frame()...)}
	for i := 0; i < 8; i++ {
		badProof.ProofData[i] = 0xFF
	}
	require.ErrorContains(t, pv.verifyGroth16WithGnark(badProof, groth16Key(1)), "deserialize proof")
}
