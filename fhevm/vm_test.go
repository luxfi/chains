// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/chains/mpcvm/fhe"
	"github.com/luxfi/crypto/mldsa"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	nodefee "github.com/luxfi/node/vms/types/fee"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// ---- shared test helpers ----

// testGas is a gas ceiling above every scheduled operation, so a test that is
// not about metering never trips the limit.
const testGas = uint64(500_000)

// testFund is enough for many operations at the scheduled prices.
const testFund = uint64(10_000_000_000)

// testScheme is the scheme most tests price against.
const testScheme = "ckks-n14"

// testChainID is THE chain id. Production runs ONE F-Chain per network, and
// every validator of it — proposer and follower alike — holds the same id: it
// is what a payer signs over and what a block id commits to. So the harness
// holds it constant too. Giving each node its own would make a proposer and a
// follower two different chains, which is not a shape production ever has, and
// would quietly excuse the very binding these tests exist to check. A test that
// is genuinely ABOUT two chains names its second one itself.
var testChainID = ids.ID{'f', 'c', 'h', 'a', 'i', 'n', '-', 't', 'e', 's', 't'}

// testGenesisTime fixes genesis, for the same reason: every validator of one
// chain reads one genesis, so its id is one value. A wall clock here would give
// two nodes built a second apart two different genesis blocks.
const testGenesisTime = int64(1_700_000_000)

// testKey is an external identity: a payer, a grantee, or a committee member.
// The ML-DSA-65 private key lives ONLY in the test, exercising the public-key
// authentication path on the VM side.
type testKey struct {
	priv *mldsa.PrivateKey
	pub  []byte
	addr fee.Account
}

func newTestKey(t *testing.T) testKey {
	t.Helper()
	priv, err := mldsa.GenerateKey(rand.Reader, mldsa.MLDSA65)
	require.NoError(t, err)
	pub := priv.PublicKey.Bytes()
	return testKey{priv: priv, pub: pub, addr: addressOf(pub)}
}

func (k testKey) hexAddr() string { return hex.EncodeToString(k.addr[:]) }

// sign attaches the payer's public key and a valid signature over the tx's
// signing bytes for THE chain under test, then clears the cached id so ID()
// recomputes.
func (k testKey) sign(t *testing.T, tx *Transaction) *Transaction {
	t.Helper()
	return k.signFor(t, testChainID, tx)
}

// signFor signs for a named chain. Only a test that is about more than one
// chain needs it.
func (k testKey) signFor(t *testing.T, chain ids.ID, tx *Transaction) *Transaction {
	t.Helper()
	tx.Auth = k.pub
	sig, err := k.priv.Sign(rand.Reader, tx.SigningBytes(chain), crypto.Hash(0))
	require.NoError(t, err)
	tx.Sig = sig
	tx.id = ids.Empty
	return tx
}

// newCommittee builds n committee members in canonical node-ID order, each
// carrying a real ML-DSA-65 public key, and returns the members alongside the
// keys that can sign for them (index-aligned).
func newCommittee(t *testing.T, n int) ([]fhe.CommitteeMember, []testKey) {
	t.Helper()
	type pair struct {
		m fhe.CommitteeMember
		k testKey
	}
	pairs := make([]pair, n)
	for i := range pairs {
		k := newTestKey(t)
		pairs[i] = pair{
			m: fhe.CommitteeMember{NodeID: ids.GenerateTestNodeID(), PublicKey: k.pub, Weight: 1},
			k: k,
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].m.NodeID.Compare(pairs[j].m.NodeID) < 0
	})
	members := make([]fhe.CommitteeMember, n)
	keys := make([]testKey, n)
	for i, p := range pairs {
		p.m.Index = i
		members[i] = p.m
		keys[i] = p.k
	}
	return members, keys
}

// newTestVM initializes an in-memory F-Chain seeded with the given funding
// allocation (hex address -> nLUX) and epoch-0 committee.
func newTestVM(t *testing.T, alloc map[string]uint64, committee []fhe.CommitteeMember, threshold int) *VM {
	t.Helper()
	logger := log.NewNoOpLogger()
	g := Genesis{
		Version:   1,
		Timestamp: testGenesisTime,
		Alloc:     alloc,
		Committee: committee,
		Threshold: threshold,
	}
	if len(committee) > 0 {
		g.PublicKey = []byte("network-fhe-public-key")
	}
	gb, err := json.Marshal(g)
	require.NoError(t, err)
	rt := &runtime.Runtime{ChainID: testChainID, NetworkID: 96369, Log: logger}
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  rt,
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  gb,
	}))
	t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	return vm
}

// ---- transaction builders ----

func digestOf(s string) [32]byte { return sha256.Sum256([]byte(s)) }

// hexOf renders a 32-byte identifier the way the RPC surface takes it.
func hexOf(v [32]byte) string { return hex.EncodeToString(v[:]) }

func registerTx(t *testing.T, k testKey, scheme string, digest [32]byte, nonce uint64) *Transaction {
	t.Helper()
	return k.sign(t, &Transaction{
		Type:     TxRegisterCiphertext,
		Scheme:   scheme,
		Payer:    k.addr,
		Subject:  deriveHandle(digest, scheme),
		GasLimit: testGas,
		Nonce:    nonce,
		Payload: mustJSON(t, RegisterPayload{
			Digest: digest, Type: 4, Level: 3, Size: 4096,
		}),
	})
}

func grantTx(t *testing.T, owner testKey, handle [32]byte, grantee fee.Account, ops uint32, expiry int64, nonce uint64) *Transaction {
	t.Helper()
	return owner.sign(t, &Transaction{
		Type:     TxGrantPermit,
		Payer:    owner.addr,
		Subject:  handle,
		GasLimit: testGas,
		Nonce:    nonce,
		Payload:  mustJSON(t, GrantPayload{Grantee: grantee, Operations: ops, Expiry: expiry}),
	})
}

func revokeTx(t *testing.T, k testKey, permitID [32]byte, nonce uint64) *Transaction {
	t.Helper()
	return k.sign(t, &Transaction{
		Type:     TxRevokePermit,
		Payer:    k.addr,
		Subject:  permitID,
		GasLimit: testGas,
		Nonce:    nonce,
		Payload:  mustJSON(t, RevokePayload{Reason: "no longer sanctioned"}),
	})
}

func requestTx(t *testing.T, k testKey, scheme string, handle, permitID [32]byte, expiry int64, nonce uint64) *Transaction {
	t.Helper()
	return k.sign(t, &Transaction{
		Type:     TxRequestDecrypt,
		Scheme:   scheme,
		Payer:    k.addr,
		Subject:  handle,
		GasLimit: testGas,
		Nonce:    nonce,
		Payload: mustJSON(t, RequestPayload{
			PermitID: permitID,
			Callback: [20]byte{0xca, 0x11},
			Selector: [4]byte{1, 2, 3, 4},
			Expiry:   expiry,
		}),
	})
}

func fulfillTx(t *testing.T, k testKey, requestID, result [32]byte, nonce uint64) *Transaction {
	t.Helper()
	return k.sign(t, &Transaction{
		Type:     TxFulfillDecrypt,
		Payer:    k.addr,
		Subject:  requestID,
		GasLimit: testGas,
		Nonce:    nonce,
		Payload:  mustJSON(t, FulfillPayload{Result: result}),
	})
}

func advanceTx(t *testing.T, k testKey, epoch uint64, committee []fhe.CommitteeMember, threshold int, pk []byte, nonce uint64) *Transaction {
	t.Helper()
	return k.sign(t, &Transaction{
		Type:     TxAdvanceEpoch,
		Payer:    k.addr,
		Subject:  committeeDigest(epoch, threshold, pk, committee),
		GasLimit: testGas,
		Nonce:    nonce,
		Payload: mustJSON(t, AdvancePayload{
			Epoch: epoch, Committee: committee, Threshold: threshold, PublicKey: pk,
		}),
	})
}

// acceptOne submits, builds, verifies, and accepts a single-tx block.
func acceptOne(t *testing.T, vm *VM, tx *Transaction) {
	t.Helper()
	_, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	acceptQueued(t, vm)
}

// acceptQueued builds, verifies, and accepts whatever is queued.
func acceptQueued(t *testing.T, vm *VM) *Block {
	t.Helper()
	blkIntf, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := blkIntf.(*Block)
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
	return blk
}

// mustJSON encodes a payload. t may be nil where the caller is not a test body
// (a table built at the top of one), since these values never fail to encode.
func mustJSON(t *testing.T, v any) []byte {
	b, err := json.Marshal(v)
	if t != nil {
		t.Helper()
		require.NoError(t, err)
	}
	return b
}

// timeAt is a fixed block timestamp, so a test that serializes one gets the
// same bytes on every run.
func timeAt(sec int64) time.Time { return time.Unix(sec, 0) }

// ---- VM lifecycle ----

func TestVMInitialize(t *testing.T) {
	committee, _ := newCommittee(t, 3)
	vm := newTestVM(t, nil, committee, 2)

	v, err := vm.Version(context.Background())
	require.NoError(t, err)
	require.Equal(t, Version, v)

	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.True(t, h.Healthy)
	require.Equal(t, "3", h.Details["committee"])
	require.Equal(t, "2", h.Details["threshold"])
	require.Equal(t, "0", h.Details["epoch"])

	ep, ok := vm.Epoch(0)
	require.True(t, ok, "genesis must seat epoch 0")
	require.Len(t, ep.Committee, 3)
	require.Equal(t, uint64(0), vm.CurrentEpoch())
}

// TestVMWithoutCommitteeIsUnhealthy proves a chain with nobody seated reports
// itself degraded rather than healthy: decryptions could be requested but never
// answered.
func TestVMWithoutCommitteeIsUnhealthy(t *testing.T) {
	vm := newTestVM(t, nil, nil, 0)
	h, err := vm.HealthCheck(context.Background())
	require.NoError(t, err)
	require.False(t, h.Healthy)
	require.Equal(t, "0", h.Details["committee"])
}

// TestGenesisRejectsUnusableCommittee proves genesis goes through the same
// committee check as TxAdvanceEpoch, so a chain cannot be born holding a
// committee consensus would refuse to install.
func TestGenesisRejectsUnusableCommittee(t *testing.T) {
	logger := log.NewNoOpLogger()
	bad := []fhe.CommitteeMember{{NodeID: ids.GenerateTestNodeID(), PublicKey: []byte("not-an-mldsa-key")}}
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: time.Now().Unix(),
		Committee: bad, Threshold: 1, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)
	vm := &VM{}
	err = vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: logger},
		DB:       memdb.New(),
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  gb,
	})
	require.ErrorIs(t, err, ErrInvalidCommittee)
}

// TestHeightIndex proves GetBlockIDAtHeight answers from an index written in
// the same commit as the block, and refuses a height the chain never reached.
func TestHeightIndex(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	genesisID, err := vm.GetBlockIDAtHeight(context.Background(), 0)
	require.NoError(t, err)
	require.Equal(t, vm.lastAccepted, genesisID, "height 0 must name the genesis block")

	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("a"), 1))
	id1, err := vm.GetBlockIDAtHeight(context.Background(), 1)
	require.NoError(t, err)
	require.Equal(t, vm.lastAccepted, id1)

	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("b"), 2))
	id2, err := vm.GetBlockIDAtHeight(context.Background(), 2)
	require.NoError(t, err)
	require.Equal(t, vm.lastAccepted, id2)
	require.NotEqual(t, id1, id2)

	// A height the chain never reached is an error, not a zero id.
	_, err = vm.GetBlockIDAtHeight(context.Background(), 99)
	require.Error(t, err)
}

// TestBlockDiscardKeepsTheQueue proves a proposal that never lands costs
// nothing. BuildBlock SELECTS from the mempool rather than draining it, so a
// block that is rejected — or that the engine simply discards, which it may do
// without ever calling Reject — cannot take the queue with it.
func TestBlockDiscardKeepsTheQueue(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("discarded"), 1)
	_, err := vm.SubmitTx(tx)
	require.NoError(t, err)

	blkIntf, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := blkIntf.(*Block)
	require.Len(t, vm.mempool, 1, "building selects, it does not drain")
	require.Len(t, vm.claims, 1)

	require.NoError(t, blk.Reject(context.Background()))
	require.Len(t, vm.mempool, 1, "reject leaves the queue alone")

	_, ok := vm.Ciphertext(tx.Subject)
	require.False(t, ok, "a rejected block must apply nothing")
	burned, _ := vm.Burned()
	require.Zero(t, burned, "a rejected block must burn nothing")

	// The transaction is still good and the next block carries it.
	acceptQueued(t, vm)
	_, ok = vm.Ciphertext(tx.Subject)
	require.True(t, ok)
	require.Empty(t, vm.mempool, "acceptance is the only thing that clears the queue")
	require.Empty(t, vm.claims, "and the only thing that releases a claim")
}

// TestBlockStatus proves a block reports processing until it is accepted.
func TestBlockStatus(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	_, err := vm.SubmitTx(registerTx(t, k, testScheme, digestOf("s"), 1))
	require.NoError(t, err)
	blkIntf, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	blk := blkIntf.(*Block)
	require.Equal(t, uint8(0), blk.Status())
	require.NoError(t, blk.Verify(context.Background()))
	require.NoError(t, blk.Accept(context.Background()))
	require.Equal(t, uint8(1), blk.Status())
}

// TestParseBlockRoundTrip proves an accepted block re-parses from its stored
// bytes with the same id and the same transactions.
func TestParseBlockRoundTrip(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, map[string]uint64{k.hexAddr(): testFund}, committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("rt"), 1)
	acceptOne(t, vm, tx)
	blk := vm.lastBlock

	parsed, err := vm.ParseBlock(context.Background(), blk.Bytes())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), parsed.ID())
	require.Equal(t, blk.Height(), parsed.Height())
	require.Equal(t, blk.ParentID(), parsed.ParentID())

	got, err := vm.GetBlock(context.Background(), blk.ID())
	require.NoError(t, err)
	require.Equal(t, blk.ID(), got.ID())
}

// TestVerifyRefusesABlockThatIsNotOne walks Verify's structural refusals: a
// block claiming to be genesis, one whose parent nobody has, an empty one, and
// one carrying more transactions than may ever be verified. None of these needs
// state, so each is refused before any signature is checked.
func TestVerifyRefusesABlockThatIsNotOne(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("tip"), 1))

	blk := func(mutate func(*Block)) *Block {
		b := &Block{
			parentID: vm.lastAccepted, height: vm.height + 1, timestamp: vm.clock.Time(),
			transactions: []*Transaction{registerTx(t, k, testScheme, digestOf("payload"), 2)},
			vm:           vm,
		}
		mutate(b)
		b.id = b.computeID()
		return b
	}

	require.ErrorIs(t, blk(func(b *Block) { b.height = 0 }).Verify(context.Background()), ErrInvalidBlock,
		"genesis is not a proposed block")
	require.Error(t, blk(func(b *Block) { b.parentID = ids.ID{0xaa} }).Verify(context.Background()),
		"a parent nobody has")
	require.ErrorIs(t, blk(func(b *Block) { b.transactions = nil }).Verify(context.Background()), ErrInvalidBlock,
		"an empty block buys block space for nothing")

	crowd := blk(func(b *Block) {
		tiny := &Transaction{Type: TxRevokePermit, Nonce: 1, Payload: mustJSON(t, RevokePayload{})}
		b.transactions = make([]*Transaction, MaxBlockTxs+1)
		for i := range b.transactions {
			b.transactions[i] = tiny
		}
	})
	require.ErrorIs(t, crowd.Verify(context.Background()), ErrInvalidBlock)

	// The control: without the mutation it verifies.
	require.NoError(t, blk(func(*Block) {}).Verify(context.Background()))
}

// TestBlockAccessorsReportItsHeader proves the header a block answers with is
// the header it was built from — including an id computed on demand when it was
// never stamped.
func TestBlockAccessorsReportItsHeader(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("hdr"), 1))
	blk := vm.lastBlock

	require.Equal(t, blk.parentID, blk.Parent())
	require.Equal(t, blk.parentID, blk.ParentID())
	require.Equal(t, blk.height, blk.Height())
	require.Equal(t, blk.timestamp, blk.Timestamp())

	unstamped := &Block{parentID: blk.parentID, height: blk.height, timestamp: blk.timestamp,
		transactions: blk.transactions, vm: vm}
	require.Equal(t, blk.ID(), unstamped.ID(), "an unstamped block names itself the same way")

	// An accepted block reports accepted even when it is no longer the tip,
	// because the store holds it.
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("hdr2"), 2))
	require.NotEqual(t, blk.id, vm.lastAccepted)
	require.Equal(t, uint8(1), blk.Status())
}

// TestLifecycleCallsAreAnswered covers the consensus surface F implements
// without holding anything: the engine's state and preference notifications,
// peer connect and disconnect, the work latch, and the plumbing a plugin binary
// reaches for. They are no-ops, and a no-op that panics is not one.
func TestLifecycleCallsAreAnswered(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	ctx := context.Background()

	require.NoError(t, vm.SetState(ctx, 1))
	require.NoError(t, vm.SetPreference(ctx, vm.lastAccepted))
	require.NoError(t, vm.Connected(ctx, ids.GenerateTestNodeID(), nil))
	require.NoError(t, vm.Disconnected(ctx, ids.GenerateTestNodeID()))

	static, err := vm.CreateStaticHandlers(ctx)
	require.NoError(t, err)
	require.Nil(t, static, "F serves nothing that does not belong to a chain")

	h, err := vm.NewHTTPHandler(ctx)
	require.NoError(t, err)
	require.NotNil(t, h)

	require.Equal(t, nodefee.MinTxFeeFloor, vm.FeePolicy().(nodefee.FlatPolicy).Fee)

	// A factory-built VM holds nothing until Initialize.
	raw, err := (&Factory{}).New(log.NewNoOpLogger())
	require.NoError(t, err)
	require.NotNil(t, raw.(*VM))

	// The work latch wakes when a transaction arrives, and stops when the caller
	// does.
	_, err = vm.SubmitTx(registerTx(t, k, testScheme, digestOf("wake"), 1))
	require.NoError(t, err)
	_, err = vm.WaitForEvent(ctx)
	require.NoError(t, err)

	cancelled, stop := context.WithCancel(ctx)
	stop()
	_, err = vm.WaitForEvent(cancelled)
	require.Error(t, err)

	// Releasing nothing does nothing.
	vm.stateLock.Lock()
	vm.release(nil)
	vm.stateLock.Unlock()
	require.Len(t, vm.mempool, 1)
}

// TestMempoolIsBounded proves admission stops at MaxMempool. Admission is open
// to anyone who can pay, so without the bound the queue is whatever an
// adversary chooses to make it.
func TestMempoolIsBounded(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	vm.mempoolLock.Lock()
	vm.mempool = make([]*Transaction, MaxMempool)
	vm.mempoolLock.Unlock()

	_, err := vm.SubmitTx(registerTx(t, k, testScheme, digestOf("overflow"), 1))
	require.ErrorIs(t, err, ErrMempoolFull)
}

// TestTheInFlightSetTracksOnlyWhatIsStillInFlight drives trackVerified's
// contract directly, because after the tip check nothing can reach it with a
// decided block — and a rule enforced only by its callers is one no test can
// show still works.
func TestTheInFlightSetTracksOnlyWhatIsStillInFlight(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("a"), 1))
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("b"), 2))
	require.Equal(t, uint64(2), vm.height)

	vm.stateLock.Lock()
	defer vm.stateLock.Unlock()

	// A block at or below the accepted height is decided or orphaned. Tracking
	// one would make it resolvable as a parent, which is how an orphan gets
	// built on.
	for _, h := range []uint64{1, 2} {
		decided := &Block{parentID: vm.lastAccepted, height: h, timestamp: vm.clock.Time(), vm: vm}
		decided.id = decided.computeID()
		vm.trackVerified(decided)
		require.NotContains(t, vm.pendingBlocks, decided.id, "a decided height is not in flight")
	}

	// One above it is tracked...
	live := &Block{parentID: vm.lastAccepted, height: 3, timestamp: vm.clock.Time(), vm: vm}
	live.id = live.computeID()
	vm.trackVerified(live)
	require.Contains(t, vm.pendingBlocks, live.id)

	// ...and dropped once the chain passes it, because nothing else will: the
	// engine may drop a block it never accepts and never rejects.
	vm.height = 3
	later := &Block{parentID: live.id, height: 4, timestamp: vm.clock.Time(), vm: vm}
	later.id = later.computeID()
	vm.trackVerified(later)
	require.NotContains(t, vm.pendingBlocks, live.id, "the set is pruned, not merely appended to")
	require.Contains(t, vm.pendingBlocks, later.id)
}

// TestInitializeFallsBackToALogger proves a VM started without a runtime logger
// still runs — with the one it was handed, or with none — rather than failing
// on the first line it writes.
func TestInitializeFallsBackToALogger(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: testGenesisTime, Committee: committee,
		Threshold: 1, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)

	for name, given := range map[string]log.Logger{
		"the one it was handed": log.NewNoOpLogger(),
		"none at all":           nil,
	} {
		t.Run(name, func(t *testing.T) {
			vm := &VM{}
			require.NoError(t, vm.Initialize(context.Background(), vmcore.Init{
				Runtime:  &runtime.Runtime{ChainID: testChainID, NetworkID: 96369},
				DB:       memdb.New(),
				ToEngine: make(chan vmcore.Message, 8),
				Log:      given,
				Genesis:  gb,
			}))
			require.NotNil(t, vm.log)
			t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
		})
	}
}
