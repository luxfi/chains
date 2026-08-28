// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package fhevm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/luxfi/chains/fee"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
)

// A chain's database can fail to answer, and what F does then is a consensus
// question rather than an operational one. The failure that matters most is the
// quiet one: a read that FAILED reported as a read that found NOTHING. The
// last-accepted pointer coming back empty made a chain at height 2 look like a
// chain that had never run, and the node went on to build height 1 over it —
// durably, over the height index, with Initialize returning nil and nothing in
// any log to say so. The same conflation on the epoch pointer seats a committee
// nobody elected, and on a nonce it reopens the replay window a nonce exists to
// close.
//
// So these tests fail the database deliberately and require F to stop. Each one
// carries its own control — the SAME read, absent rather than failing — because
// a test that only sees the failure cannot tell "refuses everything" from
// "distinguishes the two".

var errDisk = errors.New("test: the disk did not answer")

// faults is a database that fails one chosen operation and passes the rest
// through. Read failures are selected by key prefix; a write failure applies to
// the batch a versiondb Commit writes through.
type faults struct {
	database.Database
	readFails  []byte // reads of keys under this prefix fail; nil disables
	putFails   []byte // writes of keys under this prefix fail; nil disables
	writeFails bool   // the commit batch fails
	iterFails  []byte // iterators over this prefix report an error
}

func (f *faults) hit(key, prefix []byte) bool {
	return prefix != nil && bytes.HasPrefix(key, prefix)
}

func (f *faults) Get(key []byte) ([]byte, error) {
	if f.hit(key, f.readFails) {
		return nil, errDisk
	}
	return f.Database.Get(key)
}

func (f *faults) Has(key []byte) (bool, error) {
	if f.hit(key, f.readFails) {
		return false, errDisk
	}
	return f.Database.Has(key)
}

func (f *faults) Put(key, value []byte) error {
	if f.hit(key, f.putFails) {
		return errDisk
	}
	return f.Database.Put(key, value)
}

// NewBatch is called ONCE, when versiondb is constructed, and the batch it
// returns is reused for every commit — so the batch consults the switch each
// time it is written rather than copying it here.
func (f *faults) NewBatch() database.Batch {
	return &faultBatch{Batch: f.Database.NewBatch(), on: f}
}

// NewIteratorWithStartAndPrefix is the one versiondb calls; the other three
// iterator constructors funnel into it.
func (f *faults) NewIteratorWithStartAndPrefix(start, prefix []byte) database.Iterator {
	it := f.Database.NewIteratorWithStartAndPrefix(start, prefix)
	if f.iterFails != nil && bytes.HasPrefix(prefix, f.iterFails) {
		return &faultIterator{Iterator: it}
	}
	return it
}

func (f *faults) NewIteratorWithPrefix(prefix []byte) database.Iterator {
	return f.NewIteratorWithStartAndPrefix(nil, prefix)
}

type faultBatch struct {
	database.Batch
	on *faults
}

func (b *faultBatch) Write() error {
	if b.on.writeFails {
		return errDisk
	}
	return b.Batch.Write()
}

// faultIterator yields nothing and reports why, which is how a corrupt store
// presents itself: not as an empty one.
type faultIterator struct{ database.Iterator }

func (i *faultIterator) Next() bool   { return false }
func (i *faultIterator) Error() error { return errDisk }

// bootOn initializes a VM over the given database, returning the error rather
// than requiring success — these tests are about the failures.
func bootOn(t *testing.T, db database.Database, genesis []byte) (*VM, error) {
	t.Helper()
	logger := log.NewNoOpLogger()
	vm := &VM{}
	err := vm.Initialize(context.Background(), vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: testChainID, NetworkID: 96369, Log: logger},
		DB:       db,
		ToEngine: make(chan vmcore.Message, 8),
		Log:      logger,
		Genesis:  genesis,
	})
	if err == nil {
		t.Cleanup(func() { _ = vm.Shutdown(context.Background()) })
	}
	return vm, err
}

// C3: a read that fails is not a read that found nothing. Initialize returned
// nil over a live chain because the last-accepted pointer's error was
// indistinguishable from its absence, leaving the tip at genesis and the height
// at zero — from which the node builds height 1 over a chain already past it.
func TestC3_ABootReadThatFailsIsNotAFreshChain(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: testGenesisTime,
		Alloc: fundAll(k), Committee: committee, Threshold: 1,
		PublicKey: []byte("network-fhe-public-key"),
	})
	require.NoError(t, err)

	// A chain that has actually run.
	store := memdb.New()
	vm, err := bootOn(t, store, gb)
	require.NoError(t, err)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("live-1"), 1))
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("live-2"), 2))
	liveTip, liveHeight := vm.lastAccepted, vm.height
	require.Equal(t, uint64(2), liveHeight)

	// THE CONTROL: rebooting on the same store finds the chain where it left it.
	// Without this the tests below would pass just as well against a VM that
	// refused every boot.
	back, err := bootOn(t, store, gb)
	require.NoError(t, err)
	require.Equal(t, liveHeight, back.height)
	require.Equal(t, liveTip, back.lastAccepted)

	// Each pointer, unreadable in turn: the boot fails rather than inventing an
	// answer. A node that cannot read its own tip must not serve as one.
	for _, key := range [][]byte{lastAcceptedKey, currentEpochKey} {
		_, err := bootOn(t, &faults{Database: store, readFails: key}, gb)
		require.ErrorIs(t, err, errDisk, "an unreadable %q must stop the boot", key)
	}

	// A corrupt record index likewise stops the boot rather than presenting as
	// an empty one — for each of the four record kinds, so none can be the one
	// that silently loads nothing.
	for _, prefix := range []string{CiphertextPrefix, PermitPrefix, DecryptPrefix, EpochPrefix} {
		_, err := bootOn(t, &faults{Database: store, iterFails: []byte(prefix)}, gb)
		require.ErrorIsf(t, err, errDisk, "an unreadable %q index must stop the boot", prefix)
	}

	// And a nonce that cannot be read is an error, not a zero. A zero here says
	// "this payer has spent nothing", which lets every transaction it ever
	// signed through again.
	nonced, err := bootOn(t, store, gb)
	require.NoError(t, err)
	n, err := nonced.nonceOf(k.addr)
	require.NoError(t, err)
	require.Equal(t, uint64(2), n, "the control: the nonce is readable and correct")

	nonced.state = &faults{Database: store, readFails: noncePrefix}
	_, err = nonced.nonceOf(k.addr)
	require.ErrorIs(t, err, errDisk, "an unreadable nonce is an error, never a fresh account")

	// It reaches the paths that decide, too: admission and application both
	// refuse rather than treating the payer as new.
	_, err = nonced.SubmitTx(registerTx(t, k, testScheme, digestOf("replayed"), 1))
	require.ErrorIs(t, err, errDisk)
}

// A boot whose genesis marker cannot be read must stop before it decides
// whether to seed: seeding twice writes genesis over a live tip.
func TestSeedGenesisStopsWhenItCannotTellWhetherItRan(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: testGenesisTime, Committee: committee,
		Threshold: 1, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)
	_, err = bootOn(t, &faults{Database: memdb.New(), readFails: genesisMarker}, gb)
	require.ErrorIs(t, err, errDisk)
}

// TestAcceptRollsBackWhenTheCommitFails proves the whole block is rolled back
// when the one commit fails: no operation applied, no fee burned, no nonce
// consumed, and the caches reloaded from the store that never changed.
func TestAcceptRollsBackWhenTheCommitFails(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: testGenesisTime, Alloc: fundAll(k),
		Committee: committee, Threshold: 1, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)

	store := memdb.New()
	broken := &faults{Database: store}
	vm, err := bootOn(t, broken, gb)
	require.NoError(t, err)

	tx := registerTx(t, k, testScheme, digestOf("uncommittable"), 1)
	_, err = vm.SubmitTx(tx)
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)
	require.NoError(t, blk.(*Block).Verify(context.Background()))

	broken.writeFails = true
	require.ErrorIs(t, blk.(*Block).Accept(context.Background()), errDisk)

	_, ok := vm.Ciphertext(tx.Subject)
	require.False(t, ok, "an uncommitted block applied nothing")
	burned, err := vm.Burned()
	require.NoError(t, err)
	require.Zero(t, burned, "and burned nothing")
	bal, err := vm.Balance(k.addr)
	require.NoError(t, err)
	require.Equal(t, testFund, bal)
	require.Zero(t, vm.height)
	nonce, err := vm.nonceOf(k.addr)
	require.NoError(t, err)
	require.Zero(t, nonce, "nor consumed the nonce")

	// The failure was transient: with the disk answering again the same block
	// applies, so a rollback leaves the chain able to continue rather than stuck.
	broken.writeFails = false
	require.NoError(t, blk.(*Block).Accept(context.Background()))
	_, ok = vm.Ciphertext(tx.Subject)
	require.True(t, ok)
}

// TestAcceptStopsWhenTheStateCannotBeRead proves settleAndApply reports a read
// failure rather than proceeding on the answer it would have invented — here
// the payer's committed nonce, whose absence and whose failure mean opposite
// things.
func TestAcceptStopsWhenTheStateCannotBeRead(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("unreadable"), 1)
	_, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)

	underlying := vm.state
	vm.state = &faults{Database: underlying, readFails: noncePrefix}
	require.ErrorIs(t, blk.(*Block).Accept(context.Background()), errDisk)

	vm.state = underlying
	_, ok := vm.Ciphertext(tx.Subject)
	require.False(t, ok, "a block that could not be settled applied nothing")
}

// TestAWriteThatFailsIsReported proves every record writer reports a failed
// write instead of returning success and leaving the cache holding a record the
// store does not have. A closed database is the real shape of this: a block
// applying while the VM shuts down.
func TestAWriteThatFailsIsReported(t *testing.T) {
	owner := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(owner), committee, 1)
	require.NoError(t, vm.versdb.Close())

	handle := deriveHandle(digestOf("w"), testScheme)
	for name, write := range map[string]func() error{
		"ciphertext": func() error { return vm.putCiphertext(&CiphertextRecord{}) },
		"permit":     func() error { return vm.putPermit(&PermitRecord{}) },
		"decrypt":    func() error { return vm.putDecrypt(&DecryptRecord{}) },
		"epoch":      func() error { return vm.putEpoch(&EpochRecord{}) },
		"currentEpoch": func() error {
			return vm.setCurrentEpoch(7)
		},
		"nonce":  func() error { return vm.setNonce(owner.addr, 1) },
		"record": func() error { return writeRecord(vm, CiphertextPrefix, handle, &CiphertextRecord{}) },
	} {
		t.Run(name, func(t *testing.T) {
			require.ErrorIs(t, write(), database.ErrClosed)
		})
	}
}

// TestGenesisRefusesAnAllocationItCannotApply proves the funding table is held
// to the same address format everything else is, rather than seeding a chain
// that is short by however much the bad row was worth.
func TestGenesisRefusesAnAllocationItCannotApply(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	for name, addr := range map[string]string{
		"not hex":   "zzzz",
		"too short": "0011223344",
		"too long":  "00112233445566778899aabbccddeeff0011223344556677",
	} {
		t.Run(name, func(t *testing.T) {
			gb, err := json.Marshal(Genesis{
				Version: 1, Timestamp: testGenesisTime,
				Alloc:     map[string]uint64{addr: 1},
				Committee: committee, Threshold: 1, PublicKey: []byte("pk"),
			})
			require.NoError(t, err)
			_, err = bootOn(t, memdb.New(), gb)
			require.Error(t, err)
		})
	}
}

// TestInitializeRefusesWhatItCannotParse proves a malformed chain config or
// genesis stops the boot rather than starting a chain on defaults nobody chose.
func TestInitializeRefusesWhatItCannotParse(t *testing.T) {
	logger := log.NewNoOpLogger()
	boot := func(cfg, gen []byte, chain ids.ID) error {
		vm := &VM{}
		return vm.Initialize(context.Background(), vmcore.Init{
			Runtime:  &runtime.Runtime{ChainID: chain, NetworkID: 96369, Log: logger},
			DB:       memdb.New(),
			ToEngine: make(chan vmcore.Message, 8),
			Log:      logger,
			Config:   cfg,
			Genesis:  gen,
		})
	}
	require.Error(t, boot([]byte("{not json"), nil, testChainID), "a config that does not parse")
	require.Error(t, boot(nil, []byte("{not json"), testChainID), "a genesis that does not parse")

	// A chain with no identity binds nothing: every signature it accepts and
	// every block id it computes would be shared with every other chain that
	// also had none.
	require.ErrorIs(t, boot(nil, nil, ids.Empty), ErrInvalidBlock)

	// The control: the same call with all three supplied works.
	require.NoError(t, boot([]byte(`{"networkId":96369}`), nil, testChainID))
}

// TestLoadSkipsARecordItCannotDecode proves one unreadable row does not stop a
// node booting — the rest of the chain's records still load. This is the other
// side of the boot rules above: an index that ERRORS is fatal, a single record
// that does not decode is skipped and logged, because the first says nothing
// can be trusted and the second says one row cannot.
func TestLoadSkipsARecordItCannotDecode(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("good"), 1))
	good := deriveHandle(digestOf("good"), testScheme)

	var junk [32]byte
	junk[0] = 0xff
	require.NoError(t, vm.state.Put(append([]byte(CiphertextPrefix), junk[:]...), []byte("{not json")))
	require.NoError(t, vm.loadState())

	_, ok := vm.Ciphertext(good)
	require.True(t, ok, "a readable record still loads")
	_, ok = vm.Ciphertext(junk)
	require.False(t, ok, "an undecodable one is skipped, not guessed at")
}

// TestBootFailsWhenTheTipNamesNoBlock proves a last-accepted pointer to a block
// the store does not hold stops the boot. Continuing would put the chain at
// genesis while its pointer says otherwise.
func TestBootFailsWhenTheTipNamesNoBlock(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: testGenesisTime, Alloc: fundAll(k),
		Committee: committee, Threshold: 1, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)

	store := memdb.New()
	vm, err := bootOn(t, store, gb)
	require.NoError(t, err)
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("t"), 1))

	// Point the tip at a block nobody wrote.
	missing := ids.ID{0xde, 0xad}
	require.NoError(t, store.Put(lastAcceptedKey, missing[:]))
	_, err = bootOn(t, store, gb)
	require.Error(t, err)

	// A pointer of the wrong width is refused for the same reason.
	require.NoError(t, store.Put(lastAcceptedKey, []byte{1, 2, 3}))
	_, err = bootOn(t, store, gb)
	require.ErrorIs(t, err, ErrInvalidPayload)
}

// TestAcceptIsAllOrNothingAtEveryWrite walks each write Accept makes and fails
// exactly that one. A block is settled and applied through a versiondb that is
// committed ONCE, so any of these failing must leave the chain where it was —
// not half-applied, and not applied-but-unindexed.
func TestAcceptIsAllOrNothingAtEveryWrite(t *testing.T) {
	for name, prefix := range map[string][]byte{
		"the block itself":          []byte(BlockPrefix),
		"the height index":          heightPrefix,
		"the last-accepted pointer": lastAcceptedKey,
		"the payer's nonce":         noncePrefix,
		"the record it applies":     []byte(CiphertextPrefix),
	} {
		t.Run(name, func(t *testing.T) {
			k := newTestKey(t)
			committee, _ := newCommittee(t, 1)
			vm := newTestVM(t, fundAll(k), committee, 1)

			tx := registerTx(t, k, testScheme, digestOf("atomic"), 1)
			_, err := vm.SubmitTx(tx)
			require.NoError(t, err)
			blk, err := vm.BuildBlock(context.Background())
			require.NoError(t, err)
			require.NoError(t, blk.(*Block).Verify(context.Background()))

			sound := vm.state
			vm.state = &faults{Database: sound, putFails: prefix}
			require.ErrorIs(t, blk.(*Block).Accept(context.Background()), errDisk)
			vm.state = sound

			require.Zero(t, vm.height, "the chain did not move")
			_, ok := vm.Ciphertext(tx.Subject)
			require.False(t, ok, "and applied nothing")
			burned, err := vm.Burned()
			require.NoError(t, err)
			require.Zero(t, burned, "and burned nothing")

			// The control: with the disk sound the same block applies.
			require.NoError(t, blk.(*Block).Accept(context.Background()))
			require.Equal(t, uint64(1), vm.height)
		})
	}
}

// TestAbortSurvivesADatabaseThatCannotBeReloaded proves a rollback whose cache
// reload ALSO fails still returns the original failure, rather than panicking
// or reporting the second problem in place of the first.
func TestAbortSurvivesADatabaseThatCannotBeReloaded(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)

	tx := registerTx(t, k, testScheme, digestOf("doomed"), 1)
	_, err := vm.SubmitTx(tx)
	require.NoError(t, err)
	blk, err := vm.BuildBlock(context.Background())
	require.NoError(t, err)

	sound := vm.state
	vm.state = &faults{Database: sound, putFails: []byte(BlockPrefix), readFails: currentEpochKey}
	require.ErrorIs(t, blk.(*Block).Accept(context.Background()), errDisk,
		"the write failure is what the caller is told about")
	vm.state = sound
	require.Zero(t, vm.height)
}

// TestSettlementReportsWhatNoValidatorCanProceedPast walks the failures that
// abort a whole block rather than reverting one transaction. Each is reached by
// accepting a block WITHOUT verifying it first — which is exactly the case
// these checks exist for, since a peer's block reaches Accept only after Verify
// passed, and a check that only ever runs behind another is not a check.
func TestSettlementReportsWhatNoValidatorCanProceedPast(t *testing.T) {
	committee, _ := newCommittee(t, 1)

	t.Run("an unpriceable operation", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, fundAll(k), committee, 1)
		tx := k.sign(t, &Transaction{Type: 99, Payer: k.addr, GasLimit: testGas, Nonce: 1})
		require.Error(t, forceBlock(vm, tx).Accept(context.Background()))
	})

	t.Run("gas beyond the payer's own limit", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, fundAll(k), committee, 1)
		tx := registerTx(t, k, testScheme, digestOf("starved"), 1)
		tx.GasLimit = 1
		k.sign(t, tx)
		require.ErrorIs(t, forceBlock(vm, tx).Accept(context.Background()), fee.ErrOutOfGas)
	})

	t.Run("a fee the payer cannot pay", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1}, committee, 1)
		tx := registerTx(t, k, testScheme, digestOf("broke"), 1)
		require.ErrorIs(t, forceBlock(vm, tx).Accept(context.Background()), fee.ErrInsufficientFunds)
	})

	t.Run("a nonce Verify would have caught", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, fundAll(k), committee, 1)
		require.ErrorIs(t,
			forceBlock(vm, registerTx(t, k, testScheme, digestOf("gap"), 7)).Accept(context.Background()),
			ErrBadNonce)
	})
}

// TestAdmissionReportsWhatItCannotDecide covers batch.admit's own refusals over
// a peer's block: the shape checks it makes before it reads any state, and the
// state reads that can themselves fail.
func TestAdmissionReportsWhatItCannotDecide(t *testing.T) {
	committee, _ := newCommittee(t, 1)

	t.Run("malformed", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, fundAll(k), committee, 1)
		tx := k.sign(t, &Transaction{Type: 99, Payer: k.addr, GasLimit: testGas, Nonce: 1})
		require.ErrorIs(t, forceBlock(vm, tx).Verify(context.Background()), ErrInvalidTxType)
	})

	t.Run("gas over the declared limit", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, fundAll(k), committee, 1)
		tx := registerTx(t, k, testScheme, digestOf("overgas"), 1)
		tx.GasLimit = 1
		k.sign(t, tx)
		require.ErrorIs(t, forceBlock(vm, tx).Verify(context.Background()), fee.ErrOutOfGas)
	})

	t.Run("unaffordable", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, map[string]uint64{k.hexAddr(): 1}, committee, 1)
		tx := registerTx(t, k, testScheme, digestOf("poor"), 1)
		require.ErrorIs(t, forceBlock(vm, tx).Verify(context.Background()), fee.ErrInsufficientFunds)
	})

	t.Run("a nonce that cannot be read", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, fundAll(k), committee, 1)
		blk := forceBlock(vm, registerTx(t, k, testScheme, digestOf("unreadable"), 1))
		sound := vm.state
		vm.state = &faults{Database: sound, readFails: noncePrefix}
		require.ErrorIs(t, blk.Verify(context.Background()), errDisk)
		vm.state = sound
	})

	t.Run("a balance that cannot be read", func(t *testing.T) {
		k := newTestKey(t)
		vm := newTestVM(t, fundAll(k), committee, 1)
		blk := forceBlock(vm, registerTx(t, k, testScheme, digestOf("unbalanced"), 1))
		sound := vm.state
		vm.state = &faults{Database: sound, readFails: []byte("fee/")}
		vm.ledger = fee.NewLedger(vm.state)
		require.ErrorIs(t, blk.Verify(context.Background()), errDisk)
		vm.state, vm.ledger = sound, fee.NewLedger(sound)
	})
}

// TestSeedGenesisReportsAWriteItCannotMake proves the seeder stops on a failed
// write rather than committing a partly-seeded chain — one with an allocation
// but no committee, or a committee but no height index.
func TestSeedGenesisReportsAWriteItCannotMake(t *testing.T) {
	committee, _ := newCommittee(t, 1)
	g := &Genesis{
		Version: 1, Timestamp: testGenesisTime, Committee: committee,
		Threshold: 1, PublicKey: []byte("pk"),
	}
	for name, prefix := range map[string][]byte{
		"the epoch record":  []byte(EpochPrefix),
		"the epoch pointer": currentEpochKey,
		"the height index":  heightPrefix,
	} {
		t.Run(name, func(t *testing.T) {
			vm := newTestVM(t, nil, committee, 1)
			// Clear the marker so the seeder runs again: what is under test is the
			// seeding, not the once-only guard that has its own test.
			require.NoError(t, vm.versdb.Delete(genesisMarker))
			sound := vm.state
			vm.state = &faults{Database: sound, putFails: prefix}
			require.ErrorIs(t, vm.seedGenesis(g, ids.ID{1}), errDisk)
			vm.state = sound
		})
	}
}

// TestGenesisRefusesAnAllocationItCannotCredit proves the funding table is
// applied or refused whole. Two spellings of one address are one account, so a
// table can ask for more than an account can hold.
func TestGenesisRefusesAnAllocationItCannotCredit(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	gb, err := json.Marshal(Genesis{
		Version: 1, Timestamp: testGenesisTime,
		Alloc: map[string]uint64{
			k.hexAddr():        ^uint64(0),
			"0x" + k.hexAddr(): 1, // the same account, spelled the other way
		},
		Committee: committee, Threshold: 1, PublicKey: []byte("pk"),
	})
	require.NoError(t, err)
	_, err = bootOn(t, memdb.New(), gb)
	require.Error(t, err, "a balance that cannot be credited is not a balance that was")
}

// TestBalanceReportsASupplyItCannotRead proves the two numbers a balance reply
// carries are read independently, and a failure on either is reported. Burned
// supply coming back zero on a failed read is indistinguishable from a chain
// that has never settled a fee.
func TestBalanceReportsASupplyItCannotRead(t *testing.T) {
	k := newTestKey(t)
	committee, _ := newCommittee(t, 1)
	vm := newTestVM(t, fundAll(k), committee, 1)
	svc := &Service{vm: vm}
	acceptOne(t, vm, registerTx(t, k, testScheme, digestOf("burned"), 1))

	sound := vm.state
	// The account's own balance still reads; only the supply counter does not.
	vm.state = &faults{Database: sound, readFails: []byte("fee/burned")}
	vm.ledger = fee.NewLedger(vm.state)
	require.ErrorIs(t, svc.Balance(nil, &BalanceArgs{Address: k.hexAddr()}, &BalanceReply{}), errDisk)
	vm.state, vm.ledger = sound, fee.NewLedger(sound)

	var reply BalanceReply
	require.NoError(t, svc.Balance(nil, &BalanceArgs{Address: k.hexAddr()}, &reply))
	require.Positive(t, reply.BurnedNLUX, "the control: the supply reads")
}

// TestEpochRotationIsBothWritesOrNeither proves the rotation reports a failure
// on the epoch it OPENS as readily as on the one it closes. A rotation that
// closed the sitting committee and failed to seat its successor would leave the
// chain with nobody able to answer a decryption or to rotate again.
func TestEpochRotationIsBothWritesOrNeither(t *testing.T) {
	vm, _, members := newDecryptVM(t, 3, 1) // one vote decides
	next, _ := newCommittee(t, 3)

	sound := vm.state
	vm.state = &faults{Database: sound, putFails: append([]byte(EpochPrefix), encodeU64(1)...)}
	err := advanceTx(t, members[0], 1, next, 2, []byte("pk"), 1).applyAdvance(vm, vm.clock.Time().Unix())
	vm.state = sound
	require.ErrorIs(t, err, errDisk, "the successor could not be seated, so the rotation failed")
	require.Equal(t, uint64(0), vm.epoch, "and the sitting epoch is still the sitting epoch")
}
