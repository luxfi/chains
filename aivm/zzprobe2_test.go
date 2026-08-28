package aivm

import (
	"context"
	"sync"
	"testing"

	"github.com/holiman/uint256"
	"github.com/luxfi/database"
	"github.com/luxfi/database/memdb"
	"github.com/luxfi/geth/common"
	"github.com/luxfi/ids"
	"github.com/luxfi/log"
	"github.com/luxfi/runtime"
	vmcore "github.com/luxfi/vm"
	"github.com/stretchr/testify/require"
)

// failDB fails every Put after the Nth.
type failDB struct {
	database.Database
	mu   sync.Mutex
	n    int
	fail bool
}

func (d *failDB) Put(k, v []byte) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.fail {
		return errProbeDBDown
	}
	d.n++
	return d.Database.Put(k, v)
}

var errProbeDBDown = &probeErr{"probe: db down"}

type probeErr struct{ s string }

func (e *probeErr) Error() string { return e.s }

// P5: Accept commits engine state, then fails to store the block. Torn?
func TestProbe_P5_AcceptTornWrite(t *testing.T) {
	inner := memdb.New()
	db := &failDB{Database: inner}
	vm := &VM{}
	require.NoError(t, vm.Initialize(context.Background(), probeInit(db)))
	vm.SetCommitVerifier(VerifierFunc(func(CIntent) error { return nil }))
	ctx := context.Background()

	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, _ := vm.QuorumEngine()
	seedOperators(t, vm, e, st, reward)
	intent := buildIntent(e, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), reward)
	vm.EnqueueCommittedIntent(intent)

	blk, err := vm.BuildBlock(ctx)
	require.NoError(t, err)
	require.NoError(t, blk.Verify(ctx))

	db.mu.Lock()
	db.fail = true
	db.mu.Unlock()
	acceptErr := blk.Accept(ctx)
	db.mu.Lock()
	db.fail = false
	db.mu.Unlock()
	t.Logf("Accept with a failing DB = %v", acceptErr)

	raw := NewDBState(inner)
	engineCommitted := isSet(raw.GetState(slotHash(nsIntentSeen, intent.IntentID)))
	head, _ := vm.LastAccepted(ctx)
	blockStored := false
	if _, err := func() ([]byte, error) { id := blk.ID(); return inner.Get(id[:]) }(); err == nil {
		blockStored = true
	}
	t.Logf("engineCommitted=%v blockStored=%v head=%s blkID=%s", engineCommitted, blockStored, head, blk.ID())
	if acceptErr != nil && engineCommitted && !blockStored {
		t.Errorf("P5 CONFIRMED: Accept failed but the engine delta is already durable — the block is gone and its state is not")
	}
}

// P14: verifyImported tolerates ErrIntentAlreadyUsed. Can a proposer record the
// same intent twice, or an intent an earlier block already consumed?
func TestProbe_P14_DuplicateIntentInBlock(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	e, st, _ := vm.QuorumEngine()
	seedOperators(t, vm, e, st, reward)
	intent := buildIntent(e, addrOf(0xF0), hashOf(0xAB), consciousN, consciousThreshold, uint256.NewInt(1), reward)

	// A hand-built block recording the same intent 3 times.
	blk := &Block{ParentID_: vm.lastAcceptedID, Height_: 1,
		ImportedIntents: []CIntent{intent, intent, intent}, vm: vm}
	// The proposer stamps whatever root its own run produced; compute it honestly.
	require.NoError(t, blk.Verify(ctx))
	t.Logf("a block recording the same intent 3x verified (receiptRoot=%s)", blk.ReceiptRoot.Hex())
	n := e.LiveTasks(st)
	if n != 1 {
		t.Errorf("P14: %d tasks created from one intent recorded 3x", n)
	} else {
		t.Logf("P14 benign: duplicate records collapse to 1 task (anti-replay held)")
	}
}

// P15: concurrent reads of vm.running against Shutdown.
func TestProbe_P15_RunningRace(t *testing.T) {
	vm := probeVM(t, memdb.New())
	ctx := context.Background()
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 200; j++ {
				_ = vm.GetProviders()
				_, _ = vm.HealthCheck(ctx)
				_ = vm.GetMerkleRoot()
			}
		}()
	}
	wg.Add(1)
	go func() { defer wg.Done(); _ = vm.Shutdown(ctx) }()
	wg.Wait()
}

// P16: settleDue runs on both build and verify at the same height. Does the
// second pass over already-settled tasks change anything?
func TestProbe_P16_DoubleSettlePass(t *testing.T) {
	e := NewEngine(hashOf(1), hashOf(2))
	st := NewMemState()
	reward := uint256.NewInt(1_000_000_000_000_000_000)
	requester := addrOf(0xF0)
	opening := map[common.Address]*uint256.Int{requester: new(uint256.Int).Mul(reward, uint256.NewInt(64))}
	ops := make([]common.Address, 8)
	for i := range ops {
		ops[i] = addrOf(byte(0x10 + i))
		opening[ops[i]] = new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))
	}
	lg := NewMemLedger(opening)
	for i, op := range ops {
		require.NoError(t, e.RegisterOperator(st, lg, op, new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(2)), hashOf(0xAB), hashOf(byte(0x80+i))))
	}
	in := buildIntent(e, requester, hashOf(0xAB), 5, 3, uint256.NewInt(1), reward)
	taskID, err := e.ImportCommittedIntent(st, lg, VerifierFunc(func(CIntent) error { return nil }), in, 1)
	require.NoError(t, err)
	sel, _ := e.SelectOperators(st, taskID, hashOf(0xAB), 5)
	out := hashOf(0x42)
	for i := 0; i < 3; i++ {
		c := ComputeCommit(taskID, hashOf(0xAB), hashOf(0xCD), out, hashOf(7), sel[i], hashOf(9))
		require.NoError(t, e.CommitResponse(st, taskID, sel[i], c, 2))
		require.NoError(t, e.RevealResponse(st, taskID, sel[i], out, hashOf(7), hashOf(9), 32))
	}
	total := lg.Total()
	n1 := e.SettleDue(st, lg, 62)
	root1 := e.ReceiptRoot(st)
	n2 := e.SettleDue(st, lg, 62)
	root2 := e.ReceiptRoot(st)
	t.Logf("settleDue pass1=%d pass2=%d root1=%s root2=%s", n1, n2, root1.Hex(), root2.Hex())
	require.Equal(t, root1, root2, "P16: a second settleDue at the same height changed the receipt root")
	require.Equal(t, total.String(), lg.Total().String())
}

// P17: WithdrawStake wrong-error probe + re-register after withdraw.
func TestProbe_P17_WithdrawErrors(t *testing.T) {
	e := NewEngine(hashOf(1), hashOf(2))
	st := NewMemState()
	op := addrOf(1)
	lg := NewMemLedger(map[common.Address]*uint256.Int{op: new(uint256.Int).Mul(MinProviderBond, uint256.NewInt(3))})
	require.NoError(t, e.RegisterOperator(st, lg, op, MinProviderBond, hashOf(0xAB), hashOf(1)))
	_, err := e.WithdrawStake(st, lg, op, 100)
	t.Logf("WithdrawStake before Deregister = %v", err)
	if err == ErrOperatorUnbonding {
		t.Errorf("P17 CONFIRMED: refusing a NOT-unbonding operator reports 'operator is unbonding'")
	}
}

func probeInit(db database.Database) vmcore.Init {
	return vmcore.Init{
		Runtime:  &runtime.Runtime{ChainID: ids.GenerateTestID(), NetworkID: 96369, Log: log.NewNoOpLogger()},
		DB:       db,
		ToEngine: make(chan vmcore.Message, 8),
		Log:      log.NewNoOpLogger(),
		Genesis:  []byte(`{"timestamp":0,"version":1,"message":""}`),
	}
}
