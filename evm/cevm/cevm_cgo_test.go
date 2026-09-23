//go:build cgo && lux_cevm_native

package cevm

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/luxfi/crypto"
	"github.com/luxfi/geth/core/types"
)

// Tests in this file require the C++ EVM library (CGO_ENABLED=1
// -tags=lux_cevm_native) and hold it to go_bridge.h, ABI 7: a batch of plain
// transfers from funded senders runs on a GPU lane that has its device, to
// TxOK at 21000 gas each. Everything else is declined — a batch with code or
// calldata on any lane, and every batch on a CPU lane — as ErrDeclined and no
// result, and the caller runs it on its own EVM.
//
// A GPU lane is listed when the library was built with it, whether or not
// this host has the device, and without one it declines every block. A test
// that needs a device skips a lane whose device this host does not have
// (hasDevice), and on a lane whose device it has, a decline fails: a missing
// shader or a device-path regression declines too, and must not pass for an
// absent device.

func TestLibraryABIVersion(t *testing.T) {
	if got := LibraryABIVersion(); got != ABIVersion {
		t.Errorf("LibraryABIVersion() = %d, want %d (rebuild libevm-gpu)", got, ABIVersion)
	}
}

// TestABIVersion holds the constant to the ABI this binding is written to. A
// new ABI is read against this file before the number moves.
func TestABIVersion(t *testing.T) {
	const want uint32 = 7
	if ABIVersion != want {
		t.Errorf("ABIVersion = %d, want %d (update C-side EVM_GPU_ABI_VERSION in lockstep)",
			ABIVersion, want)
	}
}

// TestAvailableBackends_HasCPU: under cgo, the loaded library must always
// expose CPUSequential.
func TestAvailableBackends_HasCPU(t *testing.T) {
	bs := AvailableBackends()
	if !contains(bs, CPUSequential) {
		t.Errorf("AvailableBackends() missing CPUSequential: %v", bs)
	}
}

// A block of funded plain transfers runs on a GPU lane to TxOK at 21000 gas
// each; a CPU lane declines it. No lane answers anything else.
func TestAFundedTransferBlockRunsOnADeviceAndNowhereElse(t *testing.T) {
	const n = 4
	txs, ctx, state := transfers(n)
	for _, b := range AvailableBackends() {
		t.Run(BackendName(b), func(t *testing.T) {
			if isGPU(b) && !hasDevice(b) {
				t.Skipf("this host has no %s device", BackendName(b))
			}
			r, err := ExecuteBlock(b, 0, txs, &ctx, state)
			if !isGPU(b) {
				declined(t, r, err)
				return
			}
			ranTransfers(t, r, err, n)
		})
	}
}

// A batch that carries code is declined on every backend: gpu_execute_block
// passes no host, so it runs no code (go_bridge.h). The block is otherwise
// one a device runs, so the code is what declines it.
func TestABatchWithCodeIsDeclined(t *testing.T) {
	txs, ctx, state := transfers(1)
	code := computeBytecode(1)
	txs[0].Code = code
	for i := range state {
		if state[i].Address == txs[0].To {
			state[i].Code = code
			state[i].CodeHash = crypto.Keccak256Hash(code)
		}
	}
	for _, b := range AvailableBackends() {
		t.Run(BackendName(b), func(t *testing.T) {
			r, err := ExecuteBlock(b, 0, txs, &ctx, state)
			declined(t, r, err)
		})
	}
}

// TestHealth runs the Health() battery: a funded plain transfer. A GPU
// lane whose device this host has runs it to TxOK at 21000 gas; a CPU lane
// declines it, because the Go entry runs nothing on the CPU without a host
// (go_bridge.h).
func TestHealth(t *testing.T) {
	reports := Health()
	if len(reports) == 0 {
		t.Fatal("Health() returned no reports — runtime cannot enumerate backends")
	}
	for _, r := range reports {
		switch {
		case isGPU(r.Backend) && !hasDevice(r.Backend):
			t.Logf("Health: GPU lane %q: this host has no device for it (ok=%v err=%v)", r.Name, r.OK, r.Err)
		case isGPU(r.Backend):
			if !r.OK || r.GasUsed != 21000 {
				t.Errorf("Health: GPU lane %q: ok=%v gas=%d err=%v, want ok at 21000", r.Name, r.OK, r.GasUsed, r.Err)
			}
		case r.OK || !errors.Is(r.Err, ErrDeclined):
			t.Errorf("Health: CPU lane %q: ok=%v err=%v, want declined", r.Name, r.OK, r.Err)
		}
	}
}

// Goroutines running blocks on one device at once each get their own block's
// answer.
func TestConcurrentExecuteBlock(t *testing.T) {
	for _, b := range deviceLanes(t) {
		t.Run(BackendName(b), func(t *testing.T) {
			const goroutines, iterations, n = 8, 16, 8
			txs, ctx, state := transfers(n)
			var wg sync.WaitGroup
			for g := 0; g < goroutines; g++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for i := 0; i < iterations; i++ {
						r, err := ExecuteBlock(b, 0, txs, &ctx, state)
						if err != nil || !allTransfers(r, n) {
							t.Errorf("concurrent run on %s: err=%v result=%+v", BackendName(b), err, r)
							return
						}
					}
				}()
			}
			wg.Wait()
		})
	}
}

// TestConcurrent_Stress: 100 goroutines × 100 txs, each tx with its own code
// and calldata allocation. The library copies both before it declines the
// batch, so this is the regression test for runtime.Pinner: an unpinned Go
// pointer read from C panics or corrupts here. Every call must decline, and
// none may panic. Run with -race for full effect.
func TestConcurrent_Stress(t *testing.T) {
	if testing.Short() {
		t.Skip("stress test skipped in -short mode")
	}
	backends := AvailableBackends()
	const goroutines, txsPerGoroutine = 100, 100
	makeBlock := func(seed uint64) []Transaction {
		txs := make([]Transaction, txsPerGoroutine)
		for i := range txs {
			data := make([]byte, 32)
			for j := range data {
				data[j] = byte(seed + uint64(i) + uint64(j))
			}
			tx := bytecodeTx(seed*txsPerGoroutine+uint64(i), computeBytecode(30))
			tx.Data = data
			txs[i] = tx
		}
		return txs
	}

	var wg sync.WaitGroup
	wg.Add(goroutines)
	for g := 0; g < goroutines; g++ {
		go func(seed uint64) {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("goroutine %d panicked: %v", seed, r)
				}
			}()
			b := backends[int(seed)%len(backends)]
			r, err := ExecuteBlock(b, 0, makeBlock(seed), nil, nil)
			if !errors.Is(err, ErrDeclined) || r != nil {
				t.Errorf("goroutine %d on %s: (%+v, %v), want declined", seed, BackendName(b), r, err)
			}
		}(uint64(g))
	}
	wg.Wait()
}

// TestExecuteBlock_LargeCode: 48 KB of code crosses the boundary (the
// library copies it) and the batch is declined cleanly, never a segfault from
// an unchecked uint32 or an unpinned slice.
func TestExecuteBlock_LargeCode(t *testing.T) {
	code := computeBytecode(8000)
	if len(code) < 32_000 {
		t.Fatalf("expected >= 32K bytecode, got %d", len(code))
	}
	tx := bytecodeTx(0, code)
	tx.GasLimit = 50_000_000
	r, err := ExecuteBlock(CPUSequential, 0, []Transaction{tx}, nil, nil)
	declined(t, r, err)
}

// TestExecuteBlock_LargeData: 64 KiB of calldata on an otherwise funded
// transfer crosses the boundary through the data pin, and every lane
// declines it: the value-transfer device paths do not price calldata.
func TestExecuteBlock_LargeData(t *testing.T) {
	txs, ctx, state := transfers(1)
	txs[0].Data = make([]byte, 1<<16)
	for i := range txs[0].Data {
		txs[0].Data[i] = byte(i)
	}
	txs[0].GasLimit = 2_000_000
	state[0].Balance[0] = 10_000_000 // covers the limit: calldata is the only reason left
	for _, b := range AvailableBackends() {
		t.Run(BackendName(b), func(t *testing.T) {
			r, err := ExecuteBlock(b, 0, txs, &ctx, state)
			declined(t, r, err)
		})
	}
}

// TestBackendUnavailable: a backend the library does not offer declines the
// block, and never panics.
func TestBackendUnavailable(t *testing.T) {
	available := AvailableBackends()
	missing := Backend(-1)
	for _, b := range []Backend{CPUSequential, CPUParallel, GPUMetal, GPUCUDA} {
		if !contains(available, b) {
			missing = b
			break
		}
	}
	if missing < 0 {
		t.Skip("all backends available — cannot test unavailable path")
	}
	txs, ctx, state := transfers(1)
	r, err := ExecuteBlock(missing, 0, txs, &ctx, state)
	declined(t, r, err)
}

// A library that reports another ABI is sent nothing: every block is
// declined, a block a device would have run included, and the error says why.
func TestALibraryOfAnotherABIIsDeclined(t *testing.T) {
	loaded := libraryABI
	t.Cleanup(func() { libraryABI = loaded })
	libraryABI = ABIVersion - 1

	if got := LibraryABIVersion(); got != ABIVersion-1 {
		t.Fatalf("LibraryABIVersion() = %d, want the library's %d", got, ABIVersion-1)
	}
	txs, ctx, state := transfers(2)
	for _, b := range AvailableBackends() {
		t.Run(BackendName(b), func(t *testing.T) {
			r, err := ExecuteBlock(b, 0, txs, &ctx, state)
			declined(t, r, err)
			if !strings.Contains(err.Error(), "ABI") {
				t.Errorf("the decline does not say the ABI is why: %v", err)
			}
		})
	}
}

// -----------------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------------

func isGPU(b Backend) bool { return b == GPUMetal || b == GPUCUDA }

// transfers is a block of n plain transfers, each from its own funded sender
// to its own fresh recipient, with the block context and the state before the
// block that go_bridge.h asks for. Each limit is above the 21000 a transfer
// costs, so a lane that answers the limit as an estimate is not taken for one
// that ran it.
func transfers(n int) ([]Transaction, BlockContext, []StateAccount) {
	ctx := BlockContext{GasLimit: 30_000_000, ChainID: 1, BaseFee: 1, Coinbase: [20]byte{0xC0}}
	txs := make([]Transaction, n)
	state := make([]StateAccount, 0, 2*n+1)
	for i := range txs {
		from := [20]byte{0xA0, byte(i >> 8), byte(i)}
		to := [20]byte{0xB0, byte(i >> 8), byte(i)}
		txs[i] = Transaction{From: from, To: to, HasTo: true, GasLimit: 30_000, Value: 1, GasFeeCap: 1, GasTipCap: 1}
		state = append(state, account(from, 1_000_000), account(to, 0))
	}
	state = append(state, account(ctx.Coinbase, 0))
	return txs, ctx, state
}

// account is a snapshot row for an account without code or storage.
func account(addr [20]byte, balance uint64) StateAccount {
	return StateAccount{
		Address:     addr,
		Balance:     [4]uint64{balance},
		CodeHash:    types.EmptyCodeHash,
		StorageRoot: types.EmptyRootHash,
	}
}

// allTransfers reports whether r is n plain transfers run: every one TxOK at
// 21000 gas, at ABI 7.
func allTransfers(r *BlockResult, n int) bool {
	if r == nil || len(r.GasUsed) != n || len(r.Status) != n || r.ABIVersion != ABIVersion {
		return false
	}
	for i := 0; i < n; i++ {
		if r.Status[i] != TxOK || r.GasUsed[i] != 21000 {
			return false
		}
	}
	return r.TotalGas == uint64(n)*21000
}

func ranTransfers(t *testing.T, r *BlockResult, err error, n int) {
	t.Helper()
	if err != nil {
		// The ABI carries no reason: on a host with the device, a decline is
		// its shader not found, a driver or architecture mismatch, or a
		// regression in its path.
		t.Fatalf("ExecuteBlock: %v", err)
	}
	if !allTransfers(r, n) {
		t.Fatalf("result is not %d transfers run at 21000 gas: %+v", n, r)
	}
}

// declined holds an answer to the one other thing ExecuteBlock may say:
// ErrDeclined, and no result.
func declined(t *testing.T, r *BlockResult, err error) {
	t.Helper()
	if !errors.Is(err, ErrDeclined) {
		t.Fatalf("ExecuteBlock = %v, want ErrDeclined", err)
	}
	if r != nil {
		t.Fatalf("a declined block came back with a result: %+v", r)
	}
}

// deviceLanes is the GPU lanes whose device this host has. It skips the test
// when there is none.
func deviceLanes(t *testing.T) []Backend {
	t.Helper()
	var out []Backend
	for _, b := range AvailableBackends() {
		if isGPU(b) && hasDevice(b) {
			out = append(out, b)
		}
	}
	if len(out) == 0 {
		t.Skip("this host has no device for any GPU lane the library offers")
	}
	return out
}

// hasDevice reports whether this host has the device GPU lane b runs on: the
// GPU every Apple silicon Mac has for Metal, and for CUDA an NVIDIA driver's
// control device with at least one GPU node this process can see (a container
// can be given the first without the second). The library lists a lane it
// was built with either way.
func hasDevice(b Backend) bool {
	switch b {
	case GPUMetal:
		return runtime.GOOS == "darwin" && runtime.GOARCH == "arm64"
	case GPUCUDA:
		if _, err := os.Stat("/dev/nvidiactl"); err != nil {
			return false
		}
		gpus, _ := filepath.Glob("/dev/nvidia[0-9]*")
		return len(gpus) > 0
	}
	return false
}

// computeBytecode returns deterministic EVM bytecode that does iters
// additions then returns.
func computeBytecode(iters int) []byte {
	out := make([]byte, 0, iters*6+5)
	for i := 0; i < iters; i++ {
		out = append(out,
			0x60, 0x01, // PUSH1 1
			0x60, 0x01, // PUSH1 1
			0x01, // ADD
			0x50, // POP
		)
	}
	return append(out,
		0x60, 0x00, // PUSH1 0
		0x60, 0x00, // PUSH1 0
		0xf3, // RETURN
	)
}

func bytecodeTx(i uint64, code []byte) Transaction {
	var from [20]byte
	from[19] = byte(i)
	from[18] = byte(i >> 8)
	return Transaction{
		From:      from,
		HasTo:     true,
		Code:      code,
		GasLimit:  1_000_000,
		Nonce:     i,
		GasFeeCap: 1,
		GasTipCap: 1,
	}
}

// contains reports whether b appears in s.
func contains(s []Backend, b Backend) bool {
	for _, x := range s {
		if x == b {
			return true
		}
	}
	return false
}
