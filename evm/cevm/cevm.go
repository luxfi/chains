// Package cevm provides Go bindings to the C++ EVM (cevm) with GPU acceleration.
//
// Its block entry, gpu_execute_block (go_bridge.h, ABI 7), runs one kind of
// block: plain value transfers, on a GPU lane's value-transfer path, answering
// per-tx gas and status. Anything else it declines (ErrDeclined) and the
// caller runs on its own EVM. BatchRecoverSenders batches ecrecover.
//
// Build against the native library: CGO_ENABLED=1 go build -tags lux_cevm_native
// Build without it: go build (types only, no execution) — the default,
// and the only thing that works on a host lacking the lux-cevm bundle.
// Binary: the `cevm` binary in luxcpp/evm/build/bin/ is the Lux VM plugin.
//
// # Concurrency model
//
// ExecuteBlock and ExecuteBlock are safe to call concurrently from
// multiple goroutines. The implementation guarantees:
//
//  1. No shared mutable state on the Go side. Every call allocates a fresh
//     []C.CGpuTx for its inputs and a fresh runtime.Pinner for its lifetime.
//     The pinner pins the base address of every Go-owned []byte (tx.Data,
//     tx.Code) that the C side dereferences, and is unpinned via defer
//     after the C call returns — including on the error path.
//
//  2. The C result is freed via defer (gpu_free_result) on every code path
//     including failure. Gas/status arrays are copied into Go-owned slices
//     before the result is freed.
//
//  3. The C++ engine uses a thread_local engine cache (one per OS thread
//     reached by goroutines via cgo) for the Keccak hasher; per-instance
//     MTLBuffer / CUDA context caches are mutex-protected on the C++ side.
//     Two goroutines on different OS threads use independent kernel state.
//
//  4. The CPU path is fully reentrant: each call constructs a fresh
//     cevm state and tears it down before returning.
//
// What is NOT safe:
//   - Mutating the Transaction.Data or Transaction.Code slices while a
//     concurrent ExecuteBlock call is reading them. The pinner only
//     prevents GC moves; it does not provide read/write synchronization.
//   - Sharing a *BlockResult between goroutines without external sync.
//
// # ABI version
//
// ABIVersion is the go_bridge.h ABI the native build is written to, 7. The
// build does not compile against a header that names another, and init reads
// the loaded library's gpu_abi_version(): against a library of another ABI,
// ExecuteBlock calls nothing and declines every block, so the caller runs them
// all on its own EVM. It catches a library built against another ABI number;
// two libraries that report the same number are not told apart.
//
// Use Health() at startup to see which lanes can run a block: it runs a
// funded plain transfer on each.
package cevm

import (
	"errors"
	"fmt"
)

// ErrNotLinked is what every entry point that needs the native luxcpp library
// returns when this binary was built without it — the default build, and any
// build on a host lacking the lux-cevm bundle.
//
// It is a value rather than a message because a caller has to tell it apart
// from a bad input, and the two lead to opposite decisions: a build that
// cannot execute declines the block to whatever else can, while a block that
// cannot be executed is a hard failure. A caller that could only read the
// message either treated a missing library as a corrupt block, or — worse —
// fell back on a signature the library had rejected.
var ErrNotLinked = errors.New("cevm: native EVM not linked (rebuild with CGO_ENABLED=1 -tags=lux_cevm_native)")

// ErrDeclined is what ExecuteBlock returns when the library answers ok=0
// (go_bridge.h): the result is not the block's, and the caller runs the block
// on its own EVM. cevm declines any batch in which a transaction carries code,
// and any batch its value-transfer paths cannot run as the EVM does — a
// refusal on balance, nonce, price, block gas limit or revision, a snapshot
// row without its hashes, or a device that failed. Against a loaded library
// of another ABI, every batch is declined without a call.
//
// A declined result carries no gas or status a caller may use, so ExecuteBlock
// returns none with it.
var ErrDeclined = errors.New("cevm: declined the block (ok=0); the caller runs it")

// BlockResult is what ExecuteBlock returns for a block cevm ran: per-tx gas
// and status. StateRoot is zero: gpu_execute_block roots no state.
type BlockResult struct {
	StateRoot    [32]byte
	GasUsed      []uint64
	Status       []TxStatus
	TotalGas     uint64
	ExecTimeMs   float64
	Conflicts    uint32
	ReExecutions uint32
	ABIVersion   uint32
}

// Backend selects the C++ EVM execution mode.
type Backend int

const (
	// CPUSequential runs transactions one at a time on a single core.
	CPUSequential Backend = 0
	// CPUParallel uses Block-STM to run transactions across all cores.
	CPUParallel Backend = 1
	// GPUMetal offloads Keccak, ecrecover, and the EVM interpreter to Metal.
	GPUMetal Backend = 2
	// GPUCUDA offloads Keccak, ecrecover, and the EVM interpreter to CUDA.
	GPUCUDA Backend = 3
)

// String returns the human-readable name of the backend.
func (b Backend) String() string {
	switch b {
	case CPUSequential:
		return "cpu-sequential"
	case CPUParallel:
		return "cpu-parallel"
	case GPUMetal:
		return "gpu-metal"
	case GPUCUDA:
		return "gpu-cuda"
	default:
		return fmt.Sprintf("unknown(%d)", int(b))
	}
}

// Transaction is a single EVM transaction to execute.
//
// cevm runs a batch only when it is plain value transfers on a GPU backend's
// value-transfer path: a batch in which any transaction carries Code is
// declined (ErrDeclined), because gpu_execute_block passes no host and would
// run that code as a message, on its whole limit, which is not the tx's gas.
//
// Value and GasPrice are 64-bit on the wire. A transaction whose value or
// price does not fit is the caller's to run; it never belongs in a batch.
type Transaction struct {
	From     [20]byte
	To       [20]byte
	HasTo    bool
	Data     []byte // Calldata
	Code     []byte // The recipient's code; any makes cevm decline the batch
	GasLimit uint64
	Value    uint64
	Nonce    uint64
	GasPrice uint64
}

// TxStatus is a per-transaction execution outcome from the V2 ABI.
type TxStatus uint8

const (
	TxOK               TxStatus = 0 // STOP / clean exit
	TxReturn           TxStatus = 1
	TxRevert           TxStatus = 2
	TxOOG              TxStatus = 3
	TxError            TxStatus = 4
	TxCallNotSupported TxStatus = 5
)

// String returns a short label for the tx status.
func (s TxStatus) String() string {
	switch s {
	case TxOK:
		return "ok"
	case TxReturn:
		return "return"
	case TxRevert:
		return "revert"
	case TxOOG:
		return "oog"
	case TxError:
		return "error"
	case TxCallNotSupported:
		return "call-not-supported"
	default:
		return fmt.Sprintf("status(%d)", int(s))
	}
}

// BlockContext is the block-level execution context shared by every
// transaction in a block. It feeds the EVM opcodes that report block-level
// state: TIMESTAMP, NUMBER, CHAINID, BASEFEE, COINBASE, GASLIMIT,
// PREVRANDAO, BLOBHASH, BLOBBASEFEE.
//
// Pass a non-nil *BlockContext to ExecuteBlock when the call must mirror
// real chain semantics (consensus, replay, fork-aware execution). The
// zero-value is the documented "no context" default — chain id resolves
// to 0, timestamp to 0, etc., which matches the dispatcher's pre-v0.26
// behaviour.
//
// Field layout matches the C-side CBlockContext byte-for-byte. The binding
// copies it into a CBlockContext field by field, and the C side memcpy's that
// into evm::gpu::BlockContext; the Go layout is pinned to the C one all the
// same (TestBlockContextIsTheWireLayout, and the size check in cevm_cgo.go).
// Field order MUST match go_bridge.h CBlockContext exactly. Adding new
// fields requires bumping ABIVersion and the C-side EVM_GPU_ABI_VERSION
// in lockstep.
type BlockContext struct {
	Origin        [20]byte
	GasPrice      uint64
	Timestamp     uint64
	Number        uint64
	Prevrandao    [32]byte
	GasLimit      uint64
	ChainID       uint64
	BaseFee       uint64
	BlobBaseFee   uint64
	Coinbase      [20]byte
	BlobHashes    [8][32]byte
	NumBlobHashes uint32
}

// ABIVersion (cevm_cgo.go / cevm_nocgo.go) is the C ABI this build reads:
// go_bridge.h's EVM_GPU_ABI_VERSION, 7. It is one entry, gpu_execute_block,
// taking a block context and a state snapshot (CGpuStateAccount) and
// answering per-tx gas and status with ok, freed by gpu_free_result; ok=1
// only for a result that is the block's. The versioned _v2/_v3/_v4 entries
// are gone.

// StateAccount is one entry in the snapshot of touched accounts handed to
// ExecuteBlock, the state before the block. Fields mirror the C-side
// CGpuStateAccount (modulo the inline `Code` slice which the binding flattens
// into a single blob before crossing the cgo boundary).
//
// The snapshot must hold every account a transaction touches: cevm takes an
// account it lacks not to exist, so a transfer to a contract left out runs as
// a transfer to an empty account.
//
// Address is canonical 20-byte big-endian. Balance is little-endian limbs
// (Balance[0] = low 64 bits). Code may be nil for EOAs — empty code is the
// EOA marker. CodeHash is keccak256(code), keccak256 of nothing
// (types.EmptyCodeHash) for an account with no code, including one that does
// not exist; zero says nothing, and cevm declines a batch whose sender or
// recipient row carries it. StorageRoot is the account's storage trie root,
// types.EmptyRootHash for an account with no storage.
type StateAccount struct {
	Address     [20]byte
	Nonce       uint64
	Balance     [4]uint64
	Code        []byte
	CodeHash    [32]byte
	StorageRoot [32]byte
}
