// Package cevm provides Go bindings to the C++ EVM (cevm) with GPU acceleration.
// Import this package to use the C++ EVM as a drop-in replacement for go-ethereum's EVM.
//
// The C++ EVM supports:
//   - Block-STM parallel execution
//   - GPU Keccak-256 state hashing (Metal/CUDA)
//   - GPU batch ecrecover (Metal/CUDA)
//   - GPU EVM opcode interpreter (Metal/CUDA)
//   - ZAP VM plugin protocol (native)
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
//  2. The C result is freed via defer (gpu_free_result / gpu_free_result_v2)
//     on every code path including failure. Gas/status arrays are copied
//     into Go-owned slices before the result is freed.
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
// The Go module's ABIVersion constant is checked against the loaded
// library's gpu_abi_version() in init(). A mismatch panics at process
// start — that is intentional. A silent ABI mismatch produces wrong
// gas/state results and would corrupt consensus, so fail-fast is the
// only safe behaviour.
//
// Use Health() at startup to additionally verify each backend executes
// the canonical health-check battery (arithmetic, storage, hashing,
// memory, and the call bridge) without error.
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

// Backend selects the C++ EVM execution mode.
// BlockResult extends BlockResult with the V2 ABI fields: per-tx status
// and the post-execution state root.
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
// When Code is non-empty AND a GPU backend is selected, the C++ EVM
// dispatches each tx through the parallel opcode interpreter (Metal:
// kernel::EvmKernelHost, CUDA: cuda::EvmKernel). When Code is empty, GPU
// backends use the scheduler-only Block-STM kernel.
type Transaction struct {
	From     [20]byte
	To       [20]byte
	HasTo    bool
	Data     []byte // Calldata
	Code     []byte // EVM bytecode (optional — required for real GPU execution)
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
// Field layout matches the C-side CBlockContext byte-for-byte: this struct
// is passed to the C ABI via direct memcpy, no field-by-field translation.
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

// ABIVersion is the C ABI version this Go module expects. Compare against
// the loaded library's gpu_abi_version() to detect version skew.
//
// v5 (v0.26.0): added gpu_execute_block_v3 with CBlockContext (TIMESTAMP,
// NUMBER, CHAINID, BASEFEE, etc.) and per-tx status[] in BlockResult. V2
// callers still work; only ExecuteBlock sees the new BlockContext fields.
//
// v6: added gpu_execute_block_v4 + CGpuStateAccount. Callers can now hand
// the GPU a state snapshot (account nonce, balance, code, code_hash) so
// the kernel CALL/CREATE path resolves targets on-device instead of
// returning CallNotSupported. V3 callers still see the same wire shape.
//

// StateAccount is one entry in the snapshot of touched accounts handed to
// ExecuteBlock. Fields mirror the C-side CGpuStateAccount byte-for-byte
// (modulo the inline `Code` slice which the binding flattens into a single
// blob before crossing the cgo boundary).
//
// Address is canonical 20-byte big-endian. Balance is little-endian limbs
// (Balance[0] = low 64 bits). Code may be nil for EOAs — empty code is the
// EOA marker. CodeHash should be keccak256(code); the dispatcher does not
// recompute it because callers usually have it cached on the StateDB side.
type StateAccount struct {
	Address  [20]byte
	Nonce    uint64
	Balance  [4]uint64
	Code     []byte
	CodeHash [32]byte
}
