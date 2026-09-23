//go:build cgo && lux_cevm_native

package cevm

// OPT-IN via `-tags=lux_cevm_native`. cgo says a C compiler is available;
// it does not say the luxcpp bundle below is installed. Those are two
// facts, so they get two predicates: without the tag the package builds
// against cevm_nocgo.go and reports CPUSequential, which is what every
// host that has not run `cmake --install` on luxcpp/cevm should get.
//
// Linkage goes through the lux-cevm pkg-config bundle (libevm + libevm-gpu).
// The C header "go_bridge.h" ships under
// $LUXCPP_PREFIX/include/cevm/lib/evm/gpu/, which is in the .pc Cflags.
//
// Build + install the .pc bundle with:
//
//   cmake -S ~/work/luxcpp/cevm -B ~/work/luxcpp/cevm/build \
//         -DCMAKE_INSTALL_PREFIX=$HOME/work/luxcpp/install
//   cmake --build ~/work/luxcpp/cevm/build
//   cmake --install ~/work/luxcpp/cevm/build
//
// Then `export PKG_CONFIG_PATH=$HOME/work/luxcpp/install/lib/pkgconfig`.
//
// luxcpp-gpu / cevm_precompiles / metal-hosts / kernel-metal are folded into
// libevm-gpu's static archive in the v0.19 build, so the .pc only needs
// -levm -levm-gpu plus the Metal/Foundation frameworks on darwin and a
// stdc++ on linux.
//
// External Go consumers building from $GOMODCACHE need the .pc + libs
// installed locally; this build no longer falls back to ${SRCDIR}-relative
// luxcpp paths. fetch-luxcpp.sh is kept for the headers-only bootstrap path
// but the install step is the canonical one.
//
//go:generate ./fetch-luxcpp.sh

/*
#cgo pkg-config: lux-cevm
#cgo darwin LDFLAGS: -framework Metal -framework Foundation -lstdc++
#cgo linux  LDFLAGS: -lstdc++

#include <stdlib.h>
#include "go_bridge.h"
*/
import "C"

import (
	"fmt"
	"runtime"
	"unsafe"

	"github.com/luxfi/geth/core/types"
)

// AutoDetect returns the best available backend for this machine.
func AutoDetect() Backend {
	return Backend(C.gpu_auto_detect_backend())
}

// ABIVersion is the go_bridge.h ABI this file is written to: 7, in which ok
// says whether the result is the block's. A version 6 library answers ok=1 for
// results that are not, so this file is not correct against it even where the
// structs line up.
const ABIVersion uint32 = 7

// The header this builds against names the same ABI, or this file does not
// compile: each line fails when EVM_GPU_ABI_VERSION is smaller (the first) or
// larger (the second) than ABIVersion.
var (
	_ [ABIVersion - C.EVM_GPU_ABI_VERSION]struct{}
	_ [C.EVM_GPU_ABI_VERSION - ABIVersion]struct{}
)

// The C structs this file fills and reads, at the sizes go_bridge.h (ABI 7)
// gives them on LP64. A header that adds, drops or widens a field changes a
// size, and then this file does not compile until it has been read against
// the new header: a field it never sets would otherwise cross as zero, which
// is how storage_root went unset. Each pair fails when the size is larger
// (the first) or smaller (the second).
var (
	_ [unsafe.Sizeof(C.CGpuTx{}) - 120]struct{}
	_ [120 - unsafe.Sizeof(C.CGpuTx{})]struct{}
	_ [unsafe.Sizeof(C.CGpuStateAccount{}) - 136]struct{}
	_ [136 - unsafe.Sizeof(C.CGpuStateAccount{})]struct{}
	_ [unsafe.Sizeof(C.CGpuBlockResult{}) - 88]struct{}
	_ [88 - unsafe.Sizeof(C.CGpuBlockResult{})]struct{}
	_ [unsafe.Sizeof(C.CBlockContext{}) - unsafe.Sizeof(BlockContext{})]struct{}
	_ [unsafe.Sizeof(BlockContext{}) - unsafe.Sizeof(C.CBlockContext{})]struct{}
)

// libraryABI is the ABI the loaded library reports (gpu_abi_version), read
// once in init. The library a binary loads at run time need not be the one
// whose header it was built against.
var libraryABI uint32

// init reads the loaded library's ABI. A library of another ABI lays the
// structs out and means ok differently, so ExecuteBlock sends it nothing:
// every block is declined, and the caller runs it on its own EVM.
func init() {
	libraryABI = uint32(C.gpu_abi_version())
}

// errOtherABI is ExecuteBlock's decline when the loaded library, or a result
// it returned, is of an ABI this file is not written to.
func errOtherABI(got uint32) error {
	return fmt.Errorf("cevm: the library speaks ABI %d, this build reads %d: %w", got, ABIVersion, ErrDeclined)
}

// buildTxs converts Go transactions into C-layout transactions, pinning any
// Go-owned byte slices for the duration of the C call. The caller is
// responsible for invoking pinner.Unpin() once C has returned.
//
// Pinning rule: ctxs[i].data and ctxs[i].code are Go pointers inside Go
// memory that C will dereference. Per Go cgo rules these inner pointers
// MUST be pinned. ctxs[i].from / ctxs[i].to are stored by-value (array
// copy) so they don't need pinning.
func buildTxs(txs []Transaction, pinner *runtime.Pinner) []C.CGpuTx {
	ctxs := make([]C.CGpuTx, len(txs))
	for i := range txs {
		t := &txs[i]
		ctxs[i].from = *(*[20]C.uint8_t)(unsafe.Pointer(&t.From[0]))
		ctxs[i].to = *(*[20]C.uint8_t)(unsafe.Pointer(&t.To[0]))
		ctxs[i].gas_limit = C.uint64_t(t.GasLimit)
		ctxs[i].value = C.uint64_t(t.Value)
		ctxs[i].nonce = C.uint64_t(t.Nonce)
		ctxs[i].max_fee_per_gas = C.uint64_t(t.GasFeeCap)
		ctxs[i].max_priority_fee_per_gas = C.uint64_t(t.GasTipCap)
		if t.HasTo {
			ctxs[i].has_to = 1
		}
		if len(t.Data) > 0 {
			pinner.Pin(&t.Data[0])
			ctxs[i].data = (*C.uint8_t)(unsafe.Pointer(&t.Data[0]))
			ctxs[i].data_len = C.uint32_t(len(t.Data))
		}
		if len(t.Code) > 0 {
			pinner.Pin(&t.Code[0])
			ctxs[i].code = (*C.uint8_t)(unsafe.Pointer(&t.Code[0]))
			ctxs[i].code_len = C.uint32_t(len(t.Code))
		}
	}
	return ctxs
}

// copyU64 safely copies up to want elements from a C uint64 array into a Go
// slice. Bounds-checks `want` against a sane maximum to defend against a
// corrupted result struct returning an absurd count.
func copyU64(ptr *C.uint64_t, want uint32) []uint64 {
	if ptr == nil || want == 0 {
		return nil
	}
	const maxTxsPerBlock = 1 << 24 // 16M txs/block — far above any realistic block
	if want > maxTxsPerBlock {
		return nil
	}
	src := unsafe.Slice((*uint64)(unsafe.Pointer(ptr)), int(want))
	dst := make([]uint64, want)
	copy(dst, src)
	return dst
}

// ExecuteBlock runs txs against backend through gpu_execute_block and returns
// per-tx gas and status. A nil ctx leaves the C side on a zero block context;
// state is the state before the block and must hold every account a tx
// touches (see StateAccount). numThreads is passed through to the C executor.
//
// When the library declines the block (ok=0) ExecuteBlock returns ErrDeclined
// and no result: the caller runs the block on its own EVM. A loaded library
// of another ABI is never sent a block: ExecuteBlock declines every block it
// is given, with an error that wraps ErrDeclined.
func ExecuteBlock(backend Backend, numThreads uint32, txs []Transaction, ctx *BlockContext, state []StateAccount) (*BlockResult, error) {
	if len(txs) == 0 {
		return &BlockResult{ABIVersion: ABIVersion}, nil
	}
	if libraryABI != ABIVersion {
		return nil, errOtherABI(libraryABI)
	}

	var pinner runtime.Pinner
	defer pinner.Unpin()
	ctxs := buildTxs(txs, &pinner)

	// Build the CBlockContext.
	var cctxStorage C.CBlockContext
	var cctxPtr *C.CBlockContext
	if ctx != nil {
		cctxStorage.origin = *(*[20]C.uint8_t)(unsafe.Pointer(&ctx.Origin[0]))
		cctxStorage.gas_price = C.uint64_t(ctx.GasPrice)
		cctxStorage.timestamp = C.uint64_t(ctx.Timestamp)
		cctxStorage.number = C.uint64_t(ctx.Number)
		cctxStorage.prevrandao = *(*[32]C.uint8_t)(unsafe.Pointer(&ctx.Prevrandao[0]))
		cctxStorage.gas_limit = C.uint64_t(ctx.GasLimit)
		cctxStorage.chain_id = C.uint64_t(ctx.ChainID)
		cctxStorage.base_fee = C.uint64_t(ctx.BaseFee)
		cctxStorage.blob_base_fee = C.uint64_t(ctx.BlobBaseFee)
		cctxStorage.coinbase = *(*[20]C.uint8_t)(unsafe.Pointer(&ctx.Coinbase[0]))
		cctxStorage.blob_hashes = *(*[8][32]C.uint8_t)(unsafe.Pointer(&ctx.BlobHashes[0][0]))
		nbh := ctx.NumBlobHashes
		if nbh > 8 {
			nbh = 8
		}
		cctxStorage.num_blob_hashes = C.uint32_t(nbh)
		cctxPtr = &cctxStorage
	}

	// Pack the state snapshot. Concatenate every account's Code into a
	// flat blob and emit (offset, size) per account. EOA accounts have
	// size==0 and offset==0 (offset is unused when size==0).
	var (
		cAccts    []C.CGpuStateAccount
		cAcctsPtr *C.CGpuStateAccount
		codeBlob  []byte
		codePtr   *C.uint8_t
		codeSize  uint32
	)
	if len(state) > 0 {
		// Estimate blob size to avoid repeated grows.
		var totalCode int
		for i := range state {
			totalCode += len(state[i].Code)
		}
		codeBlob = make([]byte, 0, totalCode)
		cAccts = make([]C.CGpuStateAccount, len(state))
		for i := range state {
			a := &state[i]
			cAccts[i].address = *(*[20]C.uint8_t)(unsafe.Pointer(&a.Address[0]))
			cAccts[i].nonce = C.uint64_t(a.Nonce)
			for j := 0; j < 4; j++ {
				cAccts[i].balance[j] = C.uint64_t(a.Balance[j])
			}
			cAccts[i].code_hash = *(*[32]C.uint8_t)(unsafe.Pointer(&a.CodeHash[0]))
			cAccts[i].storage_root = *(*[32]C.uint8_t)(unsafe.Pointer(&a.StorageRoot[0]))
			if n := len(a.Code); n > 0 {
				cAccts[i].code_off = C.uint32_t(len(codeBlob))
				cAccts[i].code_size = C.uint32_t(n)
				codeBlob = append(codeBlob, a.Code...)
			} else {
				cAccts[i].code_off = 0
				cAccts[i].code_size = 0
			}
		}
		cAcctsPtr = &cAccts[0]
		if len(codeBlob) > 0 {
			pinner.Pin(&codeBlob[0])
			codePtr = (*C.uint8_t)(unsafe.Pointer(&codeBlob[0]))
			codeSize = uint32(len(codeBlob))
		}
	}

	result := C.gpu_execute_block(
		&ctxs[0],
		C.uint32_t(len(ctxs)),
		C.uint8_t(backend),
		C.uint32_t(numThreads),
		C.uint8_t(C.EVM_GPU_REV_CANCUN), // the one revision the kernels implement
		cctxPtr,
		cAcctsPtr,
		C.uint32_t(len(state)),
		codePtr,
		C.uint32_t(codeSize),
	)
	defer C.gpu_free_result(&result)
	runtime.KeepAlive(ctxs)
	runtime.KeepAlive(cctxStorage)
	runtime.KeepAlive(cAccts)
	runtime.KeepAlive(codeBlob)

	// What ok means is the ABI's, so a result of another ABI is not read at
	// all. ok=0 names no gas or status the caller may use (every status reads
	// EVM_GPU_TX_ERROR, and the arrays may be NULL). Either way nothing below
	// is read: the block goes back to the caller whole.
	if got := uint32(result.abi_version); got != ABIVersion {
		return nil, errOtherABI(got)
	}
	if result.ok == 0 {
		return nil, ErrDeclined
	}

	br := &BlockResult{
		GasUsed:      copyU64(result.gas_used, uint32(result.num_txs)),
		TotalGas:     uint64(result.total_gas),
		ExecTimeMs:   float64(result.exec_time_ms),
		Conflicts:    uint32(result.conflicts),
		ReExecutions: uint32(result.re_executions),
		ABIVersion:   uint32(result.abi_version),
	}
	for i := 0; i < 32; i++ {
		br.StateRoot[i] = byte(result.state_root[i])
	}
	if result.status != nil && result.num_txs > 0 {
		const maxTxsPerBlock = 1 << 24
		want := uint32(result.num_txs)
		if want > maxTxsPerBlock {
			return nil, fmt.Errorf("cevm: result.num_txs=%d exceeds sanity bound", want)
		}
		statSlice := unsafe.Slice((*uint8)(unsafe.Pointer(result.status)), int(want))
		br.Status = make([]TxStatus, want)
		for i, s := range statSlice {
			br.Status[i] = TxStatus(s)
		}
	}
	return br, nil
}

// BackendName returns the human-readable name of a backend as reported by the
// C++ library (which is authoritative).
func BackendName(b Backend) string {
	cstr := C.gpu_backend_name(C.uint8_t(b))
	if cstr == nil {
		return "unknown"
	}
	return C.GoString(cstr)
}

// AvailableBackends returns the list of backends compiled and detected
// at runtime by the loaded library.
func AvailableBackends() []Backend {
	n := uint32(C.gpu_available_backends(nil, 0))
	if n == 0 {
		return nil
	}
	buf := make([]C.uint8_t, n)
	got := uint32(C.gpu_available_backends(&buf[0], C.uint32_t(n)))
	out := make([]Backend, got)
	for i := uint32(0); i < got; i++ {
		out[i] = Backend(buf[i])
	}
	return out
}

// LibraryABIVersion returns the ABI the loaded library reports. When it is
// not ABIVersion, ExecuteBlock declines every block.
func LibraryABIVersion() uint32 {
	return libraryABI
}

// healthProbe is one entry in the Health() battery: a block, the state before
// it, and the gas each of its transactions must come back with at TxOK.
type healthProbe struct {
	name    string
	txs     []Transaction
	ctx     BlockContext
	state   []StateAccount
	wantGas uint64
}

// healthBattery is what Health runs on every backend.
//
// gpu_execute_block runs one kind of block (go_bridge.h, ABI 7): plain value
// transfers, on a GPU lane's value-transfer path. It declines a batch with
// code, and the CPU lanes run nothing without a host. So the battery is one
// such block — a funded sender's transfer to a fresh address — which a lane
// that can run anything runs to TxOK at its 21000 intrinsic gas, and which
// every other lane declines. Its limit is above that, so a lane that answers
// a gas estimate (the limit) instead of running it is not taken for healthy.
func healthBattery() []healthProbe {
	from, to, coinbase := [20]byte{0x01}, [20]byte{0x02}, [20]byte{0xC0}
	row := func(addr [20]byte, balance uint64) StateAccount {
		return StateAccount{
			Address:     addr,
			Balance:     [4]uint64{balance},
			CodeHash:    types.EmptyCodeHash,
			StorageRoot: types.EmptyRootHash,
		}
	}
	return []healthProbe{{
		name:    "transfer",
		txs:     []Transaction{{From: from, To: to, HasTo: true, GasLimit: 30000, Value: 1, GasFeeCap: 1, GasTipCap: 1}},
		ctx:     BlockContext{GasLimit: 30_000_000, ChainID: 1, BaseFee: 1, Coinbase: coinbase},
		state:   []StateAccount{row(from, 1_000_000), row(to, 0), row(coinbase, 0)},
		wantGas: 21000,
	}}
}

// HealthProbeResult is the outcome of a single probe on a single backend.
type HealthProbeResult struct {
	Name    string
	OK      bool
	GasUsed uint64
	Status  TxStatus
	Err     error
}

// HealthReport is the per-backend result of Health(). It aggregates the
// per-probe results into a single OK / not-OK signal: a backend is healthy
// iff every probe ran every transaction to TxOK at the gas it must cost.
type HealthReport struct {
	Backend      Backend
	Name         string
	OK           bool
	Err          error
	Probe        string // first failing probe name, empty when OK
	ProbesRun    int
	ProbeResults []HealthProbeResult
	// Aggregate stats — sum of gas across probes, status of the last probe.
	GasUsed  uint64
	Status   TxStatus
	ExecTime float64
}

// Health runs the battery through every backend the loaded library exposes
// and returns a per-backend report. Use at process start to see which lanes
// can run a block at all: a GPU lane whose device, driver or library is
// wrong fails here. Returns nil only if the runtime cannot enumerate
// backends.
//
// A backend is OK iff it ran every probe's transactions to TxOK at the gas
// they cost. A lane that declines is not OK and says so: its Err wraps
// ErrDeclined, which is the answer every CPU lane gives this entry.
func Health() []HealthReport {
	backends := AvailableBackends()
	if len(backends) == 0 {
		return nil
	}
	probes := healthBattery()
	out := make([]HealthReport, 0, len(backends))
	for _, b := range backends {
		rep := HealthReport{
			Backend:      b,
			Name:         BackendName(b),
			ProbeResults: make([]HealthProbeResult, 0, len(probes)),
		}
		allOK := true
		for _, p := range probes {
			pr := runHealthProbe(b, p)
			rep.ProbeResults = append(rep.ProbeResults, pr)
			rep.ProbesRun++
			rep.GasUsed += pr.GasUsed
			rep.Status = pr.Status
			if !pr.OK && allOK {
				allOK = false
				rep.Probe = pr.Name
				rep.Err = pr.Err
			}
		}
		rep.OK = allOK
		out = append(out, rep)
	}
	return out
}

// runHealthProbe executes one probe on one backend and returns its result.
func runHealthProbe(b Backend, p healthProbe) HealthProbeResult {
	pr := HealthProbeResult{Name: p.name}
	r, err := ExecuteBlock(b, 0, p.txs, &p.ctx, p.state)
	if err != nil {
		pr.Err = fmt.Errorf("probe %q: %w", p.name, err)
		return pr
	}
	if len(r.GasUsed) != len(p.txs) || len(r.Status) != len(p.txs) {
		pr.Err = fmt.Errorf("probe %q: malformed result (gas=%d status=%d, want %d)",
			p.name, len(r.GasUsed), len(r.Status), len(p.txs))
		return pr
	}
	for i := range p.txs {
		pr.GasUsed += r.GasUsed[i]
		pr.Status = r.Status[i]
		if r.Status[i] != TxOK || r.GasUsed[i] != p.wantGas {
			pr.Err = fmt.Errorf("probe %q: tx %d came back %s at %d gas, want ok at %d",
				p.name, i, r.Status[i], r.GasUsed[i], p.wantGas)
			return pr
		}
	}
	pr.OK = true
	return pr
}
